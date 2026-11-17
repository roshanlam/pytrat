"""Agent delegation: a chain can never become more trusted than its least trusted agent.

    uv run python examples/agent-delegation/agent_delegation.py

Story (draft-araut-oauth-transaction-tokens-for-agents-03):

1. A user asks an *external* research agent (assurance ``low``) to produce a report. The TTS
   issues a Txn-Token whose ``agentic_ctx`` records that agent as originator, hop 1.
2. The external agent delegates to an *internal* report agent (assurance ``high``). The internal
   agent obtains a replacement token from the TTS: hop 2, proximate agent updated, and the chain's
   minimum assurance stays ``low`` (monotonic attenuation, §3.5.1).
3. The reports service requires ``medium`` assurance: the delegated request is denied, so the
   external agent could not launder its low assurance through the trusted internal agent.
4. The same internal agent acting directly for the user (a ``high`` chain) is allowed.
5. A further hop beyond the configured ``max_hops`` is refused by the TTS.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import httpx
import yaml

from pytrat.client import AsyncTransactionTokenClient, ExchangeError, PrivateKeyJwtCredential
from pytrat.core import (
    PyTraTError,
    SecretToken,
    StaticKeySet,
    TokenVerifier,
    VerificationKey,
    VerifiedToken,
    VerifierSettings,
)
from pytrat.core.constants import TOKEN_TYPE_ACCESS_TOKEN
from pytrat.core.crypto import PrivateKey, generate_private_key, private_key_to_pem, sign_compact
from pytrat.policy import AgentRequirements, AuthorizationRequest, CompiledPolicy
from pytrat.server import build_components, create_app, parse_settings

TRUST_DOMAIN = "research.internal"
TOKEN_ENDPOINT = "https://tts.research.internal/token"
IDP = "https://idp.example"
SCOPE = "reports.generate"
ALG = "ES256"

AGENTS = {
    "agents": [
        {
            "id": "external-research-agent",
            "name": "Partner research agent",
            "owner": "partner-co",
            "assurance_level": "low",
            "version": "2.1",
            "provenance": "partner-supplied",
            "client_id": "partner-app",
        },
        {
            "id": "internal-report-agent",
            "name": "Internal report agent",
            "owner": "reports-team",
            "assurance_level": "high",
            "version": "5.0",
            "provenance": "sha256:internal-build",
            "client_id": "report-agent",
        },
    ]
}

# The reports service: at most 3 agent hops, and every agent in the chain at least `medium`.
REPORTS_POLICY = CompiledPolicy.build(
    policy_id="generate-report",
    allowed_scopes=[SCOPE],
    require_workload_identity=False,
    agents=AgentRequirements(enabled=True, maximum_hops=3, minimum_assurance="medium"),
)


@dataclass
class World:
    tts: AsyncTransactionTokenClient  # used by the edge that accepts the user's request
    report_agent: AsyncTransactionTokenClient  # the internal agent's trusted runtime
    idp_key: PrivateKey

    def user_token(self, *, client_id: str, agent: str) -> SecretToken:
        now = int(time.time())
        claims = {
            "iss": IDP,
            "aud": "https://api.research.example",
            "sub": "user:alice",
            "scope": SCOPE,
            "iat": now,
            "exp": now + 300,
            "client_id": client_id,
            "act": {"sub": agent},  # RFC 8693 delegation: the agent acts for alice
            "jti": uuid.uuid4().hex,
        }
        return SecretToken(sign_compact(claims, self.idp_key, alg=ALG, kid="idp", typ="at+jwt"))

    async def start_chain(self, *, client_id: str, agent: str) -> VerifiedToken:
        return await self.tts.issue(
            audience=TRUST_DOMAIN,
            scope=SCOPE,
            subject_token=self.user_token(client_id=client_id, agent=agent),
            subject_token_type=TOKEN_TYPE_ACCESS_TOKEN,
        )


def _secret(path: Path, key: PrivateKey) -> Path:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(private_key_to_pem(key))
    return path


def _jwks(kid: str, key: PrivateKey) -> dict[str, object]:
    return StaticKeySet([VerificationKey.from_public_key(kid, key.public_key(), ALG)]).to_jwks()


def build_world(directory: Path, *, max_hops: int = 2) -> World:
    keys = {name: generate_private_key(ALG) for name in ("tts", "idp", "edge", "report-agent")}
    _secret(directory / "tts.pem", keys["tts"])
    (directory / "idp.json").write_text(json.dumps(_jwks("idp", keys["idp"])))
    (directory / "agents.yaml").write_text(yaml.safe_dump(AGENTS))
    settings = parse_settings(
        {
            "trust_domain": TRUST_DOMAIN,
            "issuer": "https://tts.research.internal",
            "token_endpoint": TOKEN_ENDPOINT,
            "signing_keys": [
                {"kid": "tts", "alg": ALG, "private_key_path": "tts.pem", "state": "active"}
            ],
            "workloads": [
                {"id": "edge", "jwks": _jwks("edge", keys["edge"])},
                {"id": "report-agent", "jwks": _jwks("report-agent", keys["report-agent"])},
            ],
            "subject_tokens": {
                "jwt_access_token": [
                    {
                        "issuer": IDP,
                        "jwks_path": "idp.json",
                        "audience": "https://api.research.example",
                    }
                ]
            },
            "issuance_policy": {
                "workloads": {
                    "edge": {"scopes": [SCOPE]},
                    "report-agent": {"scopes": [SCOPE], "may_replace": True},
                }
            },
            "agents": {"enabled": True, "max_hops": max_hops, "registry_path": "agents.yaml"},
        },
        base_dir=directory,
    )
    app = create_app(build_components(settings))
    tts_keys = StaticKeySet.from_jwks(_jwks("tts", keys["tts"]))
    verifier = TokenVerifier(VerifierSettings(trust_domain=TRUST_DOMAIN), tts_keys)

    def client(workload: str) -> AsyncTransactionTokenClient:
        credential = PrivateKeyJwtCredential(
            workload,
            _secret(directory / f"{workload}.pem", keys[workload]),
            alg=ALG,
            kid=workload,
            token_endpoint=TOKEN_ENDPOINT,
        )
        http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app))
        return AsyncTransactionTokenClient(TOKEN_ENDPOINT, credential, verifier, http_client=http)

    return World(tts=client("edge"), report_agent=client("report-agent"), idp_key=keys["idp"])


def reports_service(token: VerifiedToken) -> str:
    """The protected resource's decision, with the reason when denied."""
    try:
        REPORTS_POLICY.enforce(AuthorizationRequest(token=token, caller=None, request_data={}))
    except PyTraTError as error:
        return f"DENIED ({error.reason.value})"
    return "ALLOWED"


def describe(token: VerifiedToken) -> str:
    ctx = token.claims.agentic_ctx
    if ctx is None:
        return "no agentic_ctx"
    chain = ctx.chain_metadata
    return (
        f"originator={ctx.originator.id} proximate={ctx.proximate_agent.id} "
        f"hops={chain.hop_count} min_assurance={chain.min_assurance_level} "
        f"req_wl={token.claims.req_wl}"
    )


async def run(directory: Path) -> dict[str, str]:
    world = build_world(directory)
    outcomes: dict[str, str] = {}
    async with world.tts, world.report_agent:
        print("1. User → external research agent (assurance: low)")
        external = await world.start_chain(client_id="partner-app", agent="external-research-agent")
        print(f"   token:   {describe(external)}")

        print("2. External agent delegates to the internal report agent (assurance: high)")
        delegated = await world.report_agent.replace(external)
        print(f"   token:   {describe(delegated)}")
        outcomes["delegated"] = reports_service(delegated)
        print(f"3. Reports service (requires medium): {outcomes['delegated']}")

        print("4. User → internal report agent directly")
        direct = await world.start_chain(client_id="report-agent", agent="internal-report-agent")
        print(f"   token:   {describe(direct)}")
        outcomes["direct"] = reports_service(direct)
        print(f"   Reports service: {outcomes['direct']}")

        print("5. One more agent hop beyond max_hops=2")
        try:
            await world.report_agent.replace(delegated)
            outcomes["third_hop"] = "ISSUED"
        except ExchangeError as error:
            outcomes["third_hop"] = f"REFUSED ({error.oauth_error})"
        print(f"   TTS: {outcomes['third_hop']}")
    return outcomes


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="pytrat-agents-") as tmp:
        outcomes = asyncio.run(run(Path(tmp)))
    expected = outcomes["delegated"].startswith("DENIED") and outcomes["direct"] == "ALLOWED"
    return 0 if expected and outcomes["third_hop"].startswith("REFUSED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
