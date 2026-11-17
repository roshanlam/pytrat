from __future__ import annotations

import json
import stat

import pytest
from typer.testing import CliRunner

from pytrat.cli import app
from pytrat.core import StaticKeySet
from pytrat.core.crypto import load_private_key_pem, private_key_to_pem
from pytrat.core.testing import TokenFactory

runner = CliRunner()

POLICY = """
version: 1
trust_domain: payments.internal
resources:
  - name: transfer-execution
    path: /internal/transfer
    method: POST
    allowed_scopes: [payments.transfer]
    bind_context: [amount_minor, currency]
"""


def test_version_lists_drafts() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "draft-ietf-oauth-transaction-tokens-11" in result.output


class TestKeys:
    def test_generate_writes_private_key_0600_and_public_jwks(self, tmp_path) -> None:
        result = runner.invoke(app, ["keys", "generate", "--kid", "tts-1", "--out", str(tmp_path)])
        assert result.exit_code == 0, result.output
        pem = tmp_path / "tts-1.pem"
        assert stat.S_IMODE(pem.stat().st_mode) == 0o600
        load_private_key_pem(pem.read_bytes())
        keys = StaticKeySet.from_jwks_file(tmp_path / "tts-1.jwks.json")
        assert keys.kids == {"tts-1"}
        assert "PRIVATE" not in result.output

    def test_generate_refuses_to_overwrite(self, tmp_path) -> None:
        args = ["keys", "generate", "--kid", "k", "--out", str(tmp_path)]
        assert runner.invoke(app, args).exit_code == 0
        assert runner.invoke(app, args).exit_code == 1
        assert runner.invoke(app, [*args, "--force"]).exit_code == 0

    @pytest.mark.parametrize(
        ("kid", "alg"), [("../escape", "ES256"), ("k", "HS256"), (".hidden", "ES256")]
    )
    def test_generate_rejects_bad_input(self, tmp_path, kid: str, alg: str) -> None:
        result = runner.invoke(
            app, ["keys", "generate", "--kid", kid, "--alg", alg, "--out", str(tmp_path)]
        )
        assert result.exit_code == 1

    def test_jwks_combines_private_and_public_pems(self, tmp_path) -> None:
        factory = TokenFactory.create("ES256")
        private = tmp_path / "a.pem"
        private.write_bytes(private_key_to_pem(factory.key.private_key))
        from pytrat.core.crypto import public_key_pem

        public = tmp_path / "b.pub.pem"
        public.write_bytes(public_key_pem(TokenFactory.create("EdDSA").key.public_key))
        result = runner.invoke(app, ["keys", "jwks", f"a=ES256={private}", f"b=EdDSA={public}"])
        assert result.exit_code == 0, result.output
        assert StaticKeySet.from_jwks(json.loads(result.output)).kids == {"a", "b"}
        assert '"d"' not in result.output

    @pytest.mark.parametrize("entry", ["missing-parts", "k=PS256={pem}"])
    def test_jwks_errors(self, tmp_path, entry: str) -> None:
        pem = tmp_path / "k.pem"
        pem.write_bytes(private_key_to_pem(TokenFactory.create("ES256").key.private_key))
        assert runner.invoke(app, ["keys", "jwks", entry.format(pem=pem)]).exit_code == 1


class TestPolicy:
    def test_valid(self, tmp_path) -> None:
        path = tmp_path / "policy.yaml"
        path.write_text(POLICY)
        result = runner.invoke(
            app, ["policy", "check", str(path), "--trust-domain", "payments.internal"]
        )
        assert result.exit_code == 0, result.output
        assert "POST /internal/transfer -> transfer-execution" in result.output

    def test_wrong_trust_domain_and_typo(self, tmp_path) -> None:
        path = tmp_path / "policy.yaml"
        path.write_text(POLICY)
        assert (
            runner.invoke(app, ["policy", "check", str(path), "--trust-domain", "other"]).exit_code
            == 1
        )
        path.write_text(POLICY.replace("allowed_scopes", "allowed_scope"))
        result = runner.invoke(app, ["policy", "check", str(path)])
        assert result.exit_code == 1
        assert "invalid policy" in result.output


class TestTokenInspect:
    def test_unverified_decode_never_prints_signature(self) -> None:
        token = TokenFactory.create().mint(txn="txn-1")
        result = runner.invoke(app, ["token", "inspect"], input=token)
        assert result.exit_code == 0
        assert result.output.startswith("UNVERIFIED")
        assert '"txn": "txn-1"' in result.output
        assert token.split(".")[2] not in result.output

    def test_expired_token_is_rejected(self, tmp_path) -> None:
        from pytrat.core.clock import FrozenClock

        factory = TokenFactory.create(clock=FrozenClock(1_700_000_000))
        jwks = tmp_path / "jwks.json"
        jwks.write_text(factory.key.key_set().to_json())
        token = factory.mint()
        args = ["token", "inspect", "--jwks", str(jwks), "--trust-domain", "payments.internal"]
        result = runner.invoke(app, args, input=token)
        assert "REJECTED: TOKEN_EXPIRED" in result.output

    def test_verified_fresh_token(self, tmp_path) -> None:
        import time

        from pytrat.core.clock import FrozenClock

        factory = TokenFactory.create(clock=FrozenClock(time.time()))
        jwks = tmp_path / "jwks.json"
        jwks.write_text(factory.key.key_set().to_json())
        args = ["token", "inspect", "--jwks", str(jwks), "--trust-domain", "payments.internal"]
        result = runner.invoke(app, args, input=factory.mint())
        assert result.exit_code == 0, result.output
        assert result.output.startswith("VERIFIED")

    @pytest.mark.parametrize("stdin", ["", "a.b", "!!.!!.!!"])
    def test_malformed_input(self, stdin: str) -> None:
        assert runner.invoke(app, ["token", "inspect"], input=stdin).exit_code == 1

    def test_jwks_requires_trust_domain(self, tmp_path) -> None:
        jwks = tmp_path / "jwks.json"
        jwks.write_text('{"keys": []}')
        token = TokenFactory.create().mint()
        assert (
            runner.invoke(app, ["token", "inspect", "--jwks", str(jwks)], input=token).exit_code
            == 1
        )
