# Interoperability: Tokenetes

[Tokenetes](https://tokenetes.io) (formerly *Tratteria*) is an open-source Transaction Token
Service written in Go, and a CNCF Sandbox project. This page compares it with PyTraT, which targets
`draft-ietf-oauth-transaction-tokens-11` (below, "-11"), field by field and in both directions.

**Summary.** Tokens do not interoperate in either direction, and PyTraT does not try to make them.
Tokenetes implements an early revision of the draft: `typ: txn_token`, `purp`, `azd`, and a
Subject-Identifier object in `sub`. PyTraT's verifier rejects every Tokenetes token at the first
header check (`TOKEN_TYPE_INVALID`). tokenetes-agent cannot decode a -11 token's string `sub`.
The RS256 signature and the JWK format do interoperate. So the blockers are the token's vocabulary,
not its cryptography.

Everything below was checked against Tokenetes source at the commits listed under
[Sources](#sources). Behaviour marked **live** was also observed against the real Tokenetes and
tokenetes-agent binaries (see [Live test stack](#live-test-stack)).

## Which draft does Tokenetes implement?

Tokenetes does not say. Its docs link the unversioned datatracker page. Its token format is closest
to **draft-ietf-oauth-transaction-tokens-01** (March 2024), with two differences:

* `sub` holds a Subject-Identifier object. The -00 draft carried that object in `sub_id`.
* `rctx` is the caller's `request_context` verbatim, so it has no `req_wl`.

tokenetes-agent's claim struct still has the -00 `req_ctx` member.

| Feature (Tokenetes) | First draft with it | Last draft with it |
|---|---|---|
| Header `typ: txn_token` | -00 | -01 (-02 changed it to `txntoken+jwt`) |
| `rctx` claim (with `req_ip`) | -01 (-00 used `req_ctx`) | current |
| `purp` claim | -00 | -06 (-07 renamed it to `scope`) |
| `azd` claim | -00 | -03 (-04 renamed it to `tctx`) |
| base64url `request_context` / `request_details` | -00 | -06 (-07 switched to plain JSON) |
| `token_type: N_A` in the response | -01 | current |
| No top-level `req_wl` claim | — | -01 to -06 put `req_wl` inside `rctx`; -07 made it a top-level REQUIRED claim (now -11 §9.2). Tokenetes emits it in neither place. |

Revision boundaries come from comparing the archived draft texts (-00 to -07). They do not come
from the Document History appendix, whose "Since Draft N" headings are ambiguous.

The last functional change to the token format was commit "Change scope to purp" on 2024-08-06.
Since then the repositories have had renames (Tratteria to Tokenetes, January 2025), dependency
and CVE updates, and CI maintenance. The last release is tokenetes v1.0.1 (2025-07-21). The last
commit to `tokenetes` is 2026-07-30 and to `tokenetes-agent` 2025-04-14. In short, the project is
maintained, but its protocol has stayed at the 2024 draft.

## Architecture and how Tokenetes is run

| Aspect | Tokenetes | Source |
|---|---|---|
| Components | `tokenetes` (the TTS), `tokenetes-agent` (a verifying sidecar or API), `tconfigd` (a Kubernetes controller that distributes configuration and keys) | org repos |
| Packaging | Container images `ghcr.io/tokenetes/tokenetes:latest` and `ghcr.io/tokenetes/tokenetes-agent:latest`. There are no versioned image tags. Kubernetes manifests are in `tokenetes/kubernetes/`. | `kubernetes/tokenetes-deployment.yaml` |
| Hard requirements | A SPIRE Workload API socket (startup is fatal after 15 s without one). `TCONFIGD_HOST`, `TCONFIGD_SPIFFE_ID` and `MY_NAMESPACE`. A tconfigd WebSocket over SPIFFE mTLS, which supplies *all* configuration. | `service/cmd/main.go`, `pkg/config/config.go`, `pkg/configsync/configsync.go` |
| Configuration | `TokenetesConfig` and `TraT` CRDs, pushed by tconfigd as JSON "generation rules". | `tconfigd`, `example-application/deploy/` |
| Signing key | RSA-2048, generated in memory at process start, `alg` RS256. The `kid` is the standard base64 encoding of 16 random bytes. A new key is created on every restart, and each replica has its own key. | `pkg/keys/keys.go` |
| JWKS | **There is no HTTP JWKS endpoint.** Keys reach verifiers only through tconfigd, which sends `GET_JWKS_REQUEST` to every Tokenetes instance over the WebSocket and merges the results for tokenetes-agent. | `pkg/configsync/configsync.go`, `tconfigd/.../clientmanager.go`, `tokenetes-agent/.../tokenetestrustbundlemanager.go` |

## Token request (RFC 8693 profile)

| Field or aspect | -11 (PyTraT) | Tokenetes | Compatible? |
|---|---|---|---|
| Endpoint | Deployment-defined | `POST https://<tokenetes>:443/token_endpoint` | n/a |
| Workload authentication | Mutual authentication is MUST. Asymmetric methods, RFC 7523 or SPIFFE are SHOULD (§11.5). PyTraT uses RFC 7523 `private_key_jwt`. | **SPIFFE mTLS only.** The client X.509-SVID's first URI SAN must be listed in `tokenGenerationAuthorizedServiceIds`. | **No.** The PyTraT client cannot present an X.509-SVID. **live:** a connection without a client certificate fails the TLS handshake. |
| `grant_type` | token-exchange URN (§11.1) | Same | Yes |
| `requested_token_type` | `urn:ietf:params:oauth:token-type:txn_token` | Same | Yes |
| `audience` | REQUIRED, the Trust Domain | REQUIRED (403 if empty), but **ignored**: `aud` always comes from configuration | Partly |
| `scope` | REQUIRED; the TTS MUST evaluate it (§11.1, §11.3) | **Ignored.** `purp` comes from the TraT rule that matches `request_details.path` and `method`. | **No** |
| `subject_token_type` | Any; PyTraT accepts `access_token`, `jwt`, `id_token`, `txn_token`, and `self_signed` / `unsigned_json` when opted in (§11.2) | `id_token` or `self_signed` only; anything else gets 422 | Partly. **live:** an `access_token` request got 422. |
| Self-signed subject validation | MUST validate the signature if the token is signed (§11.3) | Configurable. `validation: false` parses the token without verifying it. | Tokenetes can be configured below the -11 MUST |
| `request_context` | RECOMMENDED, a JSON object (§11.1) | **REQUIRED**, as unpadded **base64url** JSON | **No.** **live:** plain JSON got 400. |
| `request_details` | RECOMMENDED, a JSON object | **REQUIRED**, as base64url JSON `{path, method, queryParameters, headers, body}` | **No.** **live:** plain JSON got 400. |
| Response `token_type` | `N_A` (§11.4) | `N_A` | Yes (**live**) |
| Response `issued_token_type` | txn_token URN | Same | Yes (**live**) |
| Response `access_token` | The Txn-Token | Same | Yes (**live**) |
| Error format | RFC 6749 §5.2 JSON | Plain text from `http.Error` with statuses 400, 403, 422 or 500 | No |
| Replacement Txn-Tokens | `subject_token_type=txn_token` (PyTraT profile P4) | Not supported (`txn_token` subject type gets 422) | No |

## Token format, field by field

### Direction 1: Tokenetes token verified by PyTraT

PyTraT's verifier runs a fixed order of checks (see `pytrat.core.validation`). The table lists what
it does with each Tokenetes field. `tests/interoperability/test_tokenetes_fixtures.py` pins this.
The test fixes one difference at a time and asserts the *next* `ReasonCode`.

| Field | Tokenetes | -11 requirement | PyTraT result |
|---|---|---|---|
| `typ` (header) | `txn_token` | MUST be `txntoken+jwt` (§9.1) | **`TOKEN_TYPE_INVALID`**. This is the first check and fails for every Tokenetes token. (**live**) |
| `alg` | RS256 | Unspecified. PyTraT defaults to ES256, EdDSA and PS256 (profile P1). | `ALGORITHM_NOT_ALLOWED` unless the verifier is configured with `algorithms={"RS256"}`. RS256 is a supported opt-in. |
| `kid` | Standard base64 (may contain `+/=`) | Unspecified. PyTraT requires a `kid` (P2). | Accepted |
| JWKS | `{kty, n, e, kid, alg: RS256, use: sig}` | n/a | Loads with `StaticKeySet.from_jwks` (**live**), but there is no URL to fetch it from (see above). |
| `iss` | From configuration | OPTIONAL (§9.2) | Accepted. Checked when `expected_issuer` is set (P7). |
| `aud` | A single string from configuration, e.g. `https://alphastocks.com/` | MUST identify the Trust Domain (§9.2, §12.2) | Accepted when `trust_domain` matches **exactly**. A trailing `/` counts (`TRUST_DOMAIN_MISMATCH`). |
| `iat` / `exp` | Integer seconds; lifetime is the configured `lifeTime` (15 s in the example) | REQUIRED | Accepted. A `lifeTime` over 300 s gives `LIFETIME_EXCEEDED` (P3). |
| `txn` | UUID string | REQUIRED | Accepted |
| `sub` | **An object** `{"format": "email", "email": ...}` for OIDC subjects (a self-signed subject's `sub` is copied verbatim) | REQUIRED and a string (§9.2; RFC 7519 §4.1.2 StringOrURI) | **`CLAIM_INVALID` (`sub`)** for the object form |
| `scope` | **Absent**; Tokenetes sends `purp` | REQUIRED (§9.2) | **`CLAIM_MISSING` (`scope`)**. `purp` is an unknown claim and is ignored (§9.2). |
| `req_wl` | **Absent** | REQUIRED (§9.2) | **`CLAIM_MISSING` (`req_wl`)** |
| `tctx` | **Absent**; Tokenetes sends `azd` (may be `null`) | RECOMMENDED (§9.2, §9.2.3) | `azd` is ignored as unknown, so the authorization details are *not* available to PyTraT bindings |
| `rctx` | The caller's `request_context`, copied verbatim | RECOMMENDED, TTS-authoritative (§9.2.2, §11.3) | Accepted as `rctx` |
| Carrier | `Txn-Token` header | §12.1 | Same |

If every difference above were repaired, PyTraT would accept the token
(`test_fully_repaired_tokenetes_token_is_accepted_and_azd_is_ignored`). But no setting of either
product produces such a token.

### Direction 2: PyTraT TTS token verified by tokenetes-agent

tokenetes-agent (`trat/trat.go`, `tratverifier/tratverifier.go`, `verificationrules/v1alpha1/rules.go`)
uses `golang-jwt/jwt` v3.2.2 and decodes claims into a fixed struct.

| Field | PyTraT TTS | tokenetes-agent behaviour | Result |
|---|---|---|---|
| `alg` | ES256 by default; RS256 and others are opt-in | Only `*jwt.SigningMethodRSA` (RS256/384/512); PS* and ES* are refused | ES256: **error** "unexpected signing method", HTTP 500 from `/verify-trat` (**live**). RS256 works. |
| `typ` | `txntoken+jwt` | Not checked | No issue (**live**) |
| `kid` | Required | Required; looked up in the tconfigd-supplied key set | Works only if tconfigd hands out PyTraT's keys. **Upstream tconfigd cannot do this**: it merges keys from Tokenetes instances only. The live stack's mock tconfigd adds them for the test. |
| `sub` | A string (§9.2) | Decoded into `struct{format, email}` | **Decoding error**: "cannot unmarshal string into Go struct field TraT.sub", HTTP 500 (**live**). This happens before the signature check. |
| `scope` | e.g. `stock-trade` | Not read; rules match on `purp` | Even if decoding succeeded, no rule would match, so the reason would be `invalid authorization details` |
| `tctx` | Transaction details | Not read; rules compare `azd` | No authorization-detail checks are possible |
| `req_wl` | A top-level string | Expects `req_ctx.req_wl` as `[]string` (from draft -00); never used in decisions | Ignored |
| `iss` / `aud` | From PyTraT configuration | Compared exactly with `TokenetesConfig` issuer and audience | Works if configured to match |
| `exp` / `iat` | Integer seconds | `StandardClaims.Valid()` with no leeway | Works |

As a diagnostic (`test_tokenetes_agent_accepts_pytrat_signature_in_tokenetes_vocabulary`), a token
signed by PyTraT's own TTS signer (`KeyRingSigner`, RS256, `typ: txntoken+jwt`) but carrying
Tokenetes' claims (`sub` object, `purp`, `azd`) **is accepted** by tokenetes-agent (**live**).
That confirms the crypto and the keys interoperate. The PyTraT TTS never issues that shape.

## What is demonstrated and what is not

Demonstrated (live, against the real binaries pinned in `tests/interoperability/docker/Dockerfile`):

* Tokenetes issues a token over SPIFFE mTLS. Its exchange response uses the -11 members
  (`N_A`, the txn_token URN).
* A Tokenetes token, signature-verified by `pytrat.core.verify_jws` with Tokenetes' JWKS, has
  exactly the header and claim set in `tests/interoperability/vectors/tokenetes.json`. That check
  guards the fixtures against drift.
* `TokenVerifier` rejects a live Tokenetes token with `TOKEN_TYPE_INVALID`, even when it trusts
  Tokenetes' keys, allows RS256 and is configured with the right audience and issuer.
* Tokenetes rejects -11-style requests: an `access_token` subject gets 422, and plain-JSON
  `request_details` gets 400. It also refuses connections without a client SVID.
* tokenetes-agent fails to verify an RS256 PyTraT TTS-signed -11 token (500, a `sub` decoding
  error) and an ES256 one (500, wrong signing method). It accepts PyTraT-signed tokens that use
  Tokenetes' vocabulary.

Not demonstrated or not claimed:

* Any working end-to-end flow between the two products. None exists without code changes on one
  side.
* The live stack is not a production topology. It runs one container with SPIRE (join token, unix
  workload attestor), a **mock tconfigd** (`tests/interoperability/docker/mock_tconfigd.py`, built
  from the message protocol in Tokenetes source) and test-only settings: self-signed subject
  validation is off, and extra keys are injected into tokenetes-agent's trust set. Behaviour that
  depends on the real tconfigd controller or Kubernetes was not exercised.
* The PyTraT side of direction 2 uses the reference TTS's signing component (`KeyRingSigner`) with
  the TTS's -11 claim set. It does not use the full HTTP issuance pipeline.
* OIDC subject-token validation, the Tokenetes Access Evaluation API and the interception mode of
  tokenetes-agent were not exercised.

## Gap analysis and recommendation

Read in the -11 sense, Tokenetes has several incompatibilities: `typ`, `sub` type, `purp`/`scope`,
`azd`/`tctx`, the missing `req_wl`, base64url request parameters, an ignored `scope` request
parameter, and key distribution only through tconfigd. Interop could come from either side:

1. **Tokenetes moves to -11 (recommended).** This is the only path that preserves both products'
   guarantees. It needs `typ: txntoken+jwt`, a string `sub`, `scope`, `tctx`, `req_wl`, JSON
   request parameters, and ideally an HTTPS JWKS endpoint. PyTraT would then verify Tokenetes
   tokens with only `algorithms={"RS256"}` configured. The PyTraT-to-Tokenetes direction would
   also need tokenetes-agent to accept other algorithms and to trust non-Tokenetes keys.
2. **A compatibility mode in PyTraT's verifier: not done, and not recommended.** Accepting
   `txn_token`, mapping `purp` to `scope` and `azd` to `tctx`, and inventing a `req_wl` would mean
   relaxing the header `typ` check and treating draft-era claim names as authorization inputs. That
   breaks the explicit-typing defence (§9.1) and widens what the verifier accepts. The CLAUDE.md
   invariants rule it out for the core verifier. If a deployment must consume Tokenetes tokens, a
   separate, clearly labelled translator would do it. That translator would verify Tokenetes
   tokens with its own configuration and *re-issue* -11 tokens through a TTS. It would sit outside
   `pytrat.core`, and it should be designed as its own milestone, not added to the verifier.

## Live test stack

`tests/interoperability/docker/` starts SPIRE, a mock tconfigd, Tokenetes and tokenetes-agent in
one container (no Kubernetes). Upstream images are pinned by digest in the `Dockerfile`.

```bash
docker compose -f tests/interoperability/docker/docker-compose.yml up -d --build --wait
PYTRAT_TOKENETES_URL=http://127.0.0.1:18080 uv run pytest tests/interoperability -m interop -v
docker compose -f tests/interoperability/docker/docker-compose.yml down
```

Ports are bound to loopback only:

* 18080: mock tconfigd control API
* 18443: Tokenetes token endpoint (SPIFFE mTLS)
* 19030: tokenetes-agent `/verify-trat`

The gateway's X.509-SVID for the host client is written to `tests/interoperability/docker/.run/`,
which git ignores. Without `PYTRAT_TOKENETES_URL` the live tests are skipped; the fixture tests
always run.

!!! warning "Test-only stack"
    The live stack is for interoperability tests only. The mock tconfigd's `PUT /extra-jwks`
    endpoint is unauthenticated, so any local process can inject verifier keys. Its ports are
    bound to `127.0.0.1`. `entrypoint.sh` writes the gateway SVID private key world-readable
    (0644) into the git-ignored `.run/` directory. Never expose this stack beyond loopback or
    reuse its configuration.

## Sources

* tokenetes: <https://github.com/tokenetes/tokenetes> @ `f9b7acf60f2df60acbe9749e570a502aa0193fb6`
  (main, 2026-07-30). Last release v1.0.1 @ `35b49237035625062535f1b7f15799473661bd5e`.
  Image `ghcr.io/tokenetes/tokenetes@sha256:fa5c3947b8290c8b9952b06f6a7a3f9c43e8a1b18020d7028950cfee1102b4e3`
  (built 2026-07-30).
  Files: `service/handler/handler.go`, `service/pkg/service/service.go`, `service/pkg/keys/keys.go`,
  `service/pkg/common/common.go`, `service/pkg/generationrules/v1alpha1/rules.go`,
  `service/pkg/subjecttokenhandler/*.go`, `service/pkg/subjectidentifier/subjectidentifier.go`,
  `service/pkg/middlewares/middleware.go`, `service/pkg/configsync/configsync.go`,
  `service/cmd/main.go`.
* tokenetes-agent: <https://github.com/tokenetes/tokenetes-agent> @
  `b848c12ad3ac5a5d6bc89d5b46ac9c64b68a8af4` (main, 2025-04-14; release v1.0.0).
  Image `ghcr.io/tokenetes/tokenetes-agent@sha256:22cc6a48385c2b9fa5650706506dfa02d92b9e8fcaddeceae95c90a5976cd777`.
  Files: `service/trat/trat.go`, `service/tratverifier/tratverifier.go`,
  `service/verificationrules/v1alpha1/rules.go`,
  `service/tokenetestrustbundlemanager/tokenetestrustbundlemanager.go`, `service/api/handler/handler.go`.
* tconfigd: <https://github.com/tokenetes/tconfigd> @ `0b9f5cc2d3f8885813ce6e5ced899abf11d5cddd`
  (v1.0.1). File: `service/websocketserver/clientmanager.go`.
* example-application: <https://github.com/tokenetes/example-application> @
  `2bd679d6a5ed968fc1c29ef914147398fb05b3fd`. Files: `gateway/pkg/middleware/txntokenmiddleware.go`,
  `deploy/alpha-stocks-dev/tokenetes-resources/*.yaml`.
* Documentation: <https://tokenetes.io> (source: <https://github.com/tokenetes/website>,
  `content/docs/generating-and-verifying-trats/_index.md`).
* Draft history: <https://www.ietf.org/archive/id/draft-ietf-oauth-transaction-tokens-00.txt>
  through `-07.txt` (compared directly), and the vendored -11
  (`docs/spec/draft-ietf-oauth-transaction-tokens-11.txt`).
