# Security audit

!!! warning "No external audit has been performed yet"
    PyTraT has **not** been audited by an independent third party. The reviews below were run as
    part of development. They lower risk but do not replace an external audit. Do not rely on
    PyTraT for production authorization before one is done. This page is the brief for that audit.

## Reviews to date

| Review | Scope | Outcome |
|---|---|---|
| Adversarial review of v0.1 | All packages | 5 findings, all fixed with regression tests: workload impersonation via a self-asserted `sub` (P29), agent constraints bypassed by omitting `agentic_ctx` (P30), agent forgery via `act` in requester-asserted subjects (P28), a replacement-limit race, and a 500 on bound form bodies |
| Coverage-guided and property-based fuzzing | Every untrusted-input parser | 7 bugs, all fixed, including a **context-binding bypass** through NFC key collisions; see [Fuzzing](fuzzing.md) |
| Failure injection | TTS, JWKS, Agent Attribute Store, audit sink, replay store down | All paths deny; 41 tests in `tests/integration/test_failure_injection.py` |
| Adversarial review of the M9 changes | Redis, OpenTelemetry, enforcement, core parser fixes, Compose, interop and fuzz assets | 2 medium and 4 low findings, all fixed: Redis eviction re-enabling replay; missing TLS hostname checks on redis-py 5; cross-service replay-key collisions; lone surrogates causing a 500 at the TTS; a phantom issuance-log row on sink failure; and the single-use/sink trade-off, which is now documented (P31, P35, P36) |
| Replay window found during M9 | Single-use records | Records expired at `exp` while the verifier accepts until `exp + leeway`; now retained past the maximum leeway (P8) |

## Suggested audit scope

About 14,000 lines of library code in 10 packages, plus the reference TTS. In priority order:

1. **Token verification**: `pytrat.core.crypto`, `jws`, `validation`, `keys`, `claims`, `_json`.
   This is the only code that touches unverified input. Check:
    * the algorithm allowlist and key↔algorithm binding;
    * `typ` and `kid` handling;
    * size limits and strict JSON (duplicates, non-finite numbers, lone surrogates, depth);
    * the verification cache (keyed by digest, bounded, never outliving `exp`).
2. **Context binding**: `pytrat.core.binding`. Strict typed equality, canonicalisation, derived
   values, NFC collisions, and mismatches between what is checked and what the application reads.
3. **The enforcement pipeline**: `pytrat.policy.enforcement` and `compiler`. Check:
    * the order of checks, and that every outcome is audited;
    * replay recording;
    * the fail-closed paths, including FastAPI's protected-prefix middleware and startup
      route-coverage check (`pytrat.fastapi`), and the Django decorator and middleware.
4. **The reference TTS**: `pytrat.server`. Check:
    * RFC 7523 client authentication and assertion replay;
    * subject-token validation, including `act` handling (P28);
    * issuance policy;
    * replacement attenuation and the per-`txn` lock;
    * key rotation;
    * the hash-chained issuance log;
    * rate limiting.
5. **Agent profile (experimental)**: `pytrat.agents`. Monotonic attenuation (assurance minimum,
   hop count, immutable originator) and the `ToolRuntime` redaction guard.
6. **Outbound propagation**: `pytrat.client.http`. Host allowlist checked before connecting, no
   redirects, the `Authorization` header never used.
7. **Adapters**: `pytrat.redis` (atomicity, TTL, TLS, eviction) and `pytrat.otel` (no token or
   personal data in telemetry).

The [threat model](../threat-model.md) lists assets, assumptions and mitigations. The
[compatibility page](../compatibility.md) lists every place where PyTraT chose a behaviour the
drafts leave open; these choices deserve particular scrutiny.

## Reproducing the evidence

```bash
uv sync --all-packages
uv run pytest -q                                       # unit, conformance, security, integration
uv run pytest tests/security -q                        # attack-named tests and fuzz-corpus replay
docker build -f fuzz/Dockerfile -t pytrat-fuzz . && \
  docker run --rm pytrat-fuzz 300                      # Atheris, 5 minutes per harness
PYTRAT_TEST_REDIS_URL=redis://127.0.0.1:6379/0 uv run pytest packages/pytrat-redis -q
PYTRAT_TEST_COMPOSE=1 uv run pytest tests/integration/test_payment_compose.py -q
```

Report vulnerabilities as described in [Reporting vulnerabilities](policy.md).
