# Benchmarks

What PyTraT costs per request, measured rather than estimated. Every number on this page comes
from `benchmarks/` and can be reproduced with one command. The raw results (statistics only; per-
round samples and the host name removed) are in
[`assets/benchmarks/2026-11-17-apple-m5-pro.json`](assets/benchmarks/2026-11-17-apple-m5-pro.json).

## Results

Run on 2026-11-17 at commit `a9fefde` plus the benchmarks added with this page.

| Benchmark | Median (µs) | IQR (µs) | ops/s | Rounds |
|---|---:|---:|---:|---:|
| `test_verify[ES256]` | 64.6 | 3.2 | 14,779 | 16,394 |
| `test_verify[EdDSA]` | 63.3 | 1.4 | 15,567 | 16,239 |
| `test_verify[PS256]` | 47.4 | 2.6 | 20,020 | 22,182 |
| `test_verify_cached_repeat` | 1.2 | 0.0 | 837,484 | 88,889 |
| `test_context_binding` | 2.8 | 0.1 | 351,208 | 196,738 |
| `test_fastapi_request[fastapi-baseline]` | 202.5 | 34.3 | 4,773 | 6,081 |
| `test_fastapi_request[fastapi-pytrat]` | 398.0 | 43.7 | 2,408 | 2,801 |
| `test_tts_issuance` | 573.5 | 99.6 | 1,616 | 1,952 |

*Median* and *IQR* (interquartile range) are per call. *ops/s* is pytest-benchmark's `1 / mean`,
so it is slightly lower than `1 / median` wherever the distribution has a slow tail.

### Reading the numbers

* **Verification** of one Txn-Token costs about 65 µs with ES256 or EdDSA and 47 µs with PS256
  (RSA verification is cheap; RSA *signing* at the TTS is not). This is the signature check plus
  strict header, claim, Trust Domain and lifetime validation.
* **Caching** (`VerifierSettings(cache_size=...)`) makes a repeat of the same token cost about
  1.2 µs: a SHA-256 digest lookup, a check that the verifying key is still trusted, and the time
  checks, which are re-evaluated on every hit. The cache is off by default.
* **Binding** four `tctx` fields with strict, canonical comparison costs about 2.8 µs.
* **A protected FastAPI request** costs about **196 µs more** (median) than the same route without
  PyTraT, 398 µs against 202 µs, in-process over ASGI. That difference is mostly two ES256
  signature verifications (the Txn-Token and the caller's workload JWT, about 130 µs together),
  plus re-reading the bound fields through FastAPI's validators, the policy checks, building the
  audit event and binding the token to the request context.
* **A token exchange** against the reference TTS costs about 574 µs of CPU end to end: the client
  signs an RFC 7523 assertion, the TTS verifies it, checks `jti` replay, validates the subject
  access token, applies the issuance policy, signs the Txn-Token and records it in the issuance
  log, and the client verifies the result. Network round trips come on top.

## Environment

| | |
|---|---|
| Machine | Apple M5 Pro (18 cores), 48 GiB RAM, arm64 |
| OS | macOS 26.6.2 (Darwin 25.6.0) |
| Python | CPython 3.14.4 (uv-managed) |
| Libraries | cryptography 50.0.2, PyJWT 2.15.1, pydantic 2.14.3 (pydantic-core 2.50.4), FastAPI 0.163.1, Starlette 1.10.0, httpx 0.28.1, uvicorn 0.54.0 |
| Harness | pytest 9.2.0, pytest-benchmark 5.3.1, uv 0.13.5 |
| Load | Not an isolated machine: the 1-minute load average was 7–8 during the run (other builds were running). Treat the absolute values as indicative and compare rows with each other. |

## Method

* pytest-benchmark's defaults (calibrated rounds within about one second per benchmark, minimum 5
  rounds) with warm-up enabled. One process, one thread; the garbage collector is left on.
* Keys are generated fresh per benchmark: ES256 (P-256), Ed25519 and RSA-2048 for PS256.
* The token is a realistic Txn-Token from `pytrat.core.testing.TokenFactory`: `iss`, `aud`, `iat`,
  `exp`, `txn`, `sub`, `scope`, `req_wl`, a four-member `tctx` and an `rctx`.
* The FastAPI benchmarks send the same JSON body through `httpx.AsyncClient` with
  `httpx.ASGITransport`, driven by one event loop. The protected route uses
  `require_transaction(scope=..., bind_fields=[4 fields], allowed_callers=[...])`, a
  `WorkloadJwtAuthenticator`, `NullSink` audit and a protected prefix (so the fail-closed middleware
  is active). The verifier cache is off, so every request verifies both signatures.
* The TTS benchmark calls `AsyncTransactionTokenClient.issue` against `pytrat.server.create_app`
  over `ASGITransport`, with the rate limiter raised out of the way and an in-memory issuance log.
* Log records below `WARNING` are disabled during the end-to-end benchmarks, because handler cost
  depends entirely on the deployment.

## What is not measured

* **Network and TLS.** Everything runs in one process. A real hop adds a TCP/TLS round trip, and
  token exchange adds a round trip to the TTS.
* **ASGI server overhead.** uvicorn (or another server), HTTP parsing and worker scheduling are not
  included; the baseline row shows the FastAPI share.
* **Concurrency and contention.** Single-threaded, one request at a time; no throughput under load,
  no tail latency under contention.
* **Persistent storage.** The TTS issuance log is in memory; with `audit_db_path` set, each
  issuance also appends to SQLite.
* **Audit and logging sinks.** `NullSink` and disabled `INFO` logs; a `JsonLinesSink` writes from a
  background thread, `LoggingSink` costs whatever your handlers cost.
* **JWKS refresh**, which happens off the request path.
* **Cold start.** Policy compilation, key parsing and route preparation happen once at startup.

## Reproduce

```bash
uv sync --all-packages
uv run pytest benchmarks --benchmark-only --benchmark-warmup=on \
  --benchmark-columns=min,median,iqr,mean,stddev,ops,rounds --benchmark-sort=name \
  --benchmark-json=benchmark.json
```

Benchmarks live in `benchmarks/test_bench_core.py` (verification, caching, binding) and
`benchmarks/test_bench_e2e.py` (FastAPI request, TTS issuance). They are not part of the default
`pytest` run. Compare two runs with `pytest-benchmark compare`.
