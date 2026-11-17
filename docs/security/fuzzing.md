# Fuzzing

Every parser that sees untrusted input is fuzzed in two ways:

* **Property-based (Hypothesis)**, on every CI run and Python version:
  `tests/security/test_fuzz_parsers.py`. The committed Atheris seed corpus is also replayed
  through every harness by `tests/security/test_fuzz_harnesses.py`.
* **Coverage-guided (Atheris/libFuzzer)**, nightly, in `.github/workflows/fuzz.yml`. There are 13
  harnesses in `fuzz/`, covering:
    * the verifier, including a structure-aware harness that signs fuzzer-built claims;
    * claims, strict JSON, JWKS and context binding;
    * the TTS form, subject-token and client-assertion validation;
    * workload JWTs;
    * YAML policies and the agent registry;
    * exchange responses.

The invariant is the same for all of them: arbitrary input produces a value or a *specific* PyTraT
error, never an unexpected exception. Some harnesses also check an independent oracle, for example
that a binding accepted by PyTraT really is equal, or that a client assertion's identity is the
key owner.

## Findings

The first campaigns found seven bugs. All are fixed, each with a regression test asserting the
specific reason code:

| Bug | Effect | Fix |
|---|---|---|
| Object keys colliding after Unicode NFC normalisation | **Binding bypass**: one spelling passed the `tctx` check while the service read the other | Rejected (P34) |
| `1e400` decoded to infinity | Broke the "no non-finite numbers" rule; unsignable at the TTS | Rejected (P33) |
| Deep nesting in JSON, signed claims and bound values | `RecursionError` escaped as a 500 | Depth caps (P33) |
| Non-string `kty` in a JWK | `TypeError` | `ConfigurationError(KEY_UNKNOWN)` |
| PyYAML constructor errors and non-UTF-8 files | Escaped the documented `ConfigurationError` | Translated |
| Audit sink raising during a TTS denial | Denial became a 500 | Denial preserved |
| Unexpected Agent Attribute Store errors | Request failed but no denial was logged | Recorded as `DEPENDENCY_UNAVAILABLE` |

The final 60–120 s runs found nothing new. Executions per harness ranged from about 4,000 (the YAML
loaders, which run slowly because PyYAML is pure Python) to 6.4 million.

--8<-- "fuzz/README.md:usage"
