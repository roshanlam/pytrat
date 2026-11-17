# Coverage-guided fuzzing

Atheris (libFuzzer for Python) harnesses for every PyTraT parser that sees untrusted input. Each
harness asserts the library's contract, not just "does not crash": arbitrary input yields a value
or the *specific* PyTraT error the API documents, never another exception type, and accepted
values satisfy the guarantees the API promises (see each module's docstring).

| Harness (`fuzz/fuzz_<target>.py`) | Target | Raises only | Extra invariants |
|---|---|---|---|
| `verify_token` | `TokenVerifier.verify`, raw header value | `TokenError` | nothing unsigned verifies; no token in errors |
| `verify_signed` | `TokenVerifier.verify`, fuzzer-built header/payload **signed with the trusted key** | `TokenError` | accepted ⇒ right Trust Domain, kid, lifetime window |
| `parse_claims` | `parse_claims` on strictly decoded payloads | `TokenError` | accepted claims round-trip through `to_payload` |
| `strict_json` | `strict_loads` | `ValueError` | differential vs `json.loads`; no duplicates, no non-finite numbers |
| `jwks` | `StaticKeySet.from_jwks_bytes`, client `parse_jwks` | `ConfigurationError` | accepted keys are public, asymmetric, never `none`/`HS*` |
| `binding` | `ContextBinding.check` | `PyTraTError` | independent oracle: a pass means exact-type equality, no ambiguous keys |
| `token_form` | TTS `parse_token_request` | `OAuthError` | accepted requests are complete and never use a refresh token |
| `subject_token` | `JwtAccessTokenValidator`, `SelfSignedValidator`, `UnsignedJsonValidator` | `OAuthError` | accepted subjects unexpired; requester-asserted subjects carry no `act` |
| `client_assertion` | `PrivateKeyJwtAuthenticator` (RFC 7523) | `OAuthError` | identity = key owner; a replay is refused with `REPLAY_DETECTED` |
| `workload_jwt` | `WorkloadJwtAuthenticator.authenticate` | `PyTraTError` | identity = key owner; repeated header never accepted |
| `policy_yaml` | `pytrat.policy.load_policy_text` | `ConfigurationError` | |
| `agent_registry` | `pytrat.agents.YamlAgentStore` | `ConfigurationError` | loaded records resolve and use known assurance levels |
| `exchange_response` | client `parse_exchange_response` | `ExchangeError` | errors never echo a token; only 200 JSON is accepted |

Structure-aware harnesses (`verify_signed`, `subject_token`, `client_assertion`,
`workload_jwt`) split the input on NUL bytes into a JOSE header and a payload, merge them as JSON
overrides onto a valid credential and sign the result with a key the code under test trusts, so
the fuzzer spends its time in claim validation instead of failing signature checks. Keys are
generated at import time; no key material is stored anywhere in the repository.

## Running

Atheris ships Linux x86-64 wheels only (3.1.0: CPython 3.12–3.14). On any other platform,
including Apple Silicon, use the Docker image (it runs under emulation there):

```bash
docker build -f fuzz/Dockerfile -t pytrat-fuzz .
docker run --rm pytrat-fuzz 60                    # every harness, 60 s each
docker run --rm pytrat-fuzz 600 verify_signed     # one harness, 10 minutes
docker run --rm -v "$PWD/.fuzz-work:/work" -e FUZZ_WORK_DIR=/work pytrat-fuzz 60   # keep logs
```

On Linux x86-64 without Docker:

```bash
uv sync --all-packages --group fuzz
uv run fuzz/run.sh 60                            # or: uv run python -m fuzz.fuzz_jwks -help=1
```

`fuzz/run.sh [SECONDS] [TARGET ...]` reads the committed seeds in `fuzz/corpus/<target>/`
without modifying them, writes new inputs to `$FUZZ_WORK_DIR/<target>/corpus`, crash
reproducers to `$FUZZ_WORK_DIR/<target>/artifacts/`, and exits non-zero if any harness failed.

## Without Atheris

Every harness's `TestOneInput` is plain Python. `tests/security/test_fuzz_harnesses.py` replays
the whole seed corpus through them on every CI run and Python version, so a regression input
added to a harness's `seeds()` becomes a permanent test.

## When the fuzzer finds something

1. Reproduce: `python -m fuzz.fuzz_<target> <artifact>` (runs that one input).
2. Write a failing test in the package's normal test suite that asserts the specific
   `ReasonCode` (CLAUDE.md: every bug fix starts with a failing test), then fix the code.
3. Add a minimal form of the input to the harness's `seeds()` with a `# Regression:` comment and
   regenerate the corpus: `uv run python -m fuzz.make_corpus`.

The JWKS seeds contain freshly generated public keys, so regenerating rewrites those files; that
churn is expected.
