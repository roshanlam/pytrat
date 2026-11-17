# PyTraT

Python implementation of OAuth Transaction Tokens (`draft-ietf-oauth-transaction-tokens-11`) with an
experimental AI-agent profile (`draft-araut-oauth-transaction-tokens-for-agents-03`).

This is a **security library**. A bug here is an authorization bypass in someone else's system.
Correctness and clarity beat cleverness and feature count, every time.

`plan.md` is the source of truth for architecture, milestones and open decisions. Read the milestone
you are working on before writing code. If you deviate from the plan, update the plan in the same change.

## Commands

```bash
uv sync --all-packages            # install the whole workspace
uv run ruff format .              # format
uv run ruff check . --fix         # lint
uv run mypy                       # type-check (strict, whole workspace)
uv run pytest                     # all tests
uv run pytest packages/pytrat-core -q            # one package
uv run pytest -k "expired" -q                    # one behaviour
uv run pytest -m "not integration" -q            # fast loop
uv run pytest --cov --cov-report=term-missing    # coverage
```

A change is done only when `ruff format --check`, `ruff check`, `mypy` and `pytest` all pass.
Never report work as complete without having run them.

## Layout

uv workspace; every package ships a slice of the `pytrat` **PEP 420 namespace**.
There is never a `pytrat/__init__.py` anywhere.

```
packages/pytrat-core     pytrat.core     claims, verification, scopes, binding, audit events, errors
packages/pytrat-policy   pytrat.policy   YAML policy model, compiler, evaluator
packages/pytrat-client   pytrat.client   RFC 8693 exchange, workload credentials, propagating HTTP client
packages/pytrat-fastapi  pytrat.fastapi  dependencies, middleware, error responses
packages/pytrat-server   pytrat.server   reference Transaction Token Service
packages/pytrat-agents   pytrat.agents   experimental agent profile
packages/pytrat-cli      pytrat.cli      developer tooling
packages/pytrat-django   pytrat.django   middleware and decorators
```

Dependency direction is one-way and enforced by import-linter (`uv run lint-imports`):

```
core  <-  policy  <-  fastapi / django
core  <-  client  <-  fastapi / django
core  <-  agents  <-  server
core, policy  <-  server
everything  <-  cli
```

`pytrat.core` imports no web framework, no HTTP client, and nothing from `pytrat.agents`.

## Security invariants (never weaken; a failing test here is never "flaky")

1. **Fail closed.** Missing key, policy, claim, registry entry or dependency means *deny*. No
   fallback path may be more permissive than the main path. No `except Exception: pass`.
2. **Verify before reading.** Never act on claims from an unverified JWT. The only function allowed
   to parse an unverified token is the header peek in `pytrat.core.crypto`, and it returns only `kid`
   and `alg`.
3. **The token never chooses its own trust.** Keys come from trusted configuration, selected by
   `kid`. Never honour `jwk`, `jku`, `x5u`, `x5c` headers. Algorithms come from an explicit
   allowlist; `none` and all `HS*` are rejected unconditionally and are not configurable.
4. **Tokens and secrets never reach logs, exceptions, `repr`, or audit events.** Carry them in
   `SecretStr`-style wrappers. To correlate, log `txn` or a SHA-256 digest of the token.
5. **Replacement only attenuates.** `txn`, `sub`, `aud`, `act`, `originator` never change; scope
   only shrinks; assurance only falls; `hop_count` only rises.
6. **Only the TTS signs.** No package other than `pytrat.server` may hold signing keys or construct
   a signed Transaction Token. Test helpers that mint tokens live in `pytrat.core.testing` and are
   never imported by production code.
7. **`Txn-Token` header only.** Never read from or write to `Authorization`. Never send it to a host
   outside the configured allowlist. Never follow redirects with it.
8. **A Transaction Token is not authentication.** Workload identity is established separately.
9. **Strict comparison.** Context binding compares canonical values with exact type equality
   (`True != 1`, `1 != 1.0`, `"1" != 1`). Floats are rejected in bound fields.
10. **Agent `session_id` is a correlation hint**, never an authorization input.

If a task seems to require breaking one of these, stop and raise it with the user.

## Specification discipline

- The drafts are normative; `plan.md` and this file are not. Vendored copies live in `docs/spec/`.
  When they disagree with the plan, the spec wins and the plan gets fixed.
- Every normative rule we implement carries a short comment citing draft and section, e.g.
  `# txn-tokens-11 §12.2`. Every such rule has a conformance test whose name or docstring cites the
  same section.
- Where the spec is silent and we chose a behaviour, mark it `# PyTraT profile:` and record it in
  `docs/compatibility.md`. Do not present a PyTraT choice as protocol.
- Preserve claim names exactly (`req_wl`, `tctx`, `rctx`, `agentic_ctx`). Python-friendly aliases
  are properties, not renamed fields.
- Unknown claims are ignored, never rejected (txn-tokens-11 §9.2).

## Code standards

**Types**
- Python 3.12+ syntax: `type` aliases, PEP 695 generics, `X | None`, `Self`, `override`.
- mypy strict with no untyped defs. No `Any` in public signatures. `# type: ignore` needs an error
  code and a reason.
- Public data is immutable: `frozen=True, slots=True` dataclasses or frozen Pydantic models; tuples
  and `frozenset`, not lists and sets; `Mapping`, not `dict`, in signatures.
- Pydantic v2 only at trust boundaries (JWT payloads, YAML policy, HTTP bodies), always `strict=True`.
  Internal values are plain dataclasses.
- Ports are `typing.Protocol`s defined next to their consumer (`KeyProvider`, `AuditSink`,
  `ReplayStore`, `AgentAttributeStore`, `WorkloadCredential`, `Clock`). No ABC hierarchies.

**Structure**
- Sans-IO core: protocol logic is pure functions over values. I/O lives in thin shells. Sync and
  async variants share the pure part and differ only in the shell; never copy logic between them
  and never wrap one in the other with `asyncio.run`.
- Functions do one thing and fit on a screen. Prefer a module of functions to a class with no state.
- Dependencies are passed in (constructor or argument). No module-level mutable state, no singletons,
  no import-time side effects. Time comes from an injected `Clock`, never `time.time()` inline.
- Each package's `__init__.py` re-exports its public API and defines `__all__`. Everything else is
  private (`_module.py` or leading underscore) and may change freely.
- No speculative abstraction: add an interface when there is a second implementation or a test seam,
  not before.

**Errors**
- All raised errors derive from `pytrat.core.errors.PyTraTError` and carry a stable
  `ReasonCode` (`StrEnum`). Reason codes are public API: add, never rename.
- Raise the most specific error at the point of detection; translate to HTTP only at the framework
  edge. Error messages name the failed check, never the token, key material or bound values.
- Never return `None`/`False` to signal a security failure. Verification returns a value or raises.

**Style**
- ruff handles formatting and linting; do not hand-format. Line length 100.
- Docstrings (Google style) on every public symbol: what it guarantees, what it raises. Comments
  explain *why* or cite the spec; they do not narrate the code.
- Names say what the thing is: `verified_token`, `unverified_header`, `trusted_keys`. Anything not
  yet validated has `raw_` or `unverified_` in its name.
- No `print`; use `logging.getLogger(__name__)`. Libraries never configure logging.
- Constants for every protocol string (`pytrat.core.constants`); no URNs or header names inline.

**Performance**
- The verify path does no I/O and no per-request allocation that can be done at startup: parse keys,
  compile policies and binding accessors once.
- Measure before optimising. Any performance claim in docs needs a benchmark in `benchmarks/`.
- Caches are bounded, keyed by a digest (never the raw token), and never outlive `exp`.

## Testing

- pytest, `pytest-asyncio` in auto mode, Hypothesis for parsers/comparators/attenuation.
- Unit tests live beside each package (`packages/*/tests`). Cross-package suites live in
  `tests/{integration,conformance,security}`.
- Every rejection path has a test asserting the **specific** `ReasonCode`, not just "raises".
  Every bug fix starts with a failing test.
- Security tests are written as attacks: forge, swap, replay, widen, redirect. Name them for the
  attack (`test_rs256_public_key_used_as_hmac_secret_is_rejected`).
- Use `pytrat.core.testing` (`TokenFactory`, `FrozenClock`, generated keys). Never commit real or
  realistic key material; generate keys in fixtures.
- No network and no sleeping in unit tests. `httpx.MockTransport` / ASGI transport for HTTP.
- Coverage floor: 95% line + branch for `core`, `policy`, `agents`, and server issuance/replacement;
  90% elsewhere.

## Workflow

- Work one milestone slice at a time, in the order `plan.md` gives. Each slice lands with its tests,
  types and docs; no "tests later".
- Keep diffs small and single-purpose. Do not refactor unrelated code in a feature change.
- New runtime dependencies need a stated reason in the PR and an entry in the plan's dependency
  table. Prefer the standard library.
- Conventional Commits (`feat(core): ...`, `fix(server): ...`). Update `CHANGELOG.md` for anything
  user-visible. Commit or push only when asked.
- Public API changes update the docs and the example in the same change.
