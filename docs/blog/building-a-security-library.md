# What building a security library in Python taught me

*Fail closed, verify before reading, and let the fuzzer argue with you. Lessons from building
PyTraT, including three bugs in my own code that tests written by me did not catch.*

---

[PyTraT](https://github.com/roshanlam/pytrat) implements OAuth Transaction Tokens: signed, short-lived
tokens that carry what a user authorized through every hop of a microservice call chain. (The
[previous post](transaction-tokens-100-to-9000.md) explains the problem it solves.)

A bug in most libraries is a bug. A bug in this one is an authorization bypass in somebody else's
system. That changes how you build it. These are the practices that mattered most, and the bugs
that got past them anyway.

## 1. Write the invariants down before the code

Before the first module, I wrote ten rules that the code may never break, and kept them in the
repository next to the code:

1. **Fail closed.** A missing key, policy, claim or dependency means *deny*. No fallback path may be
   more permissive than the main path.
2. **Verify before reading.** Nothing acts on claims from an unverified JWT. Exactly one function
   may look inside an unverified token, and it returns only `kid` and `alg`.
3. **The token never chooses its own trust.** Keys come from configuration. `none` and `HS*` are
   rejected and cannot be enabled.
4. **Tokens never reach logs, exceptions, `repr` or audit events.**
5. **Replacement only attenuates.** Scope only shrinks, assurance only falls.

…and five more. Every one has tests named for the attack they stop:
`test_rs256_public_key_used_as_hmac_secret_is_rejected`,
`test_alg_none_with_fake_signature_is_rejected`, `test_replacement_cannot_widen_scope`.

The list sounds obvious. Its value is that every review, every code change and every new feature
gets checked against the same short list, and "is this fallback more permissive than the main
path?" becomes a question you ask automatically.

## 2. Make the rules structural, not aspirational

Rules in a document drift. Rules the build enforces do not.

* **Dependency direction** is enforced by [import-linter](https://github.com/seddonym/import-linter):
  `pytrat.core` imports no web framework, no HTTP client and nothing from the agent profile. Only
  one module may import the JWT library. Production code may never import the test helpers that
  mint tokens. Twelve contracts run in CI.
* **"Verified" is a type.** `VerifiedToken` can only be constructed by the verifier, using a private
  seal object. A function that takes a `VerifiedToken` cannot be handed an unverified one, and mypy
  in strict mode checks every call site.
* **Token leakage is a test failure.** A pytest fixture, applied to every test, scans captured log
  records for anything shaped like a compact JWS and fails the test if it finds one. I checked it
  catches a deliberate leak before trusting it.
* **Errors are API.** Every rejection raises a `PyTraTError` carrying a stable `ReasonCode` enum.
  Tests assert the *specific* reason, not just "raises", so a check that starts failing for the
  wrong reason is caught.

## 3. Keep the core sans-IO

The protocol logic is pure functions over values: parse claims, verify a signature against a key
set, compare a request to the authorized context, plan a replacement. I/O lives in thin shells, so
the sync and async token clients share all their logic and differ only in how they send bytes.
Time comes from an injected `Clock`, never from `time.time()` inline.

This made the code easy to test without mocks. It also made the code easy to fuzz, which turned
out to matter more than I expected.

## 4. Python's `==` is not your friend

The core check in Transaction Tokens compares what a service is about to do with what the token
authorized. In Python:

```python
>>> True == 1, 1 == 1.0, {"a": 1} == {"a": True}
(True, True, True)
```

For an authorization check, every one of those is a vulnerability. PyTraT canonicalises both
sides and compares them with exact type equality, so `True != 1`, `1 != 1.0` and `"1" != 1`.
Floats are rejected for bound fields entirely: money is integer minor units.

## 5. The fuzzer found a binding bypass

I had property-based tests (Hypothesis) on every parser from early on. Later I added
coverage-guided fuzzing with Atheris, with 13 harnesses. Some of them check more than "doesn't
crash": the context-binding harness re-checks every *accepted* input with an independent, much
simpler comparison.

That oracle disagreed with the library within minutes.

The canonicaliser normalised object keys to Unicode NFC, which is reasonable: `"café"` can be
spelled with a precomposed `é` or with `e` plus a combining accent, and they should compare equal.
But it never checked whether two *different* keys in the same object became identical after
normalisation. So this request:

```python
{"beneficiary": {"café": "EVIL", "café": "B"}}   # two spellings of "café"
```

passed the check against an authorized `{"café": "B"}`, because normalisation collapsed the two
keys and kept the second. The application, reading the raw dictionary, saw `"EVIL"`. The check
and the code that acted on the request disagreed about what the request said, which is the
definition of a bypass.

The fix is to reject objects whose keys collide after normalisation. It came, like every bug fix
in the project, with a regression test that fails without it.

The same fuzzing campaign found six more bugs: `1e400` decoding to infinity and then failing at
signing time, deeply nested JSON raising `RecursionError` (a 500) from inside a remote JWKS
document, a `TypeError` on a malformed key, and error-handling paths that raised the wrong
exception type. None was dramatic on its own, but each was a place where an attacker controlled
which code path ran.

## 6. Get a second pair of eyes, twice

After the first complete version I ran an adversarial review whose only goal was to break the
authorization model. It found five real issues. The worst three:

* **Workload impersonation.** Workloads authenticated to services with a signed JWT, and the
  identity came from the token's `sub` claim. Any *trusted* workload could sign a token claiming to
  be any *other* trusted workload. Identity now comes from which key verified the signature.
* **Agent constraints skipped.** A route requiring "every agent in the chain has at least medium
  assurance" accepted a token with no agent context at all. Absence was treated as "no agents,
  nothing to check" instead of "can't prove the requirement, deny."
* **A replacement-limit race.** Concurrent replacement requests could each read the count before
  any of them wrote it. A per-transaction lock around count → sign → record fixed it, and the test
  that proves it patches the counter to yield, so the race is deterministic.

A second review of the later additions (a Redis replay store, OpenTelemetry export) found that
Redis eviction under memory pressure silently deletes replay records, so the store now has a
startup check that rejects any Redis configured to evict. It also found that older redis-py versions don't check TLS
hostnames by default, so verification is now forced on.

The pattern in all of these: the code did what I designed. The *design* had an assumption I never
wrote down.

## 7. Failure is a feature to test

Every dependency of an authorization decision fails sometimes: the token service, the key
endpoint, the agent registry, the audit sink, the replay store. For each one there is an
integration test that breaks it and asserts the outcome is *deny*, with the right reason code, and
that the decision is still audited.

Writing those tests changed the design twice. For example, if the audit sink throws while a request
is being *granted*, the grant is refused with 503: an authorization nobody recorded should not
happen. If it throws while a request is being *denied*, the denial keeps its original reason.

## 8. Measure, then claim

On my laptop, verifying an ES256 token takes about 65 µs and a four-field binding check about
3 µs. The whole FastAPI dependency adds roughly 200 µs per request in-process. The repository has
the benchmark code and a report with the machine, versions and method, because a performance
number without a way to reproduce it is marketing.

## How it was built

I used AI coding agents heavily for this project: to draft modules against a written plan, to
fuzz, and to run adversarial reviews. What made that work was the same discipline you would want
from a team: written invariants, strict types, a test for every rejection path, and nothing
counted as done until format, lint, mypy, import contracts and the full test suite all passed.
Both reviews and the fuzzer found real bugs in generated code, and that is exactly why they are
part of the process.

## Where it stands

About 14,000 lines across ten packages, around 1,900 tests, strict typing throughout, and two
specifications that are still drafts. PyTraT is pre-1.0 and has not had an external audit; the
repository includes a [brief for whoever does that audit](../security/audit.md).

If you build security-sensitive Python, I'd like to hear which of these practices you rely on, and
which ones you'd add.

*Next: [can an AI agent launder its trust?](agent-trust-laundering.md)*
