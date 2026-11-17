# Threat model

PyTraT supplies *trusted transaction context* to services that already authenticate their callers.
This document states what it defends against, what it assumes, and what it does not cover.

## Assets

1. The integrity of authorized transaction parameters (`tctx`): amount, accounts, resource ids.
2. The identity of the transaction principal (`sub`) and, under the agent profile, the agent chain.
3. TTS signing keys and workload credentials.
4. Audit records of issuance, replacement and authorization decisions.

## Trust assumptions

* The Transaction Token Service and its signing keys are trusted and uncompromised.
* Verifiers obtain trusted keys from configuration, not from tokens.
* Workloads authenticate each other independently of Txn-Tokens (mTLS, signed workload credentials,
  SPIFFE). **A Txn-Token is not an authentication credential** (txn-tokens-11 §13.12).
* Clocks are synchronised within the configured leeway (default 5 s).
* The Agent Attribute Store is managed by authenticated infrastructure, never by an agent or model.

## Threats and mitigations

| Threat | Mitigation | Tested in |
|---|---|---|
| Forged token, `alg: none`, stripped signature | Allowlisted asymmetric algorithms only; signature verified before any claim is read | `tests/security/test_token_attacks.py` |
| Key confusion (HS256 with an RSA/EC public key) | `HS*` cannot be enabled; algorithms bound to key type | same |
| Token chooses its own key (`jwk`, `jku`, `x5u`, `x5c`) | Those headers are rejected; keys come only from trusted configuration | same |
| Token from another Trust Domain | `aud` must equal the verifier's Trust Domain; array `aud` rejected | same |
| Expired or long-lived token reuse | `exp` enforced with bounded leeway; maximum lifetime | same |
| Compromised intermediary alters parameters | `tctx` binding with strict, typed comparison; floats rejected for amounts | `tests/integration/test_payment_demo.py`, `tests/security/` |
| Type-juggling (`"10000"`, `10000.0`, `true`) | Exact type equality after canonicalisation | `packages/pytrat-core/tests/test_binding.py` |
| Parser differentials (duplicate JSON keys) | Duplicate members rejected everywhere | core tests |
| Replay within a token's lifetime | Opt-in single-use per operation; short lifetimes | policy tests |
| Unauthorised caller reuses a captured token | Independent workload authentication + `allowed_callers` | fastapi tests |
| One trusted workload impersonates another | Workload identity is the owner of the verifying key, never a claim | `packages/pytrat-core/tests/test_workload.py` |
| Workload forges an agent identity via a self-asserted subject | `act` refused in self-signed/unsigned subjects | server `test_subjects.py` |
| Agent constraints bypassed with a plain token | Assurance/originator constraints deny tokens without `agentic_ctx` | policy `test_evaluate.py` |
| Concurrent replacements exceed the replacement limit | Per-`txn` lock around count → sign → record | server `test_replacement.py` |
| Forgotten route protection | ASGI middleware fails closed under a protected prefix; startup route-coverage check | fastapi tests |
| Token sent to an attacker host | Outbound allowlist checked before connecting; redirects never followed | client tests |
| Token leaks into logs | Tokens wrapped in `SecretToken`; audit carries only digests; tests scan logs for JWS shapes | all suites |
| Scope widening on replacement | Requested scope must be a subset; immutables copied, not requested | server and agents tests |
| Assurance laundering through a trusted agent | Chain assurance = minimum across all agents | agents property tests |
| Unbounded delegation chains | `max_hops` enforced by the TTS and by resources | agents tests |
| Prompt injection asks the model to mint or exfiltrate tokens | The model never sees tokens or exchange functions; tool results are scanned for JWS shapes | agents runtime tests |

## Out of scope

* A compromised TTS, compromised signing keys, or a compromised host running the verifier.
* Isolation between a model and the agent runtime **in the same process**. The in-process
  `protected_tool` decorator enforces policy but is not a sandbox; run the runtime in a separate
  process or behind a network boundary when the model can execute code.
* Denial of service beyond bounded parsing and rate limits on the reference TTS.
* Confidentiality of `tctx`/`rctx` from workloads inside the Trust Domain: tokens are signed, not
  encrypted. Keep personal data out of tokens.
