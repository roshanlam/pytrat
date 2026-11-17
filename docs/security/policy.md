# Reporting vulnerabilities

--8<-- "SECURITY.md:3:11"

## Scope

See the [threat model](../threat-model.md) for what PyTraT defends against and what it assumes.
Reports showing that any *Tested in* mitigation can be bypassed are always in scope.

The security invariants every change must preserve (fail closed, verify before reading, the token
never chooses its own trust, no secrets in logs, replacement only attenuates, only the TTS signs,
`Txn-Token` header only, a Txn-Token is not authentication, strict comparison, `session_id` is a
correlation hint) are listed in the repository's `CLAUDE.md`. A change that weakens one of them is
treated as a vulnerability.
