# agent-profile-03 reconciliation notes

Source: `draft-araut-oauth-transaction-tokens-for-agents-03` (October 2026, expires 4 May 2027),
plain-text rendering from `https://www.ietf.org/archive/id/`, read verbatim for §3.2, §3.3, §3.5,
§3.6, §3.7, §4.2 (incl. §4.2.3), §5 and §6/§7. Base draft cross-checked:
`draft-ietf-oauth-transaction-tokens-11` §9.2 and §13.15.

Short quotes are verbatim; everything else is paraphrase. "Implemented in" names the
`pytrat.agents` module. Ambiguities are marked **AMBIGUOUS** with the PyTraT choice.

## Rules implemented

| § | Rule (quote / paraphrase) | Implemented in |
|---|---|---|
| 3.2.1 step 7 | act copied "as-is without modification" | `replacement.plan_agent_replacement` carries `act` |
| 3.2.1 step 8, 3.6.1 | If `client_id` resolves to a registered agent, populate `agentic_ctx` | `identity.resolve_agent`, `replacement.initial_agentic_ctx` |
| 3.2.2 step 8 | Client Credentials: "the Txn-Token MUST NOT contain an act claim" | `identity.agent_mode` (deny if `act` present on client-credentials) |
| 3.2.2 note | autonomous: "`originator.id` ... is set from `client_id`" | `initial_agentic_ctx` (originator = resolved agent) |
| 3.3 | agents SHOULD replace before downstream calls; MUST when chain-integrity policies apply | `AgentLimits.require_replacement`, `ToolRuntime(require_replacement=True)` |
| 3.3.1 | `sub`, `txn`, `aud` MUST NOT be modified; `act` MUST NOT be modified | `plan_agent_replacement`, `assert_replacement_attenuates` |
| 3.3.1 | scope "can only be attenuated" | `plan_agent_replacement` → `REPLACEMENT_WIDENS_AUTHORIZATION` |
| 3.3.1 | `req_wl` "MUST be updated by appending ... using the comma (,) character" | `append_workload` |
| 3.3.1 | `proximate_agent.id` MUST be set to the new agent; `session_id` updated alongside | `next_agentic_ctx(..., session_id=)` |
| 3.3.1 | `originator.session_id` MUST NOT be modified | `next_agentic_ctx` (originator object reused) |
| 3.3.1 | `hop_count` MUST be incremented by one | `next_agentic_ctx` |
| 3.3.1, 4.2 | `min_assurance_level` = minimum of existing and new agent's level from the store | `next_agentic_ctx` (P6) |
| 3.3.2 | non-agent caller: `agentic_ctx` "MUST be carried forward without modification" | `next_agentic_ctx` returns `current` |
| 3.5.1 | `hop_count` "Set to 1 at initial issuance" | `initial_agentic_ctx` |
| 3.5.1 | `proximate_agent.id` at issuance: "via act.sub, Agent Attribute Store lookup, or client_id — in that priority order" | `resolve_agent` |
| 3.5.1, 3.5.4, 5.15 | `session_id` "MUST NOT use this field as an authorization criterion" | `policy.check_agent_requirements` has no session input; runtime never reads it |
| 3.5.1 | originator.id "MUST NOT be modified during replacement flows" | `next_agentic_ctx` |
| 3.5.1 | "Deployments MUST define their own ordered set and comparison function" | `AssuranceOrdering` (core), re-exported |
| 3.5.1, 5.10 | `attr_store_ref` informational; RS "MUST authenticate the Agent Attribute Store response independently" | stores are configured locally; `attr_store_ref` is never dereferenced |
| 3.5.4 | unknown `agentic_ctx` fields MUST be ignored | core model `extra="ignore"` |
| 3.6.1 step 4 | non-agent: "The TTS MUST NOT populate an agentic_ctx claim" | `resolve_agent` returns `None`; plan returns no context |
| 3.6.2 | posture/provenance "MUST NOT be sourced from agent self-assertion" | `AgentRecord` only produced by stores; no API accepts agent-asserted attributes |
| 3.6.2 | store MUST contain `assurance_level` if `min_assurance_level` is used | `AgentRecord.assurance_level` required, validated against the ordering at load |
| 3.7, 5.16 | token exchange "MUST NOT be exposed as a tool"; tokens "MUST NOT appear in the LLM's context window" | `ToolRuntime` (token never passed to tools, result guard, no credential tools in `tool_specs`) |
| 4.2.1 | "The `originator` object MUST NOT be modified" | `next_agentic_ctx` |
| 4.2.3, 5.12 | "If the `hop_count` exceeds a deployment-defined threshold, the replacement request MUST be rejected" | `next_agentic_ctx` → `AGENT_HOP_LIMIT_EXCEEDED` |
| 5.9 | "MUST NOT allow a replacement token to have a higher min_assurance_level than the incoming subject token" | `next_agentic_ctx`, `assert_replacement_attenuates` |
| 5.13 | on egress the TTS "MUST strip the attr_store_ref field and any other internal identifiers" | `strip_for_egress` |
| 5.14 | without mandatory replacement, `hop_count` is a lower bound | documented on `AgentRequirements.maximum_hops` |

## Reconciliation with plan.md §2.2 / P5 / P6

- **§2.2 is accurate** on structure, immutables, `hop_count = 1` at issuance, non-agent carry-forward,
  `session_id`, and the identification order. No correction needed to the tree.
- **P6 (assurance).** §3.3.1 and §3.5.1 say "*If* `min_assurance_level` is present, it MUST be
  recalculated"; §5.9 says it must never exceed the incoming value. PyTraT keeps P6:
  `new = min(existing-or-default_assurance, agent_level)`. **AMBIGUOUS**: the spec-literal reading
  leaves an absent value absent. Adding one is not forbidden, and with `default_assurance` equal to
  the lowest level (the default) the added value is the lowest level, so it can never satisfy a
  requirement that the original token failed. A non-lowest `default_assurance` is an explicit trust
  decision and is documented as such on `AgentLimits`.
- **Hop limit.** §4.2.3 says reject if `hop_count` "exceeds" the threshold, without saying whether
  the incoming or resulting count. **AMBIGUOUS**; PyTraT checks the *resulting* count (stricter), and
  also checks it on non-agent replacements (the rule is about "the replacement request", not only
  agent callers).
- **Egress stripping (§5.13)** was not in plan.md. Added `strip_for_egress`. **AMBIGUOUS**: "any
  other internal identifiers" is undefined; PyTraT strips `attr_store_ref` only (unknown members are
  already dropped by the core model). The TTS decides when a token egresses.
- **P5 (`req_wl`).** Confirmed: §3.3.1 says comma append "per the base specification", but -11 §9.2
  defines `req_wl` only as "A string value that identifies the workload that requested the
  Txn-Token" and §13.15 has no append rule. PyTraT appends when the resulting token carries
  `agentic_ctx`; otherwise (base rules, §3.3.2) `req_wl` is set to the requesting workload.
  **AMBIGUOUS**.

## Other ambiguities and PyTraT choices

1. **Identification order (§3.5.1 vs §3.6.1).** §3.5.1 lists `act.sub` → store → `client_id`;
   §3.6.1 describes only a `client_id` lookup. PyTraT: look up `act.sub` by agent id, then
   `client_id`. If `act.sub` is present but unregistered and `client_id` resolves to a *different*
   agent, deny with `AGENT_UNVERIFIED` (PyTraT profile): falling back would attribute the chain to
   a possibly higher-assurance agent than the actual actor.
2. **Requester identity on replacement.** The spec says the TTS identifies the requesting workload
   (§4.2.2 step 8: lookup by `client_id`). `act` in the subject Txn-Token names the *original*
   actor and must not be used to identify the replacement requester. The server must pass the
   authenticated requester's record, not `act`.
3. **Agent replaces a token with no `agentic_ctx`.** Not covered. Default: deny
   `AGENT_CONTEXT_MISSING` (`AgentLimits.require_replacement=True`). With
   `require_replacement=False` a new chain starts with the requesting agent as originator,
   `hop_count = 1`.
4. **Client Credentials with `act`.** §3.2.2 says "typically does not contain an act claim, and
   therefore the Txn-Token MUST NOT contain an act claim". If one is present anyway, PyTraT denies
   (`ISSUANCE_NOT_AUTHORIZED`) rather than silently dropping it.
5. **Resource-side requirements without `agentic_ctx`.** Not covered. PyTraT denies
   (`AGENT_CONTEXT_MISSING`) when an assurance, verified-agent or originator requirement is
   configured and the token has no `agentic_ctx`; a hop limit alone is vacuously satisfied.
6. **Unknown assurance strings in tokens.** Treated as lowest when computing a chain minimum, never
   satisfying a requirement (core `AssuranceOrdering`).
7. **`require_verified_agent`** checks `proximate_agent.id` in the store (§3.5.4 / §4.2.2 step 13
   use the proximate agent for posture lookups). Originator verification is left to
   `allowed_originators`, because external originators are often unregistered (§4.1).
8. **§6 and §7** are both titled references; no normative content beyond the reference list.
