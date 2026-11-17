# pytrat-policy

Policy-as-code for PyTraT (OAuth Transaction Tokens): a strict YAML policy
model, its compiler, and `TransactionEnforcer`, the framework-agnostic per-request pipeline
(one `Txn-Token` → verify → authenticate the caller → evaluate policy → one audit event) that the
FastAPI and Django integrations share.

```bash
pip install pytrat-policy
```

## A policy

```yaml
version: 1
trust_domain: payments.internal
resources:
  - name: ledger-entry
    method: POST
    path: /internal/ledger/entries
    allowed_scopes: [payments.transfer]
    allowed_callers: [payment-service]
    bind_context: [source_account, destination_account, amount_minor, currency]
```

```python
from pytrat.policy import load_policy

policy_set = load_policy("policy.yaml", expected_trust_domain="payments.internal")
policy = policy_set.for_route("POST", "/internal/ledger/entries")  # unknown routes: deny
```

Unknown keys, duplicate keys, wrong types and settings that would be silently ignored are all
rejected at load time. Routes without a policy are denied (`POLICY_NOT_FOUND`). Checks run in a
fixed order (scope, caller, binding, agent constraints, replay), so audit reasons are stable.

## Documentation

PyTraT documentation: *Policies* (full schema reference) and the `pytrat.policy` API reference
(sources in `docs/` of the repository).

Apache-2.0.
