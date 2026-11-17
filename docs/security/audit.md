# Security audit

!!! info "Coming with M9"
    An external, third-party security audit is part of milestone M9. Its scope and findings will be
    published here.

An independent adversarial review of v0.1 found five issues, all fixed with regression tests that
fail without the fix: workload impersonation via a self-asserted `sub`, agent constraints bypassed
by omitting `agentic_ctx`, agent forgery via `act` in requester-asserted subjects, a
replacement-limit race, and a 500 on bound form bodies. See P28–P30 in
[Protocol compatibility](../compatibility.md).
