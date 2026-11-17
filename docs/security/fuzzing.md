# Fuzzing

!!! info "Coming with M9"
    Coverage-guided fuzzing with Atheris is part of milestone M9 and is documented here when it
    lands.

Every untrusted-input parser (compact JWS and JOSE headers, JWT payloads, JWKS documents,
token-exchange forms and responses, YAML policies) already has property-based tests with
Hypothesis, run on every CI build.
