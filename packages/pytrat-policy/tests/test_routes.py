from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pytrat.core import AuthorizationError, ConfigurationError, ReasonCode
from pytrat.policy import CompiledPolicy, PolicySet, RouteTemplate


def policy(policy_id: str) -> CompiledPolicy:
    return CompiledPolicy.build(policy_id=policy_id, allowed_scopes="s")


def not_found(policy_set: PolicySet, method: str, path: str) -> None:
    with pytest.raises(AuthorizationError) as info:
        policy_set.for_route(method, path)
    assert info.value.reason is ReasonCode.POLICY_NOT_FOUND


ROUTES = PolicySet.build(
    [
        ("GET", "/", policy("root")),
        ("POST", "/internal/transfer", policy("transfer")),
        ("GET", "/accounts/{account_id}", policy("account")),
        ("GET", "/accounts/me", policy("me")),
        ("GET", "/accounts/{account_id}/postings/{posting_id}", policy("posting")),
    ],
    trust_domain="t",
)


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    [
        ("GET", "/", "root"),
        ("POST", "/internal/transfer", "transfer"),
        ("GET", "/accounts/acc-1", "account"),
        ("GET", "/accounts/me", "me"),
        ("GET", "/accounts/a/postings/p", "posting"),
        ("GET", "/accounts/{account_id}", "account"),
    ],
)
def test_route_lookup(method: str, path: str, expected: str) -> None:
    assert ROUTES.for_route(method, path).policy_id == expected


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/internal/transfer"),
        ("post", "/internal/transfer"),
        ("POST", "/internal/transfer/"),
        ("POST", "/internal/transfer?x=1"),
        ("GET", "/accounts"),
        ("GET", "/accounts/"),
        ("GET", "/accounts//postings/p"),
        ("GET", "/accounts/a/b"),
        ("GET", "accounts/a"),
        ("GET", ""),
        ("DELETE", "/accounts/a"),
    ],
)
def test_unmatched_route_is_denied_policy_not_found(method: str, path: str) -> None:
    not_found(ROUTES, method, path)


def test_exact_path_wins_over_template_regardless_of_order() -> None:
    reversed_set = PolicySet.build(
        [("GET", "/a/me", policy("me")), ("GET", "/a/{id}", policy("id"))]
    )
    assert reversed_set.for_route("GET", "/a/me").policy_id == "me"
    assert reversed_set.for_route("GET", "/a/you").policy_id == "id"


def test_templates_with_different_methods_do_not_overlap() -> None:
    routes = PolicySet.build([("GET", "/a/{x}", policy("get")), ("PUT", "/a/{y}", policy("put"))])
    assert routes.for_route("PUT", "/a/1").policy_id == "put"


def test_identical_templates_with_different_names_are_rejected() -> None:
    with pytest.raises(ConfigurationError, match="overlaps"):
        PolicySet.build([("GET", "/a/{x}", policy("one")), ("GET", "/a/{y}", policy("two"))])


def test_route_errors_carry_index() -> None:
    with pytest.raises(ConfigurationError) as info:
        PolicySet.build([("GET", "/a", policy("one")), ("GET", "bad", policy("two"))])
    assert info.value.index == 1  # type: ignore[attr-defined]


def test_route_template_properties() -> None:
    route = RouteTemplate.parse("GET", "/a/{id}")
    assert route.segments == ("a", None)
    assert not route.is_exact
    assert RouteTemplate.parse("GET", "/a/b").is_exact
    assert RouteTemplate.parse("GET", "/").segments == ()


# ------------------------------------------------------------------ properties

segment = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-._~", min_size=1, max_size=8)
paths = st.lists(segment, min_size=1, max_size=6)


@given(segments=paths, mask=st.lists(st.booleans(), min_size=6, max_size=6))
def test_template_matches_every_instantiation(segments: list[str], mask: list[bool]) -> None:
    template = "/" + "/".join(f"{{p{i}}}" if mask[i] else part for i, part in enumerate(segments))
    routes = PolicySet.build([("GET", template, policy("p"))])
    assert routes.for_route("GET", "/" + "/".join(segments)).policy_id == "p"


@given(segments=paths, extra=paths)
def test_template_never_matches_a_different_segment_count(
    segments: list[str], extra: list[str]
) -> None:
    template = "/" + "/".join(f"{{p{i}}}" for i in range(len(segments)))
    routes = PolicySet.build([("GET", template, policy("p"))])
    not_found(routes, "GET", "/" + "/".join([*segments, *extra]))


@given(segments=paths, index=st.integers(min_value=0, max_value=5), other=segment)
def test_template_literal_segments_must_match_exactly(
    segments: list[str], index: int, other: str
) -> None:
    index %= len(segments)
    if other == segments[index]:
        other += "x"
    routes = PolicySet.build([("GET", "/" + "/".join(segments), policy("p"))])
    changed = [*segments]
    changed[index] = other
    not_found(routes, "GET", "/" + "/".join(changed))


@given(segments=paths, index=st.integers(min_value=0, max_value=5))
def test_parameters_never_match_empty_or_multi_segment_values(
    segments: list[str], index: int
) -> None:
    index %= len(segments)
    template_parts = [*segments]
    template_parts[index] = "{param}"
    routes = PolicySet.build([("GET", "/" + "/".join(template_parts), policy("p"))])
    for replacement in ("", "x/y"):
        concrete = [*segments]
        concrete[index] = replacement
        not_found(routes, "GET", "/" + "/".join(concrete))
