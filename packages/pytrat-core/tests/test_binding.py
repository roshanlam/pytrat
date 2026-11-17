from __future__ import annotations

from enum import IntEnum, StrEnum
from types import MappingProxyType

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pytrat.core import (
    AuthorizationError,
    ConfigurationError,
    ContextBinding,
    Derived,
    ReasonCode,
    TokenError,
)
from pytrat.core.binding import UnbindableValueError, canonical, strict_equal

TCTX = MappingProxyType(
    {
        "source_account": "account-A",
        "destination_account": "account-B",
        "amount_minor": 10000,
        "currency": "USD",
        "flags": ("a", "b"),
        "beneficiary": MappingProxyType({"name": "Bob", "country": "DE"}),
        "approved": True,
    }
)
REQUEST = {
    "source_account": "account-A",
    "destination_account": "account-B",
    "amount_minor": 10000,
    "currency": "USD",
}
FIELDS = ["source_account", "destination_account", "amount_minor", "currency"]


def denial(binding: ContextBinding, tctx, request) -> ReasonCode:
    with pytest.raises(AuthorizationError) as excinfo:
        binding.check(tctx, request)
    return excinfo.value.reason


class TestMatching:
    def test_identical_values_pass(self) -> None:
        result = ContextBinding.compile(FIELDS).check(TCTX, REQUEST)
        assert result.checked == tuple(FIELDS)
        assert result.transforms == ()

    def test_extra_request_fields_are_not_bound(self) -> None:
        ContextBinding.compile(FIELDS).check(TCTX, {**REQUEST, "memo": "anything"})

    def test_empty_binding_passes_without_tctx(self) -> None:
        assert ContextBinding.compile([]).check(None, {}).checked == ()

    def test_nested_paths_and_mapping_spec(self) -> None:
        binding = ContextBinding.compile(
            {"to.country": "beneficiary.country", "amount": "amount_minor"}
        )
        binding.check(TCTX, {"to": {"country": "DE"}, "amount": 10000})
        assert binding.fields == ("beneficiary.country", "amount_minor")

    def test_whole_objects_and_lists_compare_structurally(self) -> None:
        binding = ContextBinding.compile(["beneficiary", "flags"])
        binding.check(TCTX, {"beneficiary": {"country": "DE", "name": "Bob"}, "flags": ["a", "b"]})

    def test_unicode_is_nfc_normalised(self) -> None:
        tctx = {"name": "é"}  # é precomposed
        ContextBinding.compile(["name"]).check(tctx, {"name": "é"})  # e + combining accent

    def test_enum_subclasses_compare_as_base_type(self) -> None:
        class Currency(StrEnum):
            USD = "USD"

        class Amount(IntEnum):
            HUNDRED = 10000

        ContextBinding.compile(["currency", "amount_minor"]).check(
            TCTX, {"currency": Currency.USD, "amount_minor": Amount.HUNDRED}
        )

    def test_derived_value_is_recorded(self) -> None:
        to_minor = Derived("amount_major", "amount_minor", lambda v: v * 100, "major-to-minor")  # type: ignore[operator]
        result = ContextBinding.compile([to_minor]).check(TCTX, {"amount_major": 100})
        assert result.transforms == ("major-to-minor",)


class TestDenials:
    """The demo attack and its variants: a compromised intermediary alters bound parameters."""

    def test_tampered_amount_is_rejected(self) -> None:
        reason = denial(ContextBinding.compile(FIELDS), TCTX, {**REQUEST, "amount_minor": 900000})
        assert reason is ReasonCode.TRANSACTION_CONTEXT_MISMATCH

    @pytest.mark.parametrize(
        "value", ["10000", 10000.0, True, None, [10000], {"v": 10000}], ids=repr
    )
    def test_type_juggled_amount_is_rejected(self, value: object) -> None:
        reason = denial(ContextBinding.compile(["amount_minor"]), TCTX, {"amount_minor": value})
        assert reason is ReasonCode.TRANSACTION_CONTEXT_MISMATCH

    def test_bool_is_not_int_in_either_direction(self) -> None:
        reason = denial(ContextBinding.compile(["approved"]), TCTX, {"approved": 1})
        assert reason is ReasonCode.TRANSACTION_CONTEXT_MISMATCH

    def test_case_and_whitespace_are_significant(self) -> None:
        binding = ContextBinding.compile(["currency"])
        for value in ["usd", "USD ", " USD"]:
            assert (
                denial(binding, TCTX, {"currency": value})
                is ReasonCode.TRANSACTION_CONTEXT_MISMATCH
            )

    def test_missing_request_field(self) -> None:
        request = {k: v for k, v in REQUEST.items() if k != "currency"}
        assert (
            denial(ContextBinding.compile(FIELDS), TCTX, request)
            is ReasonCode.TRANSACTION_CONTEXT_MISMATCH
        )

    def test_missing_tctx_claim(self) -> None:
        assert (
            denial(ContextBinding.compile(FIELDS), None, REQUEST)
            is ReasonCode.TRANSACTION_CONTEXT_MISSING
        )

    def test_missing_tctx_field(self) -> None:
        binding = ContextBinding.compile(["fee_minor"])
        assert denial(binding, TCTX, {"fee_minor": 0}) is ReasonCode.TRANSACTION_CONTEXT_MISSING

    def test_nested_path_through_non_object(self) -> None:
        binding = ContextBinding.compile(["currency.code"])
        assert (
            denial(binding, TCTX, {"currency": {"code": "USD"}})
            is ReasonCode.TRANSACTION_CONTEXT_MISSING
        )

    def test_list_order_matters(self) -> None:
        binding = ContextBinding.compile(["flags"])
        assert (
            denial(binding, TCTX, {"flags": ["b", "a"]}) is ReasonCode.TRANSACTION_CONTEXT_MISMATCH
        )

    def test_extra_nested_key_is_a_mismatch(self) -> None:
        binding = ContextBinding.compile(["beneficiary"])
        request = {"beneficiary": {"name": "Bob", "country": "DE", "iban": "X"}}
        assert denial(binding, TCTX, request) is ReasonCode.TRANSACTION_CONTEXT_MISMATCH

    def test_unbindable_request_value(self) -> None:
        binding = ContextBinding.compile(["currency"])
        assert (
            denial(binding, TCTX, {"currency": b"USD"}) is ReasonCode.TRANSACTION_CONTEXT_MISMATCH
        )

    def test_float_in_tctx_is_an_invalid_claim(self) -> None:
        with pytest.raises(TokenError) as excinfo:
            ContextBinding.compile(["amount"]).check({"amount": 100.0}, {"amount": 100.0})
        assert excinfo.value.reason is ReasonCode.CLAIM_INVALID

    def test_failing_transform_fails_closed(self) -> None:
        bad = Derived("amount_major", "amount_minor", lambda v: v * 100, "major-to-minor")  # type: ignore[operator]
        binding = ContextBinding.compile([bad])
        assert (
            denial(binding, TCTX, {"amount_major": None}) is ReasonCode.TRANSACTION_CONTEXT_MISMATCH
        )

    def test_detail_names_path_but_never_values(self) -> None:
        with pytest.raises(AuthorizationError) as excinfo:
            ContextBinding.compile(FIELDS).check(
                TCTX, {**REQUEST, "destination_account": "attacker-acct"}
            )
        assert "destination_account" in excinfo.value.detail
        assert "attacker-acct" not in str(excinfo.value)
        assert "account-B" not in str(excinfo.value)


class TestCompile:
    @pytest.mark.parametrize("spec", [[""], ["a..b"], [".a"], {"a": ""}])
    def test_malformed_paths(self, spec) -> None:
        with pytest.raises(ConfigurationError):
            ContextBinding.compile(spec)

    def test_duplicate_target(self) -> None:
        with pytest.raises(ConfigurationError):
            ContextBinding.compile({"a": "amount", "b": "amount"})

    def test_unnamed_derived(self) -> None:
        with pytest.raises(ConfigurationError):
            ContextBinding.compile([Derived("a", "b", lambda v: v, "")])


json_scalars = st.none() | st.booleans() | st.integers() | st.text(max_size=8)
json_values = st.recursive(
    json_scalars,
    lambda children: (
        st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=4), children, max_size=3)
    ),
    max_leaves=10,
)


class TestProperties:
    @given(json_values)
    def test_canonical_value_equals_itself(self, value: object) -> None:
        assert strict_equal(canonical(value), canonical(value))

    @given(json_values, json_values)
    def test_strict_equal_implies_python_equal(self, left: object, right: object) -> None:
        if strict_equal(canonical(left), canonical(right)):
            assert canonical(left) == canonical(right)

    @given(st.integers())
    def test_int_never_equals_its_bool_or_str_form(self, value: int) -> None:
        assert not strict_equal(canonical(value), canonical(str(value)))
        assert not strict_equal(canonical(value), canonical(bool(value)))

    @given(st.floats(allow_nan=False))
    def test_floats_are_never_bindable(self, value: float) -> None:
        with pytest.raises(UnbindableValueError):
            canonical(value)
