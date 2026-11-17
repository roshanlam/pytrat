from pytrat.core import ContextBinding, Derived


def normalise_iban(value: object) -> object:
    # A transform must be pure. Raising (TypeError, ValueError, ...) fails the binding closed.
    if not isinstance(value, str):
        raise TypeError("IBAN must be a string")
    return value.replace(" ", "").upper()


# Field paths bound identically on both sides, plus one explicit, audited transformation.
TRANSFER = ContextBinding.compile(
    [
        "amount_minor",
        "currency",
        Derived(
            request_path="iban",
            tctx_path="destination_account",
            transform=normalise_iban,
            name="iban-normalisation",  # recorded in the audit event's detail.transforms
        ),
    ]
)

# A mapping binds differently named fields: request `account_id` against `tctx.source_account`.
ACCOUNT = ContextBinding.compile({"account_id": "source_account"})
