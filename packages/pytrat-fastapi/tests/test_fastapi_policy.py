"""Policy resolution: inline, YAML by route template, YAML by policy_id, and their agreement."""

from typing import Annotated

import pytest
from fastapi import Depends, FastAPI

from _fastapi_testkit import BIND, TCTX, Kit, ledger_app, serve
from pytrat.core import ConfigurationError
from pytrat.fastapi import Transaction
from pytrat.policy import PolicySet, load_policy_text

POLICY = """
version: 1
trust_domain: payments.internal
resources:
  - name: ledger-transfer
    method: POST
    path: /internal/transfer
    allowed_scopes: [payments.transfer]
    allowed_callers: [payment-service]
    bind_context: [source_account, destination_account, amount_minor, currency]
  - name: account-read
    method: GET
    path: /internal/accounts/{account_id}
    allowed_scopes: [payments.read]
    bind_context: [account_id]
  - name: account-me
    method: GET
    path: /internal/accounts/me
    allowed_scopes: [payments.read]
  - name: health
    method: GET
    path: /internal/health
    require_transaction: false
    require_workload_identity: false
"""


@pytest.fixture
def policy() -> PolicySet:
    return load_policy_text(POLICY)


def accounts_app(kit: Kit, policy: PolicySet, *, with_me: bool = True, **requirement):
    pytrat = kit.pytrat(policy=policy)
    app = FastAPI()
    pytrat.install(app)
    dependency = pytrat.require_transaction(**requirement)

    if with_me:

        @app.get("/internal/accounts/me")
        async def me(txn: Annotated[Transaction, Depends(dependency)]) -> dict[str, str]:
            return {"policy": txn.policy_id}

    @app.get("/internal/accounts/{account_id}")
    async def account(
        account_id: str, txn: Annotated[Transaction, Depends(dependency)]
    ) -> dict[str, str]:
        return {"policy": txn.policy_id}

    return pytrat, app


async def test_yaml_policy_is_resolved_by_route_template(kit: Kit, policy: PolicySet) -> None:
    pytrat, app = accounts_app(kit, policy)
    read = {"scope": "payments.read"}
    async with serve(app, pytrat) as client:
        own = await client.get(
            "/internal/accounts/acct-1", headers=kit.headers(tctx={"account_id": "acct-1"}, **read)
        )
        other = await client.get(
            "/internal/accounts/acct-2", headers=kit.headers(tctx={"account_id": "acct-1"}, **read)
        )
        me = await client.get("/internal/accounts/me", headers=kit.headers(**read))
    assert own.json() == {"policy": "account-read"}
    assert other.json()["reason_code"] == "TRANSACTION_CONTEXT_MISMATCH"
    assert me.json() == {"policy": "account-me"}


async def test_yaml_route_shadowed_by_a_broader_route_is_refused(kit, policy) -> None:
    pytrat, app = accounts_app(kit, policy, with_me=False)
    with pytest.raises(ConfigurationError, match="/internal/accounts/me overlaps"):
        pytrat.prepare(app)


async def test_route_without_inline_args_or_yaml_is_refused(kit: Kit, policy) -> None:
    pytrat = kit.pytrat()
    app = FastAPI()
    dependency = pytrat.require_transaction()

    @app.get("/internal/x")
    async def handler(txn: Annotated[Transaction, Depends(dependency)]) -> None: ...

    with pytest.raises(ConfigurationError, match="no YAML policy"):
        pytrat.prepare(app)
    with_yaml = kit.pytrat(policy=policy)
    app2 = FastAPI()

    @app2.get("/internal/x")
    async def handler2(
        txn: Annotated[Transaction, Depends(with_yaml.require_transaction())],
    ) -> None: ...

    with pytest.raises(ConfigurationError, match="no YAML policy"):
        with_yaml.prepare(app2)


async def test_inline_and_yaml_that_agree_use_the_yaml_policy(kit: Kit, policy) -> None:
    pytrat = kit.pytrat(policy=policy)
    app, _ = ledger_app(pytrat, bind_fields=list(reversed(BIND)))
    async with serve(app, pytrat) as client:
        response = await client.post("/internal/transfer", json=TCTX, headers=kit.headers())
    assert response.status_code == 200
    assert kit.sink.events[0].policy_id == "ledger-transfer"


@pytest.mark.parametrize(
    "requirement",
    [
        {"allowed_callers": ["payment-service", "reporting-service"]},
        {"bind_fields": ["amount_minor", "currency"]},
        {"scope": "payments.admin"},
        {"policy_id": "other-name"},
        {"require_workload_identity": False, "allowed_callers": None},
    ],
    ids=["callers", "binding", "scope", "name", "workload"],
)
def test_inline_and_yaml_disagreement_is_refused_at_startup(kit, policy, requirement) -> None:
    pytrat = kit.pytrat(policy=policy)
    app, _ = ledger_app(pytrat, **requirement)
    with pytest.raises(ConfigurationError, match="disagree"):
        pytrat.prepare(app)


async def test_policy_id_selects_a_yaml_policy(kit: Kit, policy) -> None:
    pytrat = kit.pytrat(policy=policy)
    app = FastAPI()
    dependency = pytrat.require_transaction(policy_id="account-me")

    @app.get("/internal/whoami")
    async def whoami(txn: Annotated[Transaction, Depends(dependency)]) -> dict[str, str]:
        return {"policy": txn.policy_id}

    async with serve(app, pytrat) as client:
        response = await client.get("/internal/whoami", headers=kit.headers(scope="payments.read"))
    assert response.json() == {"policy": "account-me"}


@pytest.mark.parametrize(
    ("policy_id", "use_yaml", "error"),
    [
        ("no-such-policy", True, "no YAML policy named"),
        ("no-such-policy", False, "no YAML policy named"),
        ("account-me", True, "differs from the YAML policy"),
    ],
)
def test_bad_policy_id_is_refused(kit, policy, policy_id, use_yaml, error) -> None:
    pytrat = kit.pytrat(policy=policy if use_yaml else None)
    app = FastAPI()
    dependency = pytrat.require_transaction(policy_id=policy_id)

    @app.post("/internal/transfer")
    async def transfer(txn: Annotated[Transaction, Depends(dependency)]) -> None: ...

    with pytest.raises(ConfigurationError, match=error):
        pytrat.prepare(app)


def test_yaml_policy_without_transaction_cannot_back_require_transaction(kit, policy) -> None:
    pytrat = kit.pytrat(policy=policy)
    app = FastAPI()
    dependency = pytrat.require_transaction()

    @app.get("/internal/health")
    async def health(txn: Annotated[Transaction, Depends(dependency)]) -> None: ...

    with pytest.raises(ConfigurationError, match="does not require a transaction"):
        pytrat.prepare(app)


@pytest.mark.parametrize(
    ("arguments", "error"),
    [
        ({"bind_fields": ["amount_minor"]}, "require scope or scopes"),
        ({"scope": "a", "scopes": ["b"]}, "not both"),
        ({"scopes": "a b"}, "not a single string"),
        ({"scope": "payments.transfer", "single_use": True}, "replay store"),
    ],
)
def test_invalid_inline_arguments_fail_at_declaration(kit: Kit, arguments, error) -> None:
    with pytest.raises(ConfigurationError, match=error):
        kit.pytrat().require_transaction(**arguments)


async def test_routes_yaml_cannot_express_use_inline_policies(kit: Kit, policy) -> None:
    pytrat = kit.pytrat(policy=policy)
    app = FastAPI()
    pytrat.install(app)
    dependency = pytrat.require_transaction(
        scopes=["payments.read"], require_workload_identity=False
    )

    @app.get("/internal/files/{name}.json")
    async def file(name: str, txn: Annotated[Transaction, Depends(dependency)]) -> dict:
        return {"policy": txn.policy_id}

    @app.get("/internal/blobs/{rest:path}")
    async def blob(rest: str, txn: Annotated[Transaction, Depends(dependency)]) -> dict:
        return {"policy": txn.policy_id}

    async with serve(app, pytrat) as client:
        file_response = await client.get(
            "/internal/files/a.json", headers=kit.headers(scope="payments.read", caller=None)
        )
        blob_response = await client.get(
            "/internal/blobs/a/b", headers=kit.headers(scope="payments.read", caller=None)
        )
    assert file_response.json() == {"policy": "GET /internal/files/{name}.json"}
    assert blob_response.json() == {"policy": "GET /internal/blobs/{rest}"}


def test_dependency_repr_names_its_mode(kit: Kit) -> None:
    pytrat = kit.pytrat()
    assert "inline" in repr(pytrat.require_transaction(scope="a"))
    assert "policy_id" in repr(pytrat.require_transaction(policy_id="x"))
    assert "route" in repr(pytrat.require_transaction())
