"""Context propagation of the bound Transaction Token."""

from __future__ import annotations

import asyncio

import anyio.to_thread
import pytest

from pytrat.client import bind_transaction, current_transaction, optional_transaction
from pytrat.core import ReasonCode, TokenError


def test_current_transaction_without_binding_is_token_missing() -> None:
    assert optional_transaction() is None
    with pytest.raises(TokenError) as excinfo:
        current_transaction()
    assert excinfo.value.reason is ReasonCode.TOKEN_MISSING


def test_binding_is_scoped_nested_and_restored(factory, verifier) -> None:
    outer = verifier.verify(factory.mint())
    inner = verifier.verify(factory.mint())
    with bind_transaction(outer) as bound:
        assert bound is outer
        assert current_transaction() is outer
        with bind_transaction(inner):
            assert current_transaction() is inner
        assert current_transaction() is outer
    assert optional_transaction() is None


def test_binding_is_reset_when_the_block_raises(current) -> None:
    with pytest.raises(RuntimeError), bind_transaction(current):
        raise RuntimeError
    assert optional_transaction() is None


def test_unverified_value_cannot_be_bound() -> None:
    with pytest.raises(TypeError), bind_transaction("raw.jwt.value"):  # type: ignore[arg-type]
        pass


async def test_binding_in_one_task_does_not_leak_into_another(factory, verifier) -> None:
    token = verifier.verify(factory.mint())
    bound = asyncio.Event()
    release = asyncio.Event()

    async def binder() -> None:
        with bind_transaction(token):
            bound.set()
            await release.wait()

    async def observer() -> object:
        await bound.wait()
        try:
            return optional_transaction()
        finally:
            release.set()

    _, seen = await asyncio.gather(binder(), observer())
    assert seen is None


async def test_child_task_inherits_a_copy_of_the_binding(current) -> None:
    async def child() -> object:
        return current_transaction()

    with bind_transaction(current):
        task = asyncio.create_task(child())
    # The task captured the context at creation, even though the binding has since been reset.
    assert await task is current
    assert optional_transaction() is None


async def test_binding_crosses_anyio_to_thread(current) -> None:
    with bind_transaction(current):
        seen = await anyio.to_thread.run_sync(current_transaction)
    assert seen is current


async def test_binding_crosses_asyncio_to_thread(current) -> None:
    with bind_transaction(current):
        seen = await asyncio.to_thread(current_transaction)
    assert seen is current
