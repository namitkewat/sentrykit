"""Ambient context: who is acting, and whether that survives an ``await`` or a thread hop."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest

from sentrykit.cedar import EntityRef
from sentrykit.constraints import ArgumentConstraint, ConstraintSet
from sentrykit.context import (
    Invocation,
    Principal,
    bind_context,
    clear_context,
    current_environment,
    current_principal,
    establish,
    principal_context,
    require_principal,
)
from sentrykit.envelope import AuthzEnvelope, last_envelope, set_last_envelope
from sentrykit.errors import NoContext

SEARCH = EntityRef("Action", "tool.search_orders")


# --- the principal model --------------------------------------------------------------


@pytest.mark.unit
def test_a_principal_renders_as_a_cedar_entity_reference() -> None:
    principal = Principal(id="alice")

    assert principal.uid == EntityRef("User", "alice")


@pytest.mark.unit
def test_a_principal_type_can_be_something_other_than_user() -> None:
    principal = Principal(id="batch-7", type="Service")

    assert principal.uid == EntityRef("Service", "batch-7")


@pytest.mark.unit
def test_roles_and_explicit_parents_are_both_parent_edges() -> None:
    principal = Principal(
        id="alice",
        roles=("support", "auditor"),
        parents=(EntityRef("Team", "emea"),),
    )

    parents = principal.all_parents()

    assert EntityRef("Role", "support") in parents
    assert EntityRef("Role", "auditor") in parents
    assert EntityRef("Team", "emea") in parents


@pytest.mark.unit
def test_a_principal_with_no_edges_has_no_parents() -> None:
    assert Principal(id="alice").all_parents() == ()


@pytest.mark.unit
def test_constraints_for_returns_an_empty_set_when_nothing_applies() -> None:
    principal = Principal(id="alice")

    assert not principal.constraints_for(SEARCH)


@pytest.mark.unit
def test_an_action_specific_constraint_refines_the_wildcard_baseline() -> None:
    principal = Principal(
        id="casey",
        constraints={
            "*": ConstraintSet(
                arguments={
                    "limit": ArgumentConstraint(maximum=5),
                    "tenant": ArgumentConstraint(allow=("acme",)),
                }
            ),
            "tool.search_orders": ConstraintSet(
                arguments={"limit": ArgumentConstraint(allow=(1, 2, 3))}
            ),
        },
    )

    resolved = principal.constraints_for(SEARCH)

    assert resolved.arguments["limit"].allow == (1, 2, 3)
    assert resolved.arguments["limit"].maximum is None
    assert resolved.arguments["tenant"].allow == ("acme",)


@pytest.mark.unit
def test_the_full_uid_key_wins_over_the_bare_action_id() -> None:
    principal = Principal(
        id="casey",
        constraints={
            "tool.search_orders": ConstraintSet(arguments={"limit": ArgumentConstraint(maximum=5)}),
            'Action::"tool.search_orders"': ConstraintSet(
                arguments={"limit": ArgumentConstraint(maximum=9)}
            ),
        },
    )

    assert principal.constraints_for(SEARCH).arguments["limit"].maximum == 9


# --- the normalized invocation --------------------------------------------------------


@pytest.mark.unit
def test_an_invocation_channel_defaults_to_internal() -> None:
    invocation = Invocation(
        id="inv-1",
        principal=Principal(id="alice"),
        action=SEARCH,
        resource=EntityRef("Tool", "orders"),
    )

    assert invocation.channel == "internal"
    assert invocation.now is None


@pytest.mark.unit
def test_an_invocation_reads_channel_and_now_from_its_environment() -> None:
    moment = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
    invocation = Invocation(
        id="inv-1",
        principal=Principal(id="alice"),
        action=SEARCH,
        resource=EntityRef("Tool", "orders"),
        environment={"channel": "agent", "now": moment},
    )

    assert invocation.channel == "agent"
    assert invocation.now == moment


# --- establishing and unwinding -------------------------------------------------------


@pytest.mark.unit
def test_no_principal_is_ambient_before_anything_is_established() -> None:
    assert current_principal() is None
    assert dict(current_environment()) == {}


@pytest.mark.unit
def test_an_established_principal_is_ambient_inside_the_block() -> None:
    alice = Principal(id="alice", roles=("support",))

    with establish(alice, channel="agent", request_id="r-1"):
        assert current_principal() == alice
        assert current_environment()["channel"] == "agent"
        assert current_environment()["request_id"] == "r-1"

    assert current_principal() is None


@pytest.mark.unit
def test_the_scope_unwinds_even_when_the_block_raises() -> None:
    with pytest.raises(RuntimeError), establish(Principal(id="alice")):
        raise RuntimeError("boom")

    assert current_principal() is None


@pytest.mark.unit
def test_a_scope_handle_can_be_reset_without_an_enclosing_block() -> None:
    scope = establish(Principal(id="alice"))
    assert current_principal() is not None

    scope.reset()

    assert current_principal() is None


@pytest.mark.unit
def test_resetting_a_scope_twice_is_harmless() -> None:
    scope = establish(Principal(id="alice"))
    scope.reset()
    scope.reset()

    assert current_principal() is None


@pytest.mark.unit
def test_a_nested_establishment_restores_the_outer_principal() -> None:
    outer = Principal(id="alice")
    inner = Principal(id="bob")

    with establish(outer, channel="http"):
        with establish(inner, channel="agent"):
            assert current_principal() == inner
            assert current_environment()["channel"] == "agent"
        assert current_principal() == outer
        assert current_environment()["channel"] == "http"


@pytest.mark.unit
def test_the_generator_form_establishes_the_same_context() -> None:
    alice = Principal(id="alice")

    with principal_context(alice, channel="internal"):
        assert current_principal() == alice

    assert current_principal() is None


@pytest.mark.unit
def test_clearing_the_context_drops_the_principal_and_the_environment() -> None:
    scope = establish(Principal(id="alice"), channel="http")

    clear_context()

    assert current_principal() is None
    assert dict(current_environment()) == {}
    scope.reset()


@pytest.mark.unit
def test_require_principal_returns_the_ambient_one() -> None:
    alice = Principal(id="alice")

    with establish(alice):
        assert require_principal("tool.search_orders") == alice


@pytest.mark.unit
def test_require_principal_refuses_when_nothing_is_established() -> None:
    with pytest.raises(NoContext) as caught:
        require_principal("tool.search_orders")

    assert caught.value.action == "tool.search_orders"


# --- propagation ----------------------------------------------------------------------


@pytest.mark.unit
async def test_an_established_principal_survives_an_await() -> None:
    alice = Principal(id="alice", roles=("support",))

    async def inner() -> Principal | None:
        await asyncio.sleep(0)
        return current_principal()

    with establish(alice, channel="agent"):
        seen = await inner()

    assert seen == alice


@pytest.mark.unit
async def test_concurrent_tasks_each_see_the_principal_they_were_started_under() -> None:
    async def read() -> str | None:
        await asyncio.sleep(0)
        principal = current_principal()
        return None if principal is None else principal.id

    with establish(Principal(id="alice")):
        alice_task = asyncio.create_task(read())
    with establish(Principal(id="bob")):
        bob_task = asyncio.create_task(read())

    assert await alice_task == "alice"
    assert await bob_task == "bob"


@pytest.mark.unit
async def test_an_established_principal_survives_asyncio_to_thread() -> None:
    alice = Principal(id="alice")

    with establish(alice):
        seen = await asyncio.to_thread(current_principal)

    assert seen == alice


@pytest.mark.unit
def test_bind_context_carries_the_principal_into_a_worker_thread() -> None:
    alice = Principal(id="alice", roles=("support",))

    def worker(action: str) -> Principal:
        return require_principal(action)

    with establish(alice, channel="internal"), ThreadPoolExecutor(max_workers=1) as pool:
        seen = pool.submit(bind_context(worker, "tool.search_orders")).result()

    assert seen == alice


@pytest.mark.unit
def test_bind_context_carries_the_environment_too() -> None:
    with (
        establish(Principal(id="alice"), channel="agent"),
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        seen = pool.submit(bind_context(lambda: dict(current_environment()))).result()

    assert seen["channel"] == "agent"


@pytest.mark.unit
def test_a_bare_thread_pool_submit_loses_the_principal_and_fails_closed() -> None:
    def worker() -> Principal:
        return require_principal("tool.search_orders")

    with establish(Principal(id="alice")), ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(worker)

        with pytest.raises(NoContext):
            future.result()


@pytest.mark.unit
def test_bind_context_passes_arguments_through() -> None:
    def add(left: int, right: int = 0) -> int:
        return left + right

    with establish(Principal(id="alice")):
        thunk = bind_context(add, 2, right=3)

    assert thunk() == 5


@pytest.mark.unit
def test_clearing_the_context_also_drops_the_last_decision_envelope() -> None:
    """A reused worker context must not be able to report the previous unit's decision."""
    set_last_envelope(AuthzEnvelope(decision="allow", action='Action::"tool.ping"'))
    assert last_envelope() is not None

    clear_context()

    assert last_envelope() is None
