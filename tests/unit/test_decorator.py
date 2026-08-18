"""``@protect``: the decorator's own behavior — principal resolution, overrides, wrapping."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import pytest

from sentrykit.cedar import EntityRef, PolicyEngine
from sentrykit.config import configure
from sentrykit.context import Principal, bind_context, establish
from sentrykit.decorator import is_protected, protect, protected_meta
from sentrykit.engine import Governor, derive_action, set_governor
from sentrykit.envelope import last_envelope
from sentrykit.errors import AuthzDenied, ConfigurationError, NoContext, NoValidArguments

SEARCH = 'Action::"tool.search_orders"'
ORDERS = 'Tool::"orders"'


def _plain(customer_id: str, limit: int = 10, region: str = "eu-west") -> dict[str, object]:
    """The unprotected original, so signature preservation is checkable."""
    return {"customer_id": customer_id, "limit": limit, "region": region}


def _guarded(governor: Governor | None = None) -> Callable[..., dict[str, object]]:
    return protect(action=SEARCH, resource=ORDERS, governor=governor)(_plain)


def _guarded_async() -> Callable[..., object]:
    @protect(action=SEARCH, resource=ORDERS)
    async def search_orders(customer_id: str, limit: int = 10) -> dict[str, object]:
        await asyncio.sleep(0)
        return {"customer_id": customer_id, "limit": limit}

    return search_orders


def _guarded_list() -> Callable[..., list[str]]:
    @protect(action=SEARCH, resource=ORDERS)
    def list_orders(customer_id: str) -> list[str]:
        return [f"order-for-{customer_id}"]

    return list_orders


# --- wrapping -------------------------------------------------------------------------


@pytest.mark.unit
def test_the_wrapper_keeps_the_original_signature_and_identity() -> None:
    guarded = _guarded()

    assert inspect.signature(guarded) == inspect.signature(_plain)
    assert guarded.__name__ == _plain.__name__
    assert guarded.__doc__ == _plain.__doc__


@pytest.mark.unit
def test_a_protected_callable_advertises_itself() -> None:
    guarded = _guarded()

    assert is_protected(guarded) is True
    assert is_protected(_plain) is False
    assert protected_meta(_plain) is None


@pytest.mark.unit
def test_the_recorded_metadata_describes_what_will_be_authorized() -> None:
    meta = protected_meta(_guarded())

    assert meta is not None
    assert meta.action == EntityRef("Action", "tool.search_orders")
    assert meta.resource == EntityRef("Tool", "orders")
    assert meta.spec.parameters == ("customer_id", "limit", "region")


@pytest.mark.unit
def test_bare_ids_are_read_as_an_action_and_a_resource() -> None:
    guarded = protect(action="tool.search_orders", resource="orders")(_plain)
    meta = protected_meta(guarded)

    assert meta is not None
    assert meta.action == EntityRef("Action", "tool.search_orders")
    assert meta.resource == EntityRef("Resource", "orders")


@pytest.mark.unit
def test_used_bare_the_action_is_derived_from_the_callable() -> None:
    guarded = protect(_plain)
    meta = protected_meta(guarded)

    assert meta is not None
    assert meta.action == derive_action(_plain)
    assert meta.resource is None


@pytest.mark.unit
def test_an_unparseable_action_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError):
        protect(action='Action::"unterminated')(_plain)


# --- resolving the principal ----------------------------------------------------------


@pytest.mark.unit
def test_an_entitled_ambient_principal_may_call(
    governor: Governor,
    entitled_principal: Principal,
) -> None:
    guarded = _guarded()

    with establish(entitled_principal, channel="internal"):
        result = guarded(customer_id="c-1")

    assert result["customer_id"] == "c-1"


@pytest.mark.unit
async def test_an_async_protected_callable_runs_end_to_end(
    governor: Governor,
    entitled_principal: Principal,
) -> None:
    guarded = _guarded_async()

    with establish(entitled_principal, channel="agent"):
        result = await guarded(customer_id="c-1")

    assert result["customer_id"] == "c-1"


@pytest.mark.unit
def test_an_unentitled_ambient_principal_is_refused(
    governor: Governor,
    unentitled_principal: Principal,
) -> None:
    guarded = _guarded()

    with establish(unentitled_principal), pytest.raises(AuthzDenied):
        guarded(customer_id="c-1")


@pytest.mark.unit
def test_no_ambient_principal_means_deny(governor: Governor) -> None:
    guarded = _guarded()

    with pytest.raises(NoContext):
        guarded(customer_id="c-1")


@pytest.mark.unit
def test_no_ambient_principal_still_means_deny_under_fail_mode_open(governor: Governor) -> None:
    configure(fail_mode="open")
    guarded = _guarded()

    with pytest.raises(NoContext):
        guarded(customer_id="c-1")


@pytest.mark.unit
async def test_an_async_call_with_no_principal_is_denied_too(governor: Governor) -> None:
    guarded = _guarded_async()

    with pytest.raises(NoContext):
        await guarded(customer_id="c-1")


@pytest.mark.unit
def test_an_explicit_as_beats_the_ambient_principal(
    governor: Governor,
    entitled_principal: Principal,
    unentitled_principal: Principal,
) -> None:
    guarded = _guarded()

    with establish(unentitled_principal):
        result = guarded(customer_id="c-1", _as=entitled_principal)

    assert result["customer_id"] == "c-1"


@pytest.mark.unit
def test_an_explicit_as_can_also_narrow_a_call_that_would_have_been_allowed(
    governor: Governor,
    entitled_principal: Principal,
    unentitled_principal: Principal,
) -> None:
    guarded = _guarded()

    with establish(entitled_principal), pytest.raises(AuthzDenied):
        guarded(customer_id="c-1", _as=unentitled_principal)


@pytest.mark.unit
def test_an_explicit_as_works_with_no_ambient_principal_at_all(
    governor: Governor,
    entitled_principal: Principal,
) -> None:
    guarded = _guarded()

    assert guarded(customer_id="c-1", _as=entitled_principal)["customer_id"] == "c-1"


@pytest.mark.unit
def test_the_override_keyword_never_reaches_the_callable(
    governor: Governor,
    entitled_principal: Principal,
) -> None:
    seen: dict[str, object] = {}

    @protect(action=SEARCH, resource=ORDERS)
    def record(customer_id: str) -> dict[str, object]:
        seen["customer_id"] = customer_id
        return dict(seen)

    record(customer_id="c-1", _as=entitled_principal)

    assert seen == {"customer_id": "c-1"}


@pytest.mark.unit
async def test_an_established_principal_reaches_a_protected_callable_across_an_await(
    governor: Governor,
    entitled_principal: Principal,
) -> None:
    guarded = _guarded_async()

    async def caller() -> dict[str, object]:
        await asyncio.sleep(0)
        return await guarded(customer_id="c-1")

    with establish(entitled_principal, channel="agent"):
        results = await asyncio.gather(caller(), caller())

    assert [item["customer_id"] for item in results] == ["c-1", "c-1"]


@pytest.mark.unit
def test_bind_context_carries_the_principal_into_a_protected_call_on_another_thread(
    governor: Governor,
    entitled_principal: Principal,
) -> None:
    guarded = _guarded()

    with establish(entitled_principal), ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(bind_context(guarded, customer_id="c-1")).result()

    assert result["customer_id"] == "c-1"


@pytest.mark.unit
def test_a_bare_offload_to_a_thread_fails_closed(
    governor: Governor,
    entitled_principal: Principal,
) -> None:
    guarded = _guarded()

    with establish(entitled_principal), ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(guarded, customer_id="c-1")

        with pytest.raises(NoContext):
            future.result()


# --- filtering through the decorator --------------------------------------------------


@pytest.mark.unit
def test_the_decorator_filters_and_defaults_the_arguments_it_binds(
    governor: Governor,
    constrained_principal: Principal,
) -> None:
    guarded = _guarded()

    with establish(constrained_principal):
        result = guarded("c-1", region="nowhere")

    assert result["customer_id"] == "c-1"
    assert result["region"] == "eu-west"


@pytest.mark.unit
def test_a_positional_argument_reaches_the_filter_like_a_keyword_one(
    governor: Governor,
    constrained_principal: Principal,
) -> None:
    guarded = _guarded()

    with establish(constrained_principal), pytest.raises(NoValidArguments):
        guarded("c-999")


# --- the envelope on the way out ------------------------------------------------------


@pytest.mark.unit
def test_a_mapping_result_comes_back_with_the_envelope_attached(
    governor: Governor,
    entitled_principal: Principal,
) -> None:
    guarded = _guarded()

    with establish(entitled_principal):
        result = guarded(customer_id="c-1")

    assert "_authz" in result


@pytest.mark.unit
def test_a_non_mapping_result_is_untouched_and_the_envelope_is_read_beside_it(
    governor: Governor,
    entitled_principal: Principal,
) -> None:
    guarded = _guarded_list()

    with establish(entitled_principal):
        result = guarded(customer_id="c-1")

    assert result == ["order-for-c-1"]
    envelope = last_envelope()
    assert envelope is not None
    assert envelope.decision == "allow"


@pytest.mark.unit
def test_verbosity_off_attaches_nothing_at_all(
    governor: Governor,
    entitled_principal: Principal,
) -> None:
    configure(verbosity="off")
    guarded = _guarded()

    with establish(entitled_principal):
        result = guarded(customer_id="c-1")

    assert "_authz" not in result
    assert last_envelope() is None


# --- wiring ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_pinned_governor_is_used_even_with_none_installed(
    policy_engine: PolicyEngine,
    entitled_principal: Principal,
) -> None:
    pinned = Governor(policy_engine)
    guarded = _guarded(governor=pinned)
    set_governor(None)

    with establish(entitled_principal):
        assert guarded(customer_id="c-1")["customer_id"] == "c-1"


@pytest.mark.unit
def test_protecting_a_callable_with_no_governor_wired_fails_loudly(
    entitled_principal: Principal,
) -> None:
    guarded = _guarded()

    with establish(entitled_principal), pytest.raises(ConfigurationError):
        guarded(customer_id="c-1")
