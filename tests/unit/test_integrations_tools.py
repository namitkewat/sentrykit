"""`sentrykit.integrations.tools`: the manifest decision and the omittable-argument shim.

This module is the shared half of both agent integrations and it imports **neither** of them —
`mcp` and `pydantic_ai` are absent from the `default` environment and nothing here needs them.
That is not incidental: MCP's `tools/list` and Pydantic-AI's `prepare` are two spellings of one
question, and the answer lives here precisely so the two cannot drift. A unit suite that needed
a framework to exercise it would have quietly given that up.

Two mechanisms are covered, and each is load-bearing.

**`decide_tool` — the entitlement/argument split.** The manifest probe supplies no
arguments, so the only question it can honestly answer is whether this principal may perform
this action at all. `AuthzDenied` and `NoContext` hide a tool; every other `SentrykitError` is
about arguments a probe has not got, and is enforced on dispatch instead. The tests assert
both sides, because a filter that read an argument-level refusal as a denial would hide every
required-parameter tool from every principal — and would look perfectly healthy from the
outside.

**`proposable` — the re-declaration.** Both agent frameworks validate a proposal against
the advertised JSON schema before dispatch, so a `required` parameter can never be omitted, and
an argument that can never be omitted can never be filled in from a policy default. The shim
re-declares those parameters as keyword-only and optional and forwards only what was genuinely
proposed. The double introspection is the trick and gets its own test: `inspect.signature` must
report the *shim's* parameters so the framework advertises the optional schema, while
`__wrapped__` must still reach the protected callable so the manifest filter finds its
`@protect` metadata. Those two pull in opposite directions — a `__signature__` is precisely what
stops the unwrapping walk — and a change that satisfied either alone would break the other.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

import pytest

from sentrykit.cedar import Entity, EntityRef, PolicyEngine
from sentrykit.constraints import ArgumentConstraint, ConstraintSet
from sentrykit.context import Principal
from sentrykit.decorator import protect, protected_meta
from sentrykit.engine import Governor, set_governor
from sentrykit.errors import AuthzDenied, ConfigurationError, DefaultUnavailable, NoContext
from sentrykit.integrations.tools import (
    ENTITLEMENT_ERRORS,
    decide_tool,
    decide_tools,
    governed_meta,
    permitted_tools,
    proposable,
)

SEARCH = 'Action::"tool.search_orders"'
EXPORT = 'Action::"tool.export_orders"'
ORDERS = 'Tool::"orders"'


@pytest.fixture
def installed(policy_engine: PolicyEngine) -> Governor:
    """A governor over the shared fixture policy set, installed as the process default.

    The root `conftest` supplies the policy text and tears the governor down again, so a test
    that forgets to install one sees `ConfigurationError` rather than another test's world.
    """
    governor = Governor(policy_engine)
    set_governor(governor)
    return governor


@protect(action=SEARCH, resource=ORDERS)
def search_orders(region: str, limit: int) -> dict[str, object]:
    """Search orders. Two required parameters and no Python defaults, which is the point.

    Args:
        region: Which region to search.
        limit: How many orders to return.

    Returns:
        The arguments it ran with.
    """
    return {"region": region, "limit": limit}


@protect(action=EXPORT, resource=ORDERS)
def export_orders(fmt: str = "csv") -> dict[str, object]:
    """Export orders. One parameter, already carrying a Python default.

    Args:
        fmt: The export format.

    Returns:
        The arguments it ran with.
    """
    return {"fmt": fmt}


def ungoverned(x: int) -> int:
    """A callable nobody asked sentrykit to govern.

    Args:
        x: Anything.

    Returns:
        It, unchanged.
    """
    return x


# --- decide_tool: the entitlement/argument split ---------------------------------------------


@pytest.mark.unit
def test_the_two_refusals_that_hide_a_tool_are_the_entitlement_ones() -> None:
    """The split written down in one place, so the two providers cannot each invent their own."""
    assert set(ENTITLEMENT_ERRORS) == {AuthzDenied, NoContext}


@pytest.mark.unit
def test_a_principal_the_policy_denies_is_not_shown_the_tool(
    installed: Governor, unentitled_principal: Principal
) -> None:
    """`AuthzDenied` is about entitlement, so it hides — and the refusal is reported with it."""
    decision = decide_tool("search_orders", search_orders, principal=unentitled_principal)

    assert decision.visible is False
    assert decision.governed is True
    assert isinstance(decision.error, AuthzDenied)


@pytest.mark.unit
def test_a_required_argument_with_no_default_does_not_hide_the_tool_from_anybody(
    installed: Governor, entitled_principal: Principal
) -> None:
    """The reason the split exists, asserted as the reason rather than as a rule.

    `search_orders` has two required parameters and this principal has no constraints, so the
    argument-free probe refuses with `DefaultUnavailable` — the refusal *every* principal would
    get, including one who is fully entitled. Reading it as a denial would hide the tool from
    everyone, which is a filter that lies about entitlement. So the tool stays visible and the
    argument-level refusal is reported alongside it rather than acted on.
    """
    decision = decide_tool("search_orders", search_orders, principal=entitled_principal)

    assert decision.visible is True
    assert decision.governed is True
    assert isinstance(decision.error, DefaultUnavailable)
    assert decision.plan is None


@pytest.mark.unit
def test_a_tool_whose_arguments_policy_can_supply_probes_cleanly(
    installed: Governor, constrained_principal: Principal
) -> None:
    """The other side of the same coin: a probe that completes carries its plan.

    `tool.export_orders` gives this principal a default for `fmt` and a required `tenant`, so
    the probe still cannot complete — while `tool.ping` declares no arguments at all and does.
    A successful probe's plan is what an optional schema-narrowing pass would read, so it is
    worth asserting that a probe returns one rather than merely not raising.
    """

    @protect(action='Action::"tool.ping"', resource='Resource::"tool.ping"')
    def ping() -> dict[str, object]:
        """Take no arguments, so the argument-free probe is a complete call."""
        return {"ok": True}

    decision = decide_tool("ping", ping, principal=constrained_principal)

    assert decision.visible is True
    assert decision.error is None
    assert decision.plan is not None
    assert decision.plan.allowed is True
    assert str(decision.plan.invocation.action) == 'Action::"tool.ping"'


@pytest.mark.unit
def test_an_unprotected_callable_is_reported_ungoverned_and_left_visible(
    installed: Governor, entitled_principal: Principal
) -> None:
    """sentrykit does not silently hide a tool its author never asked it to govern.

    Reported rather than merely allowed through: `governed=False` is the honest answer, and it
    is what lets a host that wants everything governed assert so in one line.
    """
    decision = decide_tool("ungoverned", ungoverned, principal=entitled_principal)

    assert decision.governed is False
    assert decision.visible is True
    assert decision.error is None
    assert decision.plan is None


@pytest.mark.unit
def test_a_protected_tool_with_no_governor_refuses_rather_than_showing_everything(
    entitled_principal: Principal,
) -> None:
    """Fail closed, applied to the manifest. No governor installed by this test, on purpose."""
    with pytest.raises(ConfigurationError, match="no governor is installed"):
        decide_tool("search_orders", search_orders, principal=entitled_principal)


@pytest.mark.unit
def test_an_ungoverned_tool_needs_no_governor_at_all(entitled_principal: Principal) -> None:
    """There is nothing to decide about it, so there is nothing to be missing."""
    assert decide_tool("ungoverned", ungoverned, principal=entitled_principal).visible is True


@pytest.mark.unit
def test_a_whole_manifest_is_decided_in_the_order_it_was_given(
    installed: Governor, unentitled_principal: Principal
) -> None:
    """Order is part of the contract: a manifest is a list a model reads top to bottom."""
    decisions = decide_tools(
        [("search_orders", search_orders), ("ungoverned", ungoverned)],
        principal=unentitled_principal,
    )

    assert [decision.name for decision in decisions] == ["search_orders", "ungoverned"]
    assert [decision.visible for decision in decisions] == [False, True]


@pytest.mark.unit
def test_permitted_tools_returns_only_the_names_a_principal_may_be_shown(
    installed: Governor, entitled_principal: Principal, unentitled_principal: Principal
) -> None:
    """The convenience form, and the same decision — asserted against two principals.

    One principal alone could not distinguish "filtered correctly" from "returns everything".
    """
    tools = {"search_orders": search_orders, "ungoverned": ungoverned}

    assert permitted_tools(tools, principal=entitled_principal) == ("search_orders", "ungoverned")
    assert permitted_tools(tools, principal=unentitled_principal) == ("ungoverned",)


@pytest.mark.unit
def test_the_probe_runs_under_the_environment_it_was_given(
    installed: Governor, entitled_principal: Principal
) -> None:
    """A policy conditioning on `context.channel` must see `agent` on the probe too.

    Asserted through behaviour rather than by inspecting the request: the policy below permits
    only over the agent channel, so the tool is visible with that environment and hidden
    without it.
    """
    engine = PolicyEngine(
        """
        @id("agents-only")
        permit (
          principal in Role::"support",
          action == Action::"tool.channelled",
          resource == Tool::"orders"
        ) when { context.channel == "agent" };
        """,
        (Entity(EntityRef("Role", "support")), Entity(EntityRef("Tool", "orders"))),
    )
    governor = Governor(engine)

    @protect(action='Action::"tool.channelled"', resource=ORDERS)
    def channelled() -> dict[str, object]:
        """Take no arguments, so only the channel can decide this."""
        return {"ok": True}

    over_agent = decide_tool(
        "channelled",
        channelled,
        principal=entitled_principal,
        governor=governor,
        environment={"channel": "agent"},
    )
    over_http = decide_tool(
        "channelled",
        channelled,
        principal=entitled_principal,
        governor=governor,
        environment={"channel": "http"},
    )

    assert over_agent.visible is True
    assert over_http.visible is False


# --- governed_meta: finding the protected callable under the wrappers ------------------------


@pytest.mark.unit
def test_governed_meta_finds_the_metadata_through_a_two_layer_chain() -> None:
    """MCP wraps a shim in a translator; Pydantic-AI wraps a shim in a ctx-taking adapter.

    Either way the protected callable is two hops down, and finding it is what decides whether
    the manifest filter governs the tool or waves it through as unprotected — which is the
    failure that would silently *unhide* a denied tool.
    """
    import functools

    shim = proposable(search_orders)

    def outer(**proposed: object) -> object:
        """The second wrapping layer, standing in for either framework's."""
        return shim(**proposed)

    functools.update_wrapper(outer, shim)

    assert governed_meta(outer) is not None
    assert governed_meta(outer) is protected_meta(search_orders)


@pytest.mark.unit
def test_governed_meta_returns_none_for_something_that_was_never_protected() -> None:
    """A wrapper chain that bottoms out in an ordinary function is ordinary all the way down."""
    import functools

    def wrapper(x: int) -> int:
        """Wrap an unprotected callable."""
        return ungoverned(x)

    functools.update_wrapper(wrapper, ungoverned)

    assert governed_meta(wrapper) is None
    assert governed_meta(ungoverned) is None


# --- proposable: the re-declaration ----------------------------------------------------------


@pytest.mark.unit
def test_every_parameter_with_no_python_default_becomes_omittable() -> None:
    """The default set is precisely the set whose value could only have come from policy.

    Keyword-only because agent frameworks propose by name, and because it removes the ordering
    trap where making one parameter optional would leave a non-default parameter after a
    defaulted one.
    """
    shim = proposable(search_orders)

    parameters = inspect.signature(shim).parameters

    assert list(parameters) == ["region", "limit"]
    assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values())
    assert parameters["region"].default is None
    assert parameters["limit"].default is None
    assert parameters["region"].annotation == (str | None)
    assert parameters["limit"].annotation == (int | None)


@pytest.mark.unit
def test_a_parameter_that_already_has_a_python_default_is_left_required_of_nothing() -> None:
    """`fmt` has its own default, so policy was never the only possible source of its value.

    It still becomes keyword-only — the shim forwards by name — but its default is its own and
    its annotation is not widened, so `None` keeps whatever meaning the author gave it.
    """
    parameters = inspect.signature(proposable(export_orders)).parameters

    assert parameters["fmt"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["fmt"].default == "csv"
    assert parameters["fmt"].annotation is str


@pytest.mark.unit
def test_optional_names_the_subset_the_caller_chooses() -> None:
    """`optional=` overrides the default set, one parameter at a time."""
    parameters = inspect.signature(proposable(search_orders, optional=["region"])).parameters

    assert parameters["region"].default is None
    assert parameters["region"].annotation == (str | None)
    assert parameters["limit"].default is inspect.Parameter.empty
    assert parameters["limit"].annotation is int


@pytest.mark.unit
def test_optional_of_nothing_keeps_every_parameter_required() -> None:
    """The documented opt-out, for a tool whose arguments are genuinely the caller's choice."""
    parameters = inspect.signature(proposable(search_orders, optional=())).parameters

    assert parameters["region"].default is inspect.Parameter.empty
    assert parameters["limit"].default is inspect.Parameter.empty
    assert parameters["region"].annotation is str


@pytest.mark.unit
def test_naming_a_parameter_the_callable_does_not_declare_is_a_configuration_error() -> None:
    """A typo in `optional=` must not silently make nothing omittable.

    The message names what *is* declared, because the whole cost of the mistake is the minutes
    spent wondering which spelling the tool wanted.
    """
    with pytest.raises(ConfigurationError, match="declares no proposable parameter named nope"):
        proposable(search_orders, optional=["nope"])


@pytest.mark.unit
def test_naming_a_positional_only_parameter_is_a_configuration_error() -> None:
    """It could not be proposed by name, so it could not be omitted either."""

    def positional(order_id: str, /, limit: int = 5) -> dict[str, object]:
        """Take one positional-only parameter."""
        return {"order_id": order_id, "limit": limit}

    with pytest.raises(ConfigurationError, match="positional-only"):
        proposable(positional, optional=["order_id"])


@pytest.mark.unit
def test_a_callable_whose_annotations_cannot_be_resolved_is_a_configuration_error() -> None:
    """Refused at wiring time, naming the callable, rather than at the first dispatch.

    Annotations are resolved eagerly against the tool's own globals, because every module here
    carries `from __future__ import annotations` and the framework would otherwise resolve the
    surviving forward references against the *shim's* module. A reference that resolves nowhere
    is a wiring mistake, and the wiring is where it should surface.
    """

    def unresolvable(region: NoSuchType) -> None:  # type: ignore[name-defined] # noqa: F821
        """Annotate a parameter with a name that does not exist."""

    with pytest.raises(ConfigurationError, match="cannot introspect the signature"):
        proposable(unresolvable)


@pytest.mark.unit
def test_an_omitted_argument_is_dropped_rather_than_forwarded_as_none() -> None:
    """The core of the shim: an omission has to reach the decorator *as an omission*.

    Forwarding `None` would make it a proposed value, the constraint filter would judge it, and
    policy default injection would never happen — which is the whole thing the shim exists for.
    """
    received: list[dict[str, object]] = []

    def record(region: str = "eu", limit: int = 10) -> dict[str, object]:
        """Record exactly which keyword arguments arrived, falling back to its own defaults."""
        received.append({"region": region, "limit": limit})
        return {"region": region, "limit": limit}

    shim = proposable(record, optional=["region", "limit"])

    shim()
    shim(region=None, limit=None)
    shim(region="uk", limit=None)

    assert received == [
        {"region": "eu", "limit": 10},
        {"region": "eu", "limit": 10},
        {"region": "uk", "limit": 10},
    ]


@pytest.mark.unit
def test_a_supplied_value_passes_through_untouched(installed: Governor) -> None:
    """The other half: what the caller did propose reaches the callable exactly as sent."""
    seen: list[dict[str, object]] = []

    def record(region: str = "eu", limit: int = 10) -> dict[str, object]:
        """Record what arrived."""
        seen.append({"region": region, "limit": limit})
        return {"region": region, "limit": limit}

    shim = proposable(record, optional=["region", "limit"])

    shim(region="uk", limit=5)
    shim(region=None, limit=5)

    assert seen == [{"region": "uk", "limit": 5}, {"region": "eu", "limit": 5}]


@pytest.mark.unit
def test_an_async_callable_gets_an_async_shim() -> None:
    """Registered on either framework, an async tool must stay awaitable through the shim."""

    async def fetch(region: str, limit: int) -> dict[str, object]:
        """An async tool body."""
        await asyncio.sleep(0)
        return {"region": region, "limit": limit}

    shim = proposable(fetch)

    assert inspect.iscoroutinefunction(shim)
    assert asyncio.run(shim(region="uk", limit=3)) == {"region": "uk", "limit": 3}


@pytest.mark.unit
def test_a_sync_callable_gets_a_sync_shim() -> None:
    """And a sync one is not silently made awaitable, which would change how a host calls it."""
    shim = proposable(export_orders)

    assert not inspect.iscoroutinefunction(shim)


@pytest.mark.unit
def test_the_shim_satisfies_both_introspections_at_once() -> None:
    """The trick, asserted as the two opposing requirements it reconciles.

    `inspect.signature` must stop at the shim, or the framework would advertise the protected
    callable's required parameters and the re-declaration would buy nothing. `inspect.unwrap`
    must not stop there, or the manifest filter would find no `@protect` metadata and would
    treat a governed tool as ungoverned. Both are asserted together because a change that fixed
    either one alone would break the other.
    """
    shim = proposable(search_orders)

    advertised = inspect.signature(shim).parameters

    assert advertised["region"].default is None
    assert shim.__wrapped__ is search_orders
    assert protected_meta(shim.__wrapped__) is not None
    assert shim.__name__ == "search_orders"
    assert shim.__doc__ is not None
    assert shim.__doc__.startswith("Search orders.")


@pytest.mark.unit
def test_var_args_are_not_treated_as_proposable_parameters() -> None:
    """`*args`/`**kwargs` are not proposed by name, and the engine's spec does not model them."""

    def flexible(region: str, *args: object, **kwargs: object) -> dict[str, object]:
        """Declare both variadic forms alongside a real parameter."""
        return {"region": region, "args": args, "kwargs": kwargs}

    parameters = inspect.signature(proposable(flexible)).parameters

    assert list(parameters) == ["region"]


@pytest.mark.unit
def test_a_shimmed_tool_is_still_governed_by_the_manifest_filter(
    installed: Governor, unentitled_principal: Principal
) -> None:
    """The two mechanisms in this module, meeting: the shim must not cost a tool its guard.

    Registered through a shim, a denied tool is still hidden. If `__wrapped__` were ever lost,
    this would flip to visible — a hidden-tool-becomes-advertised regression that no assertion
    about the signature alone would catch.
    """
    decision = decide_tool(
        "search_orders", proposable(search_orders), principal=unentitled_principal
    )

    assert decision.governed is True
    assert decision.visible is False


@pytest.mark.unit
def test_the_shim_carries_a_constrained_principals_defaults_all_the_way_through(
    installed: Governor,
) -> None:
    """End to end, with no framework in sight: omit everything, and policy fills it in.

    This is the shim's whole purpose in one assertion — it makes the omission expressible,
    `@protect` turns it into a policy default, and the tool body runs on values the caller never
    proposed.
    """
    principal = Principal(
        id="dana",
        roles=("support",),
        constraints={
            SEARCH: ConstraintSet(
                arguments={
                    "region": ArgumentConstraint(
                        allow=("eu", "uk"), default="eu", policy="dana-region"
                    ),
                    "limit": ArgumentConstraint(maximum=50, default=10, policy="dana-limit"),
                }
            )
        },
    )
    shim = proposable(search_orders)

    from sentrykit.context import establish

    with establish(principal, channel="agent"):
        result: Any = shim()

    assert result["region"] == "eu"
    assert result["limit"] == 10
    assert set(result["_authz"]["defaults_applied"]) == {"region", "limit"}
