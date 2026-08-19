"""Nothing about tool dispatch *N* survives into tool dispatch *N+1*, on either agent boundary.

This is the agent half of `tests/integration/test_web_context_isolation.py`, and it is written
the way it is because a leak test driven only through a framework's own harness can pass
**vacuously**. `mcp.Client` runs the
server in its own task, and `agent.run(...)` runs each tool call in Pydantic-AI's, and a task
starts from a *copy* of the context — so a provider that never released anything would still
look spotless through either front door.

So every assertion with teeth here drives **two dispatches inside one `contextvars` context**,
through one middleware instance or one adapter, and asks what is ambient in between. Nothing
copies the context, so a missing `finally: provider.release(...)` is visible.

And the teeth are *demonstrated*, not claimed. Each of the two providers has a paired test that
swaps in a subclass whose `release` does nothing and asserts, with `pytest.raises(AssertionError)`,
that the leak check fails against it. A comment saying "confirmed by construction" rots; a test
that fails when the construction stops holding does not.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import pytest

pytest.importorskip("mcp")
pytest.importorskip("pydantic_ai")

import mcp
from examples.fastmcp_server.policy import build_grants as build_mcp_grants
from examples.fastmcp_server.server import create_server
from examples.pydantic_ai_agent.agent import Caller
from examples.pydantic_ai_agent.policy import POLICY_TEXT as AGENT_POLICY_TEXT
from examples.pydantic_ai_agent.policy import build_grants as build_agent_grants
from mcp.server.context import ServerRequestContext
from mcp.types import CallToolResult
from pydantic_ai import RunContext
from pydantic_ai.models.test import TestModel
from pydantic_ai.usage import RunUsage

import sentrykit
from sentrykit.context import ContextScope
from sentrykit.decorator import protect
from sentrykit.integrations.base import DEFAULT_PRINCIPAL_HEADER
from sentrykit.integrations.fastmcp import FastMCPProvider, SentrykitToolMiddleware
from sentrykit.integrations.pydantic_ai import PydanticAIProvider, tool_adapter

PRINCIPAL_KEY = DEFAULT_PRINCIPAL_HEADER
"""The ``_meta`` key a principal id travels in."""


class LeakyFastMCPProvider(FastMCPProvider):
    """A provider whose ``release`` does nothing — the bug this module exists to catch.

    Not a mock: everything else about it is the real provider, so a test that fails against it
    fails for exactly one reason.
    """

    def release(self, scope: ContextScope | None) -> None:
        """Do nothing, leaving the last dispatch's principal ambient."""


class LeakyPydanticAIProvider(PydanticAIProvider):
    """The Pydantic-AI mirror of :class:`LeakyFastMCPProvider`."""

    def release(self, scope: ContextScope | None) -> None:
        """Do nothing, leaving the last dispatch's principal ambient."""


def call_context(user: str | None, *, arguments: Mapping[str, Any] | None = None) -> Any:
    """Build the ``tools/call`` request context the middleware is handed.

    Constructed by hand rather than driven through a client on purpose: a client would run the
    server in its own task, and a fresh context copy per dispatch is the isolation this module
    must not have. Every field the provider reads is real, and ``session`` is unused on this
    path.

    Args:
        user: The principal id to put in ``_meta``, or ``None`` for an unauthenticated call.
        arguments: The tool arguments the caller proposes.

    Returns:
        The request context.
    """
    return ServerRequestContext(
        session=cast(Any, None),
        lifespan_context=None,
        protocol_version="2026-07-28",
        method="tools/call",
        params={"name": "search_orders", "arguments": dict(arguments or {})},
        request_id="1",
        meta=cast(Any, None if user is None else {PRINCIPAL_KEY: user}),
    )


def run_context(caller: Caller | None) -> RunContext[Any]:
    """Build the run context one Pydantic-AI tool dispatch is handed.

    Args:
        caller: The run's ``deps``, or ``None`` for a run with no human behind it.

    Returns:
        The run context.
    """
    return RunContext(
        deps=caller,
        model=TestModel(),
        usage=RunUsage(),
        tool_name="search_orders",
        tool_call_id="call-1",
        run_id="run-1",
    )


def body_of(result: object) -> Mapping[str, Any]:
    """Read the body off whatever a dispatch returned.

    The MCP middleware answers with a :class:`~mcp.types.CallToolResult`; a tool that ran
    answers with its own mapping. Both are read the same way here because these tests care only
    about *which principal* the dispatch was decided for.

    Args:
        result: The dispatch's return value.

    Returns:
        The body as a mapping.
    """
    if isinstance(result, CallToolResult):
        assert result.structured_content is not None, f"no structured body on {result!r}"
        return result.structured_content
    assert isinstance(result, Mapping), f"unexpected dispatch result {result!r}"
    return result


# --- MCP -----------------------------------------------------------------------------------


def mcp_middleware(*, leaky: bool = False) -> SentrykitToolMiddleware:
    """Wire one middleware over the example server, with or without a working ``release``.

    ``create_server()`` installs the governor, so the provider is built with no explicit grant
    store and picks that one up — the same lazy resolution a real host relies on when it wires
    ``install()`` and the provider in either order.

    Args:
        leaky: Whether to use the provider that never releases.

    Returns:
        The middleware.
    """
    server = create_server()
    provider = LeakyFastMCPProvider() if leaky else FastMCPProvider()
    return SentrykitToolMiddleware(server, provider=provider)


async def drive_two_mcp_dispatches(
    middleware: SentrykitToolMiddleware,
) -> tuple[list[object], dict[str, object]]:
    """Run two ``tools/call`` dispatches through one middleware, in the caller's own context.

    Args:
        middleware: The middleware under test.

    Returns:
        ``(results, checkpoints)`` — what each dispatch returned, and what was ambient between
        and after them.
    """
    checkpoints: dict[str, object] = {}
    results: list[object] = []

    async def call_next(ctx: ServerRequestContext[Any, Any]) -> Any:
        """Stand in for the tool: report the principal the dispatch established."""
        principal = sentrykit.current_principal()
        return {"seen": principal.id if principal is not None else None}

    results.append(await middleware(call_context("alice"), call_next))
    checkpoints["between"] = sentrykit.current_principal()
    results.append(await middleware(call_context(None), call_next))
    checkpoints["after"] = sentrykit.current_principal()
    return results, checkpoints


@pytest.mark.integration
async def test_mcp_leaves_no_principal_behind_between_two_dispatches_in_one_context() -> None:
    """Two ``tools/call`` dispatches, one task, one context — and nothing ambient between them.

    The assertion with teeth. Its companion below proves it has them.
    """
    middleware = mcp_middleware()

    results, checkpoints = await drive_two_mcp_dispatches(middleware)

    assert body_of(results[0])["seen"] == "alice"
    assert checkpoints["between"] is None
    assert checkpoints["after"] is None


@pytest.mark.integration
async def test_the_mcp_leak_check_fails_when_the_provider_stops_releasing() -> None:
    """The teeth, made permanent.

    Same two dispatches through a middleware whose provider's ``release`` is a no-op. Alice is
    still ambient at the ``between`` checkpoint, so the assertion above fails — which is the
    only thing that makes it worth having.
    """
    middleware = mcp_middleware(leaky=True)

    _, checkpoints = await drive_two_mcp_dispatches(middleware)

    leaked = checkpoints["between"]
    assert leaked is not None and getattr(leaked, "id", None) == "alice"
    with pytest.raises(AssertionError):
        assert checkpoints["between"] is None


@pytest.mark.integration
async def test_an_unauthenticated_mcp_dispatch_after_an_entitled_one_is_refused() -> None:
    """The behavioural consequence: the second call is ``NoContext``, not silently alice's.

    A leak would show up here as the second dispatch *succeeding* — which is the failure that
    actually hurts a user, as distinct from the checkpoint that detects it earliest. The tool
    is a genuinely ``@protect``-ed callable rather than a probe, so the refusal comes from the
    gate and not from the middleware being clever.
    """
    middleware = mcp_middleware()

    @protect(action='Action::"orders.search"', resource='Tool::"orders"')
    def protected_search(region: str, limit: int) -> dict[str, object]:
        """Search orders."""
        return {"region": region, "limit": limit}

    async def call_next(ctx: ServerRequestContext[Any, Any]) -> Any:
        """Run the protected tool, whatever the ambient context turns out to be."""
        return protected_search()

    first = await middleware(call_context("alice"), call_next)
    second = await middleware(call_context(None), call_next)

    assert body_of(first)["region"] == "eu"
    assert body_of(second)["error"] == "NoContext"


# --- Pydantic-AI ------------------------------------------------------------------------------


def pydantic_ai_adapter(*, leaky: bool = False) -> Any:
    """Wire one governed adapter over the example agent's policy and grants.

    Args:
        leaky: Whether to use the provider that never releases.

    Returns:
        The adapter, which is exactly the callable ``governed_tool`` registers.
    """
    store = build_agent_grants()
    sentrykit.install(AGENT_POLICY_TEXT, grant_store=store)
    provider = LeakyPydanticAIProvider(grants=store) if leaky else PydanticAIProvider(grants=store)

    @protect(action='Action::"orders.search"', resource='Tool::"orders"')
    def search_orders(region: str, limit: int) -> dict[str, object]:
        """Search orders, reporting the principal the dispatch was decided for."""
        principal = sentrykit.current_principal()
        return {
            "region": region,
            "limit": limit,
            "seen": principal.id if principal is not None else None,
        }

    return tool_adapter(search_orders, provider=provider)


async def drive_two_agent_dispatches(adapter: Any) -> tuple[list[Any], dict[str, object]]:
    """Run two tool dispatches through one adapter, in the caller's own context.

    A run would put each dispatch in Pydantic-AI's own task, and the context copy that comes
    with it is precisely the isolation this must not have.

    Args:
        adapter: The adapter under test.

    Returns:
        ``(results, checkpoints)``.
    """
    checkpoints: dict[str, object] = {}
    results: list[Any] = []

    results.append(await adapter(run_context(Caller("alice"))))
    checkpoints["between"] = sentrykit.current_principal()
    results.append(await adapter(run_context(None)))
    checkpoints["after"] = sentrykit.current_principal()
    return results, checkpoints


@pytest.mark.integration
async def test_pydantic_ai_leaves_no_principal_behind_between_two_dispatches() -> None:
    """A run is a loop, so establishment is per *dispatch* and not per run.

    Two dispatches in one context, and the principal is gone between them — which is what
    "release in a ``finally`` around each tool call" means when it is true.
    """
    adapter = pydantic_ai_adapter()

    results, checkpoints = await drive_two_agent_dispatches(adapter)

    assert body_of(results[0])["seen"] == "alice"
    assert checkpoints["between"] is None
    assert checkpoints["after"] is None


@pytest.mark.integration
async def test_the_pydantic_ai_leak_check_fails_when_the_provider_stops_releasing() -> None:
    """The teeth for the agent side, on the same construction as the MCP one."""
    adapter = pydantic_ai_adapter(leaky=True)

    _, checkpoints = await drive_two_agent_dispatches(adapter)

    leaked = checkpoints["between"]
    assert leaked is not None and getattr(leaked, "id", None) == "alice"
    with pytest.raises(AssertionError):
        assert checkpoints["between"] is None


@pytest.mark.integration
async def test_a_dispatch_with_no_caller_after_an_entitled_one_is_refused() -> None:
    """The behavioural consequence on the agent side: ``NoContext``, not silently alice's."""
    adapter = pydantic_ai_adapter()

    results, _ = await drive_two_agent_dispatches(adapter)

    assert body_of(results[0])["region"] == "eu"
    assert body_of(results[1])["error"] == "NoContext"


# --- both, at the provider itself -------------------------------------------------------------


@pytest.mark.integration
async def test_the_mcp_provider_releases_what_it_established() -> None:
    """The narrowest form of the claim: establish, observe, release, observe."""
    provider = FastMCPProvider(grants=build_mcp_grants())

    scope = provider.establish(call_context("alice"))
    established = sentrykit.current_principal()
    provider.release(scope)

    assert established is not None
    assert established.id == "alice"
    assert sentrykit.current_principal() is None


@pytest.mark.integration
async def test_the_pydantic_ai_provider_releases_what_it_established() -> None:
    provider = PydanticAIProvider(grants=build_agent_grants())

    scope = provider.establish(run_context(Caller("alice")))
    established = sentrykit.current_principal()
    provider.release(scope)

    assert established is not None
    assert established.id == "alice"
    assert sentrykit.current_principal() is None


@pytest.mark.integration
@pytest.mark.parametrize("provider_class", [FastMCPProvider, PydanticAIProvider])
def test_releasing_nothing_still_leaves_the_context_clean(provider_class: type) -> None:
    """``release(None)`` is what an unauthenticated dispatch's ``finally`` calls.

    It has to be safe, and it has to leave the context *empty* rather than merely untouched:
    "nothing was established" and "whatever the last dispatch left behind" must mean the same
    thing to the next caller. A principal is established by hand first, so a release that only
    reset a scope it was given would sail past this and leave that principal ambient.
    """
    provider = provider_class()
    sentrykit.establish(sentrykit.Principal(id="left-over"))

    provider.release(None)

    assert sentrykit.current_principal() is None
    assert sentrykit.last_envelope() is None


@pytest.mark.integration
async def test_a_client_driven_sequence_answers_each_call_as_its_own_caller() -> None:
    """The sequence a reader expects to find, driven through the real front door.

    It is deliberately *not* the teeth — ``mcp.Client`` runs the server in its own task, so
    this would stay green against a middleware that never released anything. It is kept
    because it would still catch a provider that established the *wrong* principal, and
    because it is the shape a user would write themselves.
    """
    async with mcp.Client(create_server()) as client:
        alice = await client.call_tool("search_orders", {}, meta={PRINCIPAL_KEY: "alice"})
        anonymous = await client.call_tool("search_orders", {}, meta=None)
        bob = await client.call_tool("search_orders", {}, meta={PRINCIPAL_KEY: "bob"})
        anonymous_again = await client.call_tool("search_orders", {}, meta=None)

    assert body_of(alice)["region"] == "eu"
    assert body_of(anonymous)["error"] == "NoContext"
    assert body_of(bob)["error"] == "AuthzDenied"
    assert body_of(anonymous_again)["error"] == "NoContext"
