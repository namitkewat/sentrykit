"""The MCP provider, driven through the example server over an in-memory transport.

`mcp.Client` accepts an `MCPServer` directly and runs it in-process, so every test here is a
real client/server round trip — real JSON-RPC framing, real ``_meta`` propagation, real
``CallToolResult`` deserialization — with no socket, no subprocess and no live model.

The client is entered with ``async with`` inside each test rather than yielded from a fixture.
That is not a style preference: ``mcp.Client`` holds an AnyIO task group, and pytest-asyncio
may finalize an async-generator fixture in a different task than it set it up in, which trips
``Attempted to exit cancel scope in a different task``. Entering and leaving in the test's own
task is the only shape that is correct.

Two things are asked here that the web suite has no analogue for:

* **The manifest is per-principal.** ``tools/list`` is filtered by the same gate that enforces
  dispatch, and the two halves of that invariant (:mod:`sentrykit.integrations.tools`) are
  asserted *together* — a test that only checked the hiding would go green against a server
  that hid a tool and then happily ran it.
* **The relationship is multi-hop.** ``read_order`` is permitted by a policy naming only
  ``Project::"orders-eu"`` at both ends, four edges away from the caller. Cedar resolves
  User → Team → Division → Project ∋ Order; nothing in the tool, the server or the test says
  so. Cutting one edge (``create_server(severed=True)``) flips both the dispatch and the
  manifest, which is the evidence that the graph and not a hard-coded list is doing the work.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from typing import Any

import pytest

pytest.importorskip("mcp")

import mcp
from examples.mcp_server.policy import POLICY_TEXT, build_grants
from examples.mcp_server.server import create_server
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

import sentrykit
from sentrykit.integrations.base import DEFAULT_PRINCIPAL_HEADER
from sentrykit.integrations.mcp import MCPProvider, governed_tool, protect_server
from sentrykit.stores.memory import InMemoryAuditSink

PRINCIPAL_KEY = DEFAULT_PRINCIPAL_HEADER
"""The ``_meta`` key the example server and every client below carry the principal in.

``_meta`` rather than a header because it is the only carrier that exists on *every*
transport, in-memory included. The name is the web providers' for continuity.
"""


def meta_for(user: str | None) -> dict[str, Any] | None:
    """Build the request ``_meta`` for a caller, or ``None`` for an unauthenticated one.

    Args:
        user: The principal id, or ``None``.

    Returns:
        The ``_meta`` mapping, or ``None``.
    """
    return None if user is None else {PRINCIPAL_KEY: user}


def payload_of(result: CallToolResult) -> Mapping[str, Any]:
    """Read a tool result's body, whichever way this result carried it.

    A tool annotated ``-> dict[str, object]`` gets an output schema, so its body arrives in
    ``structured_content``; a refusal built by :meth:`MCPProvider.render_error` puts it
    there too. The text fallback exists so this helper still reports something useful — rather
    than ``None`` — if a tool is ever registered without an output schema.

    Args:
        result: The client's tool result.

    Returns:
        The body as a mapping.
    """
    if result.structured_content is not None:
        return result.structured_content
    for item in result.content:
        text = getattr(item, "text", None)
        if text is not None:
            decoded: Any = json.loads(text)
            if isinstance(decoded, Mapping):
                return decoded
    raise AssertionError(f"no readable body on {result!r}")


def authz_of(result: CallToolResult) -> Mapping[str, Any]:
    """Return the ``_authz`` envelope on a tool result.

    Args:
        result: The client's tool result.

    Returns:
        The envelope.

    Raises:
        AssertionError: If there is none — a contract failure worth reporting as itself rather
            than as a ``KeyError`` further down the test.
    """
    body = payload_of(result)
    assert "_authz" in body, f"no _authz envelope in {body!r}"
    envelope: Mapping[str, Any] = body["_authz"]
    return envelope


class Caller:
    """One MCP client, addressed by principal id rather than by ``_meta`` plumbing.

    Args:
        client: The connected client.
    """

    def __init__(self, client: mcp.Client) -> None:
        self._client = client

    async def call(
        self, name: str, arguments: Mapping[str, Any] | None = None, *, user: str | None = None
    ) -> CallToolResult:
        """Invoke one tool as ``user``."""
        return await self._client.call_tool(name, dict(arguments or {}), meta=meta_for(user))

    async def manifest(self, *, user: str | None = None) -> tuple[str, ...]:
        """List the tool names ``user`` is shown."""
        listed = await self._client.list_tools(meta=meta_for(user))
        return tuple(tool.name for tool in listed.tools)


@asynccontextmanager
async def serving(*, severed: bool = False) -> AsyncGenerator[Caller, None]:
    """Open a client over a freshly built example server.

    Built per test rather than imported: ``create_server()`` calls ``configure()`` and
    ``install()``, and the root ``conftest`` tears both down between tests — so a server built
    once at import time would be answering to a governor that no longer exists.

    Args:
        severed: Build the graph with ``Team::"eu-support"`` detached from its division, and
            nothing else changed — same policy text, same roles, same constraints, same tools.
            A difference in outcome can then only have come from the graph.

    Yields:
        The caller.
    """
    async with mcp.Client(create_server(severed=severed)) as client:
        yield Caller(client)


# --- the dispatch gate ---------------------------------------------------------------------


@pytest.mark.integration
async def test_an_entitled_call_runs_on_the_defaults_policy_injected() -> None:
    """Alice proposes nothing; policy supplies both arguments and says that it did.

    Neither parameter has a Python default, so a value can only have come from the principal's
    grants — which is the difference between "the tool chose" and "the policy decided". The
    envelope has to *say* so as well as the values having to be right: a model that cannot see
    which arguments it did not choose cannot report honestly on what it did.
    """
    async with serving() as caller:
        result = await caller.call("search_orders", user="alice")

    body = payload_of(result)
    envelope = authz_of(result)
    assert result.is_error is not True
    assert body["region"] == "eu"
    assert body["limit"] == 10
    assert envelope["decision"] == "allow"
    assert set(envelope.get("defaults_applied", {})) == {"region", "limit"}, (
        "the envelope must report the arguments policy filled in; got "
        f"{envelope!r}. See the note on the middleware's argument write-back."
    )


@pytest.mark.integration
async def test_a_permitted_argument_is_passed_through_untouched() -> None:
    """A default must never override a value the principal is entitled to pass."""
    async with serving() as caller:
        result = await caller.call("search_orders", {"region": "uk", "limit": 5}, user="alice")

    body = payload_of(result)
    assert body["region"] == "uk"
    assert body["limit"] == 5
    assert "rejected" not in authz_of(result)


@pytest.mark.integration
async def test_a_disallowed_argument_is_dropped_and_defaulted_and_the_model_is_told() -> None:
    """The model proposed ``cn``; the tool ran on ``eu`` and the refusal is named, not silent.

    Naming it is what lets the model adapt rather than quietly believe it searched China.
    """
    async with serving() as caller:
        result = await caller.call("search_orders", {"region": "cn", "limit": 5}, user="alice")

    body = payload_of(result)
    assert result.is_error is not True
    assert body["region"] == "eu"
    assert body["limit"] == 5
    rejections = authz_of(result)["rejected"]
    assert [item["name"] for item in rejections] == ["region"]
    assert rejections[0]["value"] == "cn"


@pytest.mark.integration
async def test_a_principal_without_the_role_is_refused_with_a_structured_envelope() -> None:
    """Bob is an auditor; only support may search.

    The refusal is a ``CallToolResult`` and not a raised error precisely so this assertion is
    possible: a propagating error arrives with ``structured_content=None`` and the envelope
    gone.
    """
    async with serving() as caller:
        result = await caller.call("search_orders", user="bob")

    body = payload_of(result)
    assert result.is_error is True
    assert body["error"] == "AuthzDenied"
    assert authz_of(result)["decision"] == "deny"


@pytest.mark.integration
async def test_an_unauthenticated_call_is_refused_rather_than_run() -> None:
    """No ``_meta`` principal means no principal, and no principal is a refusal."""
    async with serving() as caller:
        result = await caller.call("search_orders")

    body = payload_of(result)
    assert result.is_error is True
    assert body["error"] == "NoContext"
    assert authz_of(result)["decision"] == "deny"


@pytest.mark.integration
async def test_a_refused_call_never_reaches_the_tool_body() -> None:
    """The positioning, asserted: sentrykit refuses the *side effect* before it happens.

    A counter in the tool body is the only way to tell "refused" from "ran and then had its
    result replaced", and the shipped example cannot carry one — so this test builds its own
    server over the example's own policy and grants. Alice's call proves the counter works at
    all; the other two prove it did not move.

    Registered through ``governed_tool`` because that is the only supported way to register a
    protected MCP tool: a bare ``@server.tool()`` advertises ``region`` and ``limit`` as
    required, so alice's argument-free call would be turned away by schema validation before
    the decorator ever ran — and the counter would stay at zero for the wrong reason.
    """
    calls: list[str] = []
    store = build_grants()
    sentrykit.install(POLICY_TEXT, grant_store=store)

    server: MCPServer = MCPServer("counting-orders")

    @governed_tool(server, action='Action::"orders.search"', resource='Tool::"orders"')
    def search_orders(region: str, limit: int) -> dict[str, object]:
        """Record that the body ran, and report the arguments policy let through."""
        calls.append(region)
        return {"region": region, "limit": limit}

    protect_server(server, provider=MCPProvider(grants=store))

    async with mcp.Client(server) as client:
        allowed = await client.call_tool("search_orders", {}, meta=meta_for("alice"))
        refused = await client.call_tool("search_orders", {}, meta=meta_for("bob"))
        unauthenticated = await client.call_tool("search_orders", {}, meta=None)

    assert allowed.is_error is not True
    assert refused.is_error is True
    assert payload_of(refused)["error"] == "AuthzDenied"
    assert unauthenticated.is_error is True
    assert payload_of(unauthenticated)["error"] == "NoContext"
    assert calls == ["eu"], "a refused call must not reach the tool body"


@pytest.mark.integration
async def test_one_dispatch_writes_exactly_one_audit_record() -> None:
    """One call, one decision, one record — allowed or refused.

    The regression guard for a pre-flight decision creeping back into the middleware. An
    earlier build decided the call once in the middleware and once again in the decorator, and
    the only externally visible symptom was the audit trail counting each allowed dispatch
    twice. An audit trail that over-reports is not a lesser bug than one that under-reports:
    both make the record useless as evidence of what actually happened.

    Refusals are counted too, because "decide once" has to hold on the path where the call does
    not run at all.
    """
    store = build_grants()
    sink = InMemoryAuditSink()
    sentrykit.install(POLICY_TEXT, grant_store=store, audit_sink=sink)

    server: MCPServer = MCPServer("audited-orders")

    @governed_tool(server, action='Action::"orders.search"', resource='Tool::"orders"')
    def search_orders(region: str, limit: int) -> dict[str, object]:
        """Search orders."""
        return {"region": region, "limit": limit}

    protect_server(server, provider=MCPProvider(grants=store))

    async with mcp.Client(server) as client:
        allowed = await client.call_tool("search_orders", {}, meta=meta_for("alice"))
        after_allow = len(sink.records)
        refused = await client.call_tool("search_orders", {}, meta=meta_for("bob"))
        after_deny = len(sink.records)

    assert allowed.is_error is not True
    assert refused.is_error is True
    assert after_allow == 1, f"one allowed dispatch wrote {after_allow} records"
    assert after_deny - after_allow == 1, f"one refused dispatch wrote {after_deny - 1} records"
    assert [record.decision for record in sink.records] == ["allow", "deny"]


# --- the manifest, and the invariant that it is not the enforcement -------------------------


@pytest.mark.integration
async def test_the_manifest_is_per_principal_and_hiding_is_not_the_enforcement() -> None:
    """Both halves of the invariant in :mod:`sentrykit.integrations.tools`, in one test.

    Alice is shown ``read_order`` and bob is not — and bob calling it anyway, having skipped
    ``tools/list`` entirely, is refused just the same. Asserting only the hiding would leave a
    server that hid the tool and then ran it looking perfectly healthy.
    """
    async with serving() as caller:
        alice_manifest = await caller.manifest(user="alice")
        bob_manifest = await caller.manifest(user="bob")
        bob_direct = await caller.call("read_order", {"order_id": "ord-0003"}, user="bob")

    assert "read_order" in alice_manifest
    assert "read_order" not in bob_manifest
    assert bob_direct.is_error is True
    assert payload_of(bob_direct)["error"] == "AuthzDenied"
    assert authz_of(bob_direct)["decision"] == "deny"


@pytest.mark.integration
async def test_a_tool_the_principal_may_invoke_is_never_hidden() -> None:
    """The *if* half: hiding is a usability affordance, so it must not over-hide.

    ``search_orders`` has two parameters and no Python defaults. A filter that read the
    argument-level refusal of an argument-free probe as a denial would hide it from everybody,
    which is the failure mode ``ENTITLEMENT_ERRORS`` exists to prevent — so the tool being
    *shown* and the tool *running* are asserted together.
    """
    async with serving() as caller:
        manifest = await caller.manifest(user="alice")
        ran = await caller.call("search_orders", user="alice")

    assert "search_orders" in manifest
    assert ran.is_error is not True


@pytest.mark.integration
async def test_an_unauthenticated_caller_is_shown_no_tools_at_all() -> None:
    """Fail closed, applied to the manifest: no principal, no entitlement, nothing to show."""
    async with serving() as caller:
        manifest = await caller.manifest()

    assert manifest == ()


# --- the multi-hop relationship -------------------------------------------------------------


@pytest.mark.integration
async def test_a_four_hop_relationship_permits_a_call_no_policy_names_directly() -> None:
    """User → Team → Division → Project ∋ Order, resolved by Cedar and by nothing else.

    The permitting policy names ``Project::"orders-eu"`` at both ends and mentions neither
    alice nor ``Order::"ord-0003"``. This is the relationship resolution sentrykit offloads to
    policy rather than letting a model infer it or scattering it across ``if`` statements.
    """
    async with serving() as caller:
        result = await caller.call("read_order", {"order_id": "ord-0003"}, user="alice")
        manifest = await caller.manifest(user="alice")

    body = payload_of(result)
    assert result.is_error is not True
    assert body["order_id"] == "ord-0003"
    assert authz_of(result)["decision"] == "allow"
    assert "read_order" in manifest


@pytest.mark.integration
async def test_cutting_one_edge_of_the_chain_denies_and_hides_the_same_call() -> None:
    """One removed parent edge, and alice loses both the permission and the advertisement.

    Same policy text, same role, same tool, same arguments as the test above — the only
    difference is that ``Team::"eu-support"`` no longer has ``Division::"emea"`` as a parent.
    That the outcome flips is the proof that the chain, and not a list somebody typed, is what
    granted the call.
    """
    async with serving(severed=True) as caller:
        result = await caller.call("read_order", {"order_id": "ord-0003"}, user="alice")
        manifest = await caller.manifest(user="alice")

    assert result.is_error is True
    assert payload_of(result)["error"] == "AuthzDenied"
    assert "read_order" not in manifest


@pytest.mark.integration
async def test_severing_the_chain_leaves_the_role_gate_alone() -> None:
    """Alice can still search on the severed graph, because that gate is a role and not a chain.

    Without this the previous test would also pass against a store that had simply lost alice.
    The whole manifest is pinned rather than one membership, because what makes the point is
    that ``read_order`` is the *only* thing missing from it: everything she holds by role is
    still advertised, so the one tool that went is the one the cut edge was carrying.
    """
    async with serving(severed=True) as caller:
        result = await caller.call("search_orders", user="alice")
        manifest = await caller.manifest(user="alice")

    assert result.is_error is not True
    assert manifest == ("desk_status", "brief_orders", "search_orders", "issue_refund")


@pytest.mark.integration
async def test_a_principal_on_the_other_branch_never_reaches_the_order() -> None:
    """Bob's chain is intact and simply leads somewhere else: ``Project::"orders-us"``.

    So his refusal is not the severed graph's — it is the ordinary answer for a principal whose
    relationships do not reach the resource, on a graph where alice's do.
    """
    async with serving() as caller:
        result = await caller.call("read_order", {"order_id": "ord-0003"}, user="bob")
        manifest = await caller.manifest(user="bob")

    assert result.is_error is True
    assert payload_of(result)["error"] == "AuthzDenied"
    assert "read_order" not in manifest


# --- the middleware's other responsibilities --------------------------------------------------


@pytest.mark.integration
async def test_the_middleware_leaves_every_other_method_alone() -> None:
    """``initialize`` already happened: the client is connected, which is the assertion.

    The middleware wraps *every* inbound message, so a provider that tried to identify a
    principal on a non-tool method would have failed the handshake before this returned.
    """
    async with serving() as caller:
        assert await caller.manifest(user="alice")


@pytest.mark.integration
def test_the_provider_refuses_to_narrow_a_request_from_another_framework() -> None:
    """A provider wired to the wrong boundary says so, naming both sides."""
    provider = MCPProvider(grants=build_grants())

    with pytest.raises(sentrykit.ConfigurationError, match="wrong framework"):
        provider.narrow(object())


@pytest.mark.integration
def test_wiring_the_same_server_twice_governs_each_dispatch_once() -> None:
    """A module that wires at import and a test that wires in a fixture must not double-govern."""
    store = build_grants()
    sentrykit.install(POLICY_TEXT, grant_store=store)
    server: MCPServer = MCPServer("orders")

    before = len(list(server.middleware))
    protect_server(server, provider=MCPProvider(grants=store))
    after_first = len(list(server.middleware))
    protect_server(server, provider=MCPProvider(grants=store))

    assert after_first == before + 1, "wiring must add exactly one middleware"
    assert len(list(server.middleware)) == after_first, "wiring twice must not add a second"


@pytest.mark.integration
def test_the_example_server_can_be_built_twice_in_one_process() -> None:
    """Two servers, two grant stores, no shared mutable state — the tests depend on it."""
    normal = create_server()
    severed = create_server(severed=True)

    assert normal is not severed
