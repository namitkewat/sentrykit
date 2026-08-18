"""The phase-4 examples in the docs do what they say, down to the printed values.

`tests/unit/test_documented_examples*.py` pin the phase 1 and 2 pages and
`test_documented_examples_phase3.py` pins the web page; this pins the two agent examples —
`examples/fastmcp_server/README.md`, `examples/pydantic_ai_agent/README.md` — and the module
docstrings of `sentrykit.integrations.fastmcp`, `sentrykit.integrations.pydantic_ai` and
`sentrykit.integrations.tools`.

Same reason as ever, restated because it keeps mattering: documentation that has drifted from
the code is worse than none, because a reader trusts it, copies it, and then debugs the wrong
thing. Every literal asserted here appears verbatim in one of those files. If a page and this
file disagree, one of them is a bug.

Several of these pin a **warning** rather than a feature — that a bare `@server.tool()`
registration swallows a refusal, that an omittable argument cannot carry a meaningful `None`,
that a framework rejects a proposal against the advertised schema before any adapter runs, that
the standalone `fastmcp` distribution does not import. A warning nobody checks is a rumour, and
two of those four are now the *reason* a piece of the design exists rather than a footnote about
it — so they are asserted as contrasts, showing both what goes wrong without the mechanism and
what it buys.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")
pytest.importorskip("pydantic_ai")

import mcp
from examples.fastmcp_server.policy import POLICY_TEXT as MCP_POLICY_TEXT
from examples.fastmcp_server.policy import build_grants as build_mcp_grants
from examples.fastmcp_server.server import create_server
from examples.pydantic_ai_agent.agent import (
    Caller,
    build_agent,
    default_model,
    dispatch_context,
    propose,
)
from examples.pydantic_ai_agent.agent import offered_tools as offered_tools_for
from examples.pydantic_ai_agent.policy import POLICY_TEXT as AGENT_POLICY_TEXT
from examples.pydantic_ai_agent.policy import build_grants as build_agent_grants
from examples.pydantic_ai_agent.service import search_orders as agent_search_orders
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult
from pydantic_ai import Agent, RunContext, ToolDefinition
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel
from pydantic_ai.usage import RunUsage

import sentrykit
from sentrykit.decorator import protect
from sentrykit.integrations.base import DEFAULT_PRINCIPAL_HEADER
from sentrykit.integrations.fastmcp import FastMCPProvider, protect_server, registered_tools
from sentrykit.integrations.fastmcp import governed_tool as mcp_governed_tool
from sentrykit.integrations.pydantic_ai import (
    PydanticAIProvider,
    governed_tool,
    tool_adapter,
)
from sentrykit.integrations.tools import (
    ENTITLEMENT_ERRORS,
    decide_tool,
    governed_meta,
    permitted_tools,
)

SEARCH = 'Action::"orders.search"'
EXPORT = 'Action::"orders.export"'
ORDERS = 'Tool::"orders"'


def body_of(result: CallToolResult) -> Mapping[str, Any]:
    """Read a tool result's body, whichever way this result carried it."""
    if result.structured_content is not None:
        return result.structured_content
    for item in result.content:
        text = getattr(item, "text", None)
        if text is not None:
            decoded: Any = json.loads(text)
            if isinstance(decoded, Mapping):
                return decoded
    raise AssertionError(f"no readable body on {result!r}")


@asynccontextmanager
async def serving(*, severed: bool = False) -> AsyncIterator[mcp.Client]:
    """Open a client over the example MCP server, the way the README's snippets drive it.

    A context manager rather than a fixture because ``mcp.Client`` holds an AnyIO task group,
    and pytest-asyncio may finalize an async-generator fixture in a different task than it set
    it up in — which trips ``Attempted to exit cancel scope in a different task``.

    Args:
        severed: Build the graph with one edge removed.

    Yields:
        The connected client.
    """
    async with mcp.Client(create_server(severed=severed)) as connected:
        yield connected


def _definitions_offered_to(agent: Agent[Caller, str], caller: Caller) -> list[ToolDefinition]:
    """Return the tool definitions the model is offered for one caller.

    The manifest is only observable from inside a run, so this drives one turn on a model that
    proposes nothing and reports `AgentInfo.function_tools` — the same technique the example's
    own `offered_tools` uses, kept here because these tests want the whole definition rather
    than just the names.

    Args:
        agent: The agent to inspect.
        caller: Whose behalf the run acts on.

    Returns:
        The definitions, in registration order.
    """
    seen: list[list[ToolDefinition]] = []

    def observe(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        """Record the definitions and answer without proposing anything."""
        seen.append(list(info.function_tools))
        return ModelResponse(parts=[TextPart("noted")])

    agent.run_sync("what can you do?", deps=caller, model=FunctionModel(observe))
    return seen[0]


@pytest.fixture
def agent() -> Agent[Caller, str]:
    """A freshly built example agent, the way the README's snippets build one."""
    return build_agent()


# --- examples/pydantic_ai_agent/README.md ------------------------------------------------------


@pytest.mark.integration
def test_the_manifest_is_per_caller_exactly_as_the_readme_prints_it(
    agent: Agent[Caller, str],
) -> None:
    """The README — "The manifest is per-caller": `['search_orders']` / `['export_orders']`."""
    assert asyncio.run(offered_tools_for(agent, Caller("alice"))) == ["search_orders"]
    assert asyncio.run(offered_tools_for(agent, Caller("bob"))) == ["export_orders"]


@pytest.mark.integration
def test_the_narrowed_search_returns_exactly_what_the_readme_prints(
    agent: Agent[Caller, str],
) -> None:
    """The README — "Argument filtering, then default injection"."""
    assert asyncio.run(propose(agent, Caller("alice"), "search_orders", region="cn", limit=5)) == {
        "region": "eu",
        "limit": 5,
        "orders": ["order-0", "order-1", "order-2"],
        "_authz": {
            "decision": "allow",
            "action": SEARCH,
            "resource": ORDERS,
            "principal": 'User::"alice"',
            "processed": {"limit": 5, "region": "eu"},
            "rejected": [
                {
                    "name": "region",
                    "rule": "allow-set",
                    "reason": "Value is not one of the permitted values",
                    "policy": "alice-region",
                    "value": "cn",
                }
            ],
            "defaults_applied": {"region": "eu"},
        },
    }


@pytest.mark.integration
def test_the_model_may_omit_both_arguments_and_gets_what_the_readme_prints(
    agent: Agent[Caller, str],
) -> None:
    """The README — "Defaults for arguments nobody proposed", proposed by the *model*.

    The whole dict, because every part of it is a claim: the values, the empty proposal behind
    them, and `defaults_applied` naming both — which is the envelope saying the model chose
    neither.
    """
    assert asyncio.run(propose(agent, Caller("alice"), "search_orders")) == {
        "region": "eu",
        "limit": 10,
        "orders": ["order-0", "order-1", "order-2"],
        "_authz": {
            "decision": "allow",
            "action": SEARCH,
            "resource": ORDERS,
            "principal": 'User::"alice"',
            "processed": {"region": "eu", "limit": 10},
            "defaults_applied": {"region": "eu", "limit": 10},
        },
    }


@pytest.mark.integration
def test_a_call_whose_every_argument_was_refused_is_itself_refused(
    agent: Agent[Caller, str],
) -> None:
    """The README — "Nothing left to run with": no default rescues a wholly refused call."""
    refused = asyncio.run(propose(agent, Caller("alice"), "search_orders", region="cn", limit=999))

    assert isinstance(refused, Mapping)
    assert refused["detail"] == "Every supplied argument was rejected by policy."
    assert refused["error"] == "NoValidArguments"
    envelope = refused["_authz"]
    assert [item["name"] for item in envelope["rejected"]] == ["region", "limit"]
    assert envelope["allowed"]["region"]["allow"] == ["eu", "uk"]
    assert envelope["allowed"]["limit"]["maximum"] == 50


@pytest.mark.integration
def test_a_hidden_tool_gets_the_model_the_correction_the_readme_quotes(
    agent: Agent[Caller, str],
) -> None:
    """The README — "bob may not search, and his model is never told the tool exists".

    Pydantic-AI, not sentrykit, writes this sentence: a proposal for a tool the run never
    offered is rejected before any adapter is reached. Pinning the exact text is how the README
    stays honest about *which layer* answered.
    """
    correction = asyncio.run(propose(agent, Caller("bob"), "search_orders", region="eu", limit=3))

    assert correction == "Unknown tool name: 'search_orders'. Available tools: 'export_orders'"


@pytest.mark.integration
def test_hiding_is_not_the_enforcement_exactly_as_the_readme_prints(
    agent: Agent[Caller, str],
) -> None:
    """The README — "…and hiding is not the enforcement"."""
    dispatch = tool_adapter(agent_search_orders)

    assert asyncio.run(dispatch(dispatch_context(agent, Caller("bob")))) == {
        "detail": 'The policy denied action Action::"orders.search".',
        "error": "AuthzDenied",
        "_authz": {
            "decision": "deny",
            "reason": 'The policy denied action Action::"orders.search".',
            "action": SEARCH,
            "resource": ORDERS,
        },
    }


@pytest.mark.integration
def test_the_argument_aware_forbid_prints_what_the_readme_says_it_does(
    agent: Agent[Caller, str],
) -> None:
    """The README — "A policy that reads the argument": csv allowed, pdf refused."""
    assert asyncio.run(propose(agent, Caller("bob"), "export_orders", fmt="csv")) == {
        "fmt": "csv",
        "exported": 42,
        "_authz": {
            "decision": "allow",
            "action": EXPORT,
            "resource": ORDERS,
            "principal": 'User::"bob"',
            "processed": {"fmt": "csv"},
        },
    }
    assert asyncio.run(propose(agent, Caller("bob"), "export_orders", fmt="pdf")) == {
        "detail": 'The policy denied action Action::"orders.export".',
        "error": "AuthzDenied",
        "_authz": {
            "decision": "deny",
            "reason": 'The policy denied action Action::"orders.export".',
            "action": EXPORT,
            "resource": ORDERS,
        },
    }


@pytest.mark.integration
def test_debug_verbosity_names_the_policy_the_readme_names(agent: Agent[Caller, str]) -> None:
    """The README's closing line on that snippet: `'determining_policies': ['no-pdf-exports']`."""
    sentrykit.configure(verbosity="debug")

    refused = asyncio.run(propose(agent, Caller("bob"), "export_orders", fmt="pdf"))

    assert isinstance(refused, Mapping)
    assert refused["_authz"]["determining_policies"] == ["no-pdf-exports"]


@pytest.mark.integration
def test_turning_the_filter_off_leaves_enforcement_completely_intact() -> None:
    """The README — the *if* half: `governed_tool(..., filter_manifest=False)`.

    The claim is that the model gets refusals instead of a shorter menu, which is only true if
    the tool is both offered *and* refused. Both halves are asserted.
    """
    store = build_agent_grants()
    sentrykit.configure(verbosity="verbose")
    sentrykit.install(AGENT_POLICY_TEXT, grant_store=store)
    provider = PydanticAIProvider(grants=store)

    unfiltered: Agent[Caller, str] = Agent(TestModel(), deps_type=Caller)
    governed_tool(unfiltered, provider=provider, filter_manifest=False)(agent_search_orders)

    offered = asyncio.run(offered_tools_for(unfiltered, Caller("bob")))
    refused = asyncio.run(propose(unfiltered, Caller("bob"), "search_orders", region="eu", limit=3))

    assert offered == ["search_orders"]
    assert isinstance(refused, Mapping)
    assert refused["error"] == "AuthzDenied"


@pytest.mark.integration
def test_governed_tool_re_declares_the_arguments_the_framework_would_have_required(
    agent: Agent[Caller, str],
) -> None:
    """The README's first "detail worth copying", and the reason `proposable` exists at all.

    Both halves, because the claim is a *contrast*. A tool registered the plain way advertises
    `region` and `limit` as required and a model omitting them is turned away by Pydantic-AI
    before any adapter runs — so on that tool, policy default injection is simply unreachable.
    A `governed_tool`-registered one advertises the same parameters as omittable, and the
    omission reaches the decorator as an omission.

    Asserting only the second half would leave the paragraph unexplained: a reader would have
    no way to tell that the re-declaration buys anything.
    """
    plain: Agent[Caller, str] = Agent(TestModel(), deps_type=Caller)

    @plain.tool
    async def search_orders(ctx: RunContext[Caller], region: str, limit: int) -> dict[str, object]:
        """Search orders, registered without sentrykit and therefore with both args required."""
        return {"region": region, "limit": limit}

    turned_away = asyncio.run(propose(plain, Caller("alice"), "search_orders"))
    dispatched = asyncio.run(propose(agent, Caller("alice"), "search_orders"))

    assert not isinstance(turned_away, Mapping)
    assert "Field required" in str(turned_away)
    assert isinstance(dispatched, Mapping)
    assert dispatched["_authz"]["defaults_applied"] == {"region": "eu", "limit": 10}


@pytest.mark.integration
def test_the_advertised_schema_is_the_shape_the_readme_describes(
    agent: Agent[Caller, str],
) -> None:
    """The README — "keyword-only and optional", and "`optional=()` keeps everything required".

    `search_orders` opts in and loses its `required` list entirely; `export_orders` opts out
    with `optional=()` and keeps `fmt` required, because `fmt` is a genuine choice by whoever
    wants the export and not something policy could supply. The two are asserted together
    since the paragraph is about the *choice* between them.
    """
    offered = {
        definition.name: definition.parameters_json_schema
        for caller in (Caller("alice"), Caller("bob"))
        for definition in _definitions_offered_to(agent, caller)
    }

    search = offered["search_orders"]
    assert "required" not in search
    assert search["properties"]["region"] == {
        "anyOf": [{"type": "string"}, {"type": "null"}],
        "default": None,
        "description": "Which region to search. Constrained per principal.",
    }
    assert offered["export_orders"]["required"] == ["fmt"]
    assert offered["export_orders"]["properties"]["fmt"]["type"] == "string"


@pytest.mark.integration
def test_an_omittable_argument_cannot_carry_a_meaningful_none(
    agent: Agent[Caller, str],
) -> None:
    """The README's warning, reproduced: the shim reads `None` as *not proposed*.

    A model that explicitly proposes `region=None` gets alice's default rather than a `None`
    reaching the tool body — which is the trade-off the README tells a reader to weigh before
    letting a genuinely nullable parameter into the omittable set. If this ever stops being
    true, the warning has to go.
    """
    dispatched = asyncio.run(propose(agent, Caller("alice"), "search_orders", region=None, limit=5))

    assert isinstance(dispatched, Mapping)
    assert dispatched["region"] == "eu"
    assert dispatched["limit"] == 5
    assert dispatched["_authz"]["defaults_applied"] == {"region": "eu"}


@pytest.mark.integration
def test_the_governed_tool_is_returned_unchanged_and_still_importable() -> None:
    """The README's second "detail worth copying", and the module docstring's promise."""
    store = build_agent_grants()
    sentrykit.install(AGENT_POLICY_TEXT, grant_store=store)
    built: Agent[Caller, str] = Agent(TestModel(), deps_type=Caller)

    returned = governed_tool(built, provider=PydanticAIProvider(grants=store))(agent_search_orders)

    assert returned is agent_search_orders
    assert sentrykit.is_protected(returned)


@pytest.mark.integration
async def test_on_refusal_raise_ends_the_run_as_the_module_docstring_says() -> None:
    """The docstring's last paragraph: the opt-out for a host that treats a refusal as a bug.

    The default is asserted everywhere else in this suite; this is the other branch, and
    without it the paragraph is an unchecked promise.
    """
    store = build_agent_grants()
    sentrykit.install(AGENT_POLICY_TEXT, grant_store=store)
    provider = PydanticAIProvider(grants=store)

    raising = tool_adapter(agent_search_orders, provider=provider, on_refusal="raise")
    returning = tool_adapter(agent_search_orders, provider=provider)
    bob = RunContext(deps=Caller("bob"), model=TestModel(), usage=RunUsage())

    with pytest.raises(sentrykit.AuthzDenied):
        await raising(bob)
    assert (await returning(bob))["error"] == "AuthzDenied"


# --- src/sentrykit/integrations/tools.py, the module docstring ---------------------------------


@pytest.mark.integration
def test_a_manifest_probe_with_no_governor_refuses_rather_than_showing_everything() -> None:
    """The docstring's fail-closed rule, applied to the manifest.

    "A manifest that silently showed everything because nothing was installed would be the
    exact failure mode ADR-003 exists to prevent" — so a protected tool with no governor is a
    `ConfigurationError`, not a shrug.
    """
    with pytest.raises(sentrykit.ConfigurationError, match="no governor is installed"):
        decide_tool("search_orders", agent_search_orders, principal=sentrykit.Principal(id="alice"))


@pytest.mark.integration
def test_only_entitlement_refusals_hide_a_tool() -> None:
    """The docstring's two groups, named: `AuthzDenied` and `NoContext`, and nothing else.

    The list is asserted rather than described, because the split between "may not do this at
    all" and "did not propose valid arguments" is the whole of the manifest's honesty.
    """
    assert set(ENTITLEMENT_ERRORS) == {sentrykit.AuthzDenied, sentrykit.NoContext}


@pytest.mark.integration
def test_an_unprotected_tool_is_reported_ungoverned_and_left_visible() -> None:
    """The docstring — "An unprotected tool is not a governed tool"."""

    def untouched(x: int) -> int:
        """A tool nobody asked sentrykit to govern."""
        return x

    decision = decide_tool("untouched", untouched, principal=sentrykit.Principal(id="nobody"))

    assert decision.governed is False
    assert decision.visible is True
    assert decision.error is None


@pytest.mark.integration
def test_a_required_argument_with_no_default_does_not_hide_a_tool_from_everybody() -> None:
    """The docstring's reason for the split: the probe supplies no arguments.

    ``search_orders`` has two required parameters. Reading the argument-level refusal of an
    argument-free probe as a denial would hide it from every principal, which is a filter that
    lies about entitlement.
    """
    store = build_agent_grants()
    sentrykit.install(AGENT_POLICY_TEXT, grant_store=store)
    alice = store.get_principal("alice")
    assert alice is not None

    names = permitted_tools({"search_orders": agent_search_orders}, principal=alice)

    assert names == ("search_orders",)


# --- src/sentrykit/integrations/pydantic_ai.py, the module docstring ----------------------------


@pytest.mark.integration
def test_the_pydantic_ai_module_docstring_example_runs_as_written() -> None:
    """The `governed_tool` snippet at the top of the module, transcribed and executed.

    Its shape is the promise: one `@protect`, one registration, a `deps` type whose field is
    the *human*, and a tool body that takes no `ctx`.
    """
    from dataclasses import dataclass

    store = build_agent_grants()
    sentrykit.configure(verbosity="verbose")
    sentrykit.install(AGENT_POLICY_TEXT, grant_store=store)

    @dataclass
    class LocalCaller:
        """The human, not the agent."""

        principal: str

    built: Agent[LocalCaller, str] = Agent(TestModel(), deps_type=LocalCaller)

    @governed_tool(built, provider=PydanticAIProvider(grants=store))
    @protect(action='Action::"orders.search"', resource='Tool::"orders"')
    def search_orders(region: str = "eu", limit: int = 3) -> dict[str, object]:
        """Search orders."""
        return {"region": region, "limit": limit}

    result = built.run_sync("search", deps=LocalCaller(principal="alice"))

    assert json.loads(result.output)["search_orders"]["_authz"]["principal"] == 'User::"alice"'


# --- examples/fastmcp_server/README.md and the fastmcp module docstring -------------------------


ALICE = {DEFAULT_PRINCIPAL_HEADER: "alice"}
"""The README's `ALICE`, verbatim."""

BOB = {DEFAULT_PRINCIPAL_HEADER: "bob"}
"""The README's `BOB`, verbatim."""


@pytest.mark.integration
async def test_the_manifest_the_mcp_readme_prints_is_the_manifest_served() -> None:
    """The README — "The manifest is per-principal", all three printed lists."""
    async with serving() as client:
        alice = await client.list_tools(meta=ALICE)
        bob = await client.list_tools(meta=BOB)
        anonymous = await client.list_tools(meta={})

    assert [tool.name for tool in alice.tools] == ["search_orders", "read_order"]
    assert [tool.name for tool in bob.tools] == ["export_orders"]
    assert [tool.name for tool in anonymous.tools] == []


@pytest.mark.integration
async def test_the_mcp_readme_default_injection_prints_what_it_says() -> None:
    """The README — "Default injection": `-> False eu 10`, then both names in
    `defaults_applied`.

    And the sentence under the snippet — "neither is in `rejected`, which is the envelope
    saying *the model chose none of this*". Both halves are asserted, because the README's
    claim is about what the envelope *distinguishes*, not merely about the two values.
    """
    async with serving() as client:
        result = await client.call_tool("search_orders", {}, meta=ALICE)

    body = body_of(result)
    envelope = body["_authz"]
    assert result.is_error is not True
    assert body["region"] == "eu"
    assert body["limit"] == 10
    assert envelope["defaults_applied"] == {"region": "eu", "limit": 10}
    assert "rejected" not in envelope


@pytest.mark.integration
async def test_the_mcp_readme_argument_filtering_prints_what_it_says() -> None:
    """The README — "Argument filtering": `-> eu 5`, the exact rejection, the exact default.

    Also pins the second "detail worth copying": the caller's own proposal reaches the
    decorator untouched, which is why `cn` is in `rejected` at all rather than having been
    quietly overwritten by the plan.
    """
    async with serving() as client:
        result = await client.call_tool("search_orders", {"region": "cn", "limit": 5}, meta=ALICE)

    envelope = body_of(result)["_authz"]
    assert body_of(result)["region"] == "eu"
    assert body_of(result)["limit"] == 5
    assert envelope["rejected"] == [
        {
            "name": "region",
            "rule": "allow-set",
            "reason": "Value is not one of the permitted values",
            "policy": "alice-region",
            "value": "cn",
        }
    ]
    assert envelope["defaults_applied"] == {"region": "eu"}


@pytest.mark.integration
async def test_the_mcp_readme_role_gate_prints_what_it_says() -> None:
    """The README — "The role gate": the structured refusal *and* its text content.

    The text line is the one a model reads if it never looks at the structured half, so the
    README prints it and this asserts it.
    """
    async with serving() as client:
        result = await client.call_tool("search_orders", {}, meta=BOB)

    body = body_of(result)
    assert result.is_error is True
    assert body["error"] == "AuthzDenied"
    assert body["_authz"]["decision"] == "deny"
    assert body["_authz"]["action"] == SEARCH
    assert result.content[0].text == 'The policy denied action Action::"orders.search".'


@pytest.mark.integration
async def test_the_mcp_readme_hidden_tool_called_by_name_prints_what_it_says() -> None:
    """The README — "Hiding is not the enforcement", including the resource it names."""
    async with serving() as client:
        result = await client.call_tool("read_order", {"order_id": "o-1"}, meta=BOB)

    body = body_of(result)
    assert result.is_error is True
    assert body["error"] == "AuthzDenied"
    assert body["_authz"]["resource"] == 'Order::"o-1"'


@pytest.mark.integration
async def test_the_multi_hop_read_the_mcp_readme_showcases() -> None:
    """The README — "Four hops, resolved by Cedar": `-> False o-1`, then `-> allow`."""
    async with serving() as client:
        result = await client.call_tool("read_order", {"order_id": "o-1"}, meta=ALICE)

    body = body_of(result)
    assert result.is_error is not True
    assert body["order_id"] == "o-1"
    assert body["_authz"]["decision"] == "allow"


@pytest.mark.integration
async def test_the_mcp_readme_argument_aware_forbid_prints_what_it_says() -> None:
    """The README — "A policy that reads the argument": `-> False csv`, then `-> True deny`."""
    async with serving() as client:
        allowed = await client.call_tool("export_orders", {"fmt": "csv"}, meta=BOB)
        refused = await client.call_tool("export_orders", {"fmt": "pdf"}, meta=BOB)

    assert allowed.is_error is not True
    assert body_of(allowed)["fmt"] == "csv"
    assert refused.is_error is True
    assert body_of(refused)["_authz"]["decision"] == "deny"


@pytest.mark.integration
async def test_severing_one_edge_does_what_the_mcp_readme_says_it_does() -> None:
    """The README — "Break one edge and the access goes with it", all three printed lines.

    The third one is what keeps the other two honest: alice can still *search* on the severed
    graph, so the read was lost because the relationship was, and not because she was.
    """
    async with serving(severed=True) as severed:
        refused = await severed.call_tool("read_order", {"order_id": "o-1"}, meta=ALICE)
        listed = await severed.list_tools(meta=ALICE)
        still_allowed = await severed.call_tool("search_orders", {}, meta=ALICE)

    assert refused.is_error is True
    assert body_of(refused)["error"] == "AuthzDenied"
    assert [tool.name for tool in listed.tools] == ["search_orders"]
    assert still_allowed.is_error is not True
    assert body_of(still_allowed)["region"] == "eu"


@pytest.mark.integration
async def test_a_tool_call_is_validated_against_its_schema_before_the_body_runs() -> None:
    """Pins the first half of the README's "omittable-argument shim" bullet.

    Registered the plain way, ``search_orders(region, limit)`` called with no arguments is
    rejected by the transport and never reaches the body — it "could never be called with none
    of them, and default injection would be unreachable from a model". Everything
    :func:`~sentrykit.integrations.tools.proposable` does is a response to this one measured
    fact, so if it ever stops being true the shim stops being necessary.
    """
    ungoverned: MCPServer = MCPServer("ungoverned")

    @ungoverned.tool()
    def search_orders(region: str, limit: int) -> dict[str, object]:
        """Search orders, with no `@protect` and no policy anywhere near it."""
        return {"region": region, "limit": limit}

    async with mcp.Client(ungoverned) as client:
        result = await client.call_tool("search_orders", {})

    assert result.is_error is True
    assert "Field required" in result.content[0].text


@pytest.mark.integration
async def test_the_advertised_mcp_schema_is_the_shape_the_readme_describes() -> None:
    """The other half of that bullet: the shim advertises the policy-suppliable args optional.

    The advertised shape *is* the mechanism — a model reads the schema and nothing else — so it
    is asserted literally rather than inferred from a call happening to succeed.
    """
    async with serving() as client:
        listed = await client.list_tools(meta=ALICE)

    schemas = {tool.name: tool.input_schema for tool in listed.tools}
    region = schemas["search_orders"]["properties"]["region"]

    assert "required" not in schemas["search_orders"]
    assert region["anyOf"] == [{"type": "string"}, {"type": "null"}]
    assert region["default"] is None
    assert schemas["search_orders"]["properties"]["limit"]["anyOf"] == [
        {"type": "integer"},
        {"type": "null"},
    ]


@pytest.mark.integration
async def test_a_bare_server_tool_registration_really_does_swallow_the_refusal() -> None:
    """Pins the README's sharp edge: never hand a `@protect`-ed callable to `@server.tool()`.

    A warning nobody checks is a rumour, and this one is now load-bearing — it is the reason
    `governed_tool` exists rather than being a convenience. Both of the README's claims about
    the bare registration are asserted, `structuredContent: null` and the
    `"Error executing tool …"` string, and so is the sentence that follows them: **the gate
    still ran and the side effect was still refused.** That last half is what makes this a
    legibility bug rather than a security one, and it is the part a reader is most likely to
    get wrong.

    Python defaults on both parameters, so the call reaches the decorator rather than being
    turned away by schema validation — otherwise this would be pinning the wrong failure.
    """
    ran: list[str] = []
    store = build_mcp_grants()
    sentrykit.install(MCP_POLICY_TEXT, grant_store=store)
    server: MCPServer = MCPServer("bare-registration")

    @server.tool()
    @protect(action='Action::"orders.search"', resource='Tool::"orders"')
    def search_orders(region: str = "eu", limit: int = 10) -> dict[str, object]:
        """Search orders, registered the way the README says never to."""
        ran.append(region)
        return {"region": region, "limit": limit}

    protect_server(server, provider=FastMCPProvider(grants=store))

    async with mcp.Client(server) as client:
        refused = await client.call_tool("search_orders", {}, meta=BOB)

    assert refused.is_error is True
    assert refused.structured_content is None, "the envelope survived a bare registration"
    assert refused.content[0].text.startswith("Error executing tool search_orders")
    assert ran == [], "the gate still ran and the side effect was still refused"


@pytest.mark.integration
def test_the_fastmcp_module_docstring_example_wires_a_server_as_written() -> None:
    """The `governed_tool` + `protect_server` snippet at the top of the module, as written.

    The snippet passes `action`/`resource` to `governed_tool` and writes no separate
    `@protect`, so this pins that `governed_tool` applies it. Both of the docstring's claims
    about the two wrapping layers are asserted as well: `__wrapped__` still reaches the
    protected callable, so :func:`~sentrykit.integrations.tools.governed_meta` finds its
    metadata and the manifest filter governs the tool rather than waving it through as
    unprotected; and the callable handed back is the protected one rather than a wrapper, so
    the rest of the program keeps its function.
    """
    store = build_mcp_grants()
    sentrykit.install(MCP_POLICY_TEXT, grant_store=store)
    server: MCPServer = MCPServer("orders")

    @mcp_governed_tool(server, action='Action::"orders.read"', resource='Order::"o-1"')
    def read_order(order_id: str, limit: int = 10) -> dict[str, object]:
        """Read an order."""
        return {"order_id": order_id, "limit": limit}

    provider = protect_server(server, provider=FastMCPProvider(grants=store))
    discovered = registered_tools(server)

    assert isinstance(provider, FastMCPProvider)
    assert sentrykit.is_protected(read_order)
    assert "read_order" in discovered
    assert discovered["read_order"] is not read_order, "the registered callable is the wrapper"
    assert governed_meta(discovered["read_order"]) is not None


@pytest.mark.integration
def test_the_standalone_fastmcp_distribution_is_never_imported() -> None:
    """Pins the module docstring's warning, `docs/agents.md`'s admonition, and research §0.

    Three places say it, so it is worth being sure once: `sentrykit[fastmcp]` installs
    `mcp>=2,<3` and the separately published `fastmcp` distribution — which is in this
    environment as somebody else's transitive dependency and does not import against mcp 2.0 —
    is never reached for. A reader who takes the module's name at face value and runs
    `pip install fastmcp` gets a broken environment, which is exactly why the page says so.
    """
    from importlib import metadata

    from sentrykit.integrations import fastmcp as module

    borrowed = {
        getattr(value, "__module__", "").split(".")[0]
        for value in vars(module).values()
        if getattr(value, "__module__", None)
    }
    requirements = metadata.metadata("sentrykit").get_all("Requires-Dist") or []
    # The quoting of a marker is the packaging tooling's business, so it is normalized away
    # rather than pinned: what this test is about is which distribution the extra names.
    declared = [item for item in requirements if "extra == fastmcp" in item.replace("'", "")]

    assert "mcp.server.mcpserver" in (module.__doc__ or "")
    assert "fastmcp" not in borrowed
    assert module.MCPServer.__module__.startswith("mcp.")
    assert declared, "sentrykit declares no fastmcp extra at all"
    assert all(item.startswith("mcp<3,>=2") for item in declared), declared


# --- docs/agents.md -----------------------------------------------------------------------------
#
# The page a reader arrives at before either README. `test_documented_examples_phase3.py` pins
# `docs/web-frameworks.md` the same way, and for the same reason: a page is a promise, and an
# unchecked promise drifts.


@pytest.mark.integration
async def test_the_agents_page_mcp_quickstart_behaves_as_the_page_describes() -> None:
    """The page's MCP walkthrough, end to end: offered, omitted, defaulted, hidden, refused.

    Five claims in one test because the page makes them as one story — alice is offered the
    tool, may call it with nothing, gets her own values with both named in `defaults_applied`,
    while bob is not offered it *and* is refused when he calls it anyway. Splitting them would
    let a reader check the reassuring half in isolation.
    """
    async with serving() as client:
        alice_manifest = await client.list_tools(meta=ALICE)
        omitted = await client.call_tool("search_orders", {}, meta=ALICE)
        bob_manifest = await client.list_tools(meta=BOB)
        bob_by_name = await client.call_tool("search_orders", {}, meta=BOB)

    body = body_of(omitted)
    assert "search_orders" in [tool.name for tool in alice_manifest.tools]
    assert body["region"] == "eu"
    assert body["limit"] == 10
    assert body["_authz"]["defaults_applied"] == {"region": "eu", "limit": 10}
    assert "search_orders" not in [tool.name for tool in bob_manifest.tools]
    assert bob_by_name.is_error is True
    assert body_of(bob_by_name)["error"] == "AuthzDenied"


@pytest.mark.integration
async def test_the_filtering_guarantee_the_agents_page_states_as_an_iff_holds_both_ways() -> None:
    """`docs/agents.md` — "The filtering guarantee", asserted in one place as the page states it.

    The page says both halves are load-bearing and both are asserted in the same test, so this
    is that test, and it is the one that should break if the guarantee changes. *Only if*: a
    hidden tool called by name is refused anyway. *If*: a tool alice may invoke is offered to
    her and runs.
    """
    async with serving() as client:
        alice_manifest = [tool.name for tool in (await client.list_tools(meta=ALICE)).tools]
        bob_manifest = [tool.name for tool in (await client.list_tools(meta=BOB)).tools]
        hidden_called_anyway = await client.call_tool("read_order", {"order_id": "o-1"}, meta=BOB)
        offered_and_run = await client.call_tool("read_order", {"order_id": "o-1"}, meta=ALICE)

    assert "read_order" in alice_manifest
    assert offered_and_run.is_error is not True

    assert "read_order" not in bob_manifest
    assert hidden_called_anyway.is_error is True
    assert body_of(hidden_called_anyway)["_authz"]["decision"] == "deny"


@pytest.mark.integration
def test_the_entitlement_split_the_agents_page_names_is_the_split_implemented(
    agent: Agent[Caller, str],
) -> None:
    """`docs/agents.md` — the paragraph naming which refusals hide a tool and which do not.

    The page lists `AuthzDenied` and `NoContext` on one side and `DefaultUnavailable`,
    `NoValidArguments`, `ArgumentRejected` and `ValidationFailed` on the other, and gives the
    reason: a required parameter with no policy default raises for *everybody*, so treating it
    as a denial would hide every such tool from every principal. Both the membership and the
    reason are checkable, so both are checked — `bob` has no `orders.search` default for
    anything, and `search_orders` is still offered to `alice`, who does.
    """
    store = build_agent_grants()
    sentrykit.install(AGENT_POLICY_TEXT, grant_store=store)
    alice = store.get_principal("alice")
    assert alice is not None

    hiding = set(ENTITLEMENT_ERRORS)
    not_hiding = {
        sentrykit.DefaultUnavailable,
        sentrykit.NoValidArguments,
        sentrykit.ArgumentRejected,
        sentrykit.ValidationFailed,
    }

    assert hiding == {sentrykit.AuthzDenied, sentrykit.NoContext}
    assert hiding.isdisjoint(not_hiding)
    assert permitted_tools({"search_orders": agent_search_orders}, principal=alice) == (
        "search_orders",
    )
    assert "search_orders" in asyncio.run(offered_tools_for(agent, Caller("alice")))


@pytest.mark.integration
def test_the_agents_page_promise_that_an_ungoverned_tool_stays_visible() -> None:
    """`docs/agents.md`: "It is left **visible**: sentrykit does not silently hide a tool its
    author never asked it to govern"."""

    def untouched(x: int) -> int:
        """A tool with no `@protect` anywhere in its chain."""
        return x

    decision = decide_tool("untouched", untouched, principal=sentrykit.Principal(id="nobody"))

    assert decision.governed is False
    assert decision.visible is True


@pytest.mark.integration
def test_the_agents_page_accepts_authenticated_principal_as_an_identify_callback() -> None:
    """`docs/agents.md` — "Where the principal comes from", the snippet at the end of it.

    Pinned by wiring it rather than by calling it: `authenticated_principal` returns `None` off
    an authenticated transport, so what is checkable here is that the page's snippet is *valid*
    — the name exists at the import path the page gives, and the provider accepts it. A reader
    copying the two lines gets a provider, not an `ImportError`.
    """
    from mcp.server.mcpserver import authenticated_principal

    provider = FastMCPProvider(identify=authenticated_principal, grants=build_mcp_grants())

    assert provider.channel == "agent"
    assert provider.name == "fastmcp"


@pytest.mark.integration
async def test_the_manifest_cache_scope_the_agents_page_documents_is_what_mcp_sends() -> None:
    """`docs/agents.md` — "Manifest caching": `cacheScope: "private"` and `ttlMs: 0`.

    A claim about somebody else's library, which is exactly the kind that rots without anyone
    noticing. It is load-bearing here: the manifest is per-principal, so a default that cached
    it across callers would show one principal another's tools. Read off the wire rather than
    from a constant, so an mcp upgrade that changed the default fails this instead of shipping.
    """
    async with serving() as client:
        listed = await client.list_tools(meta=ALICE)

    assert listed.cache_scope == "private"
    assert listed.ttl_ms == 0


@pytest.mark.integration
def test_the_four_hop_policy_the_agents_page_quotes_is_the_example_policy() -> None:
    """`docs/agents.md` — "Relationships are resolved by the policy, not by the model".

    The page quotes the policy as Cedar source. A quoted policy that had drifted from the one
    the example actually evaluates would be the worst kind of documentation bug: it reads as
    evidence. So the quote is checked against `examples/fastmcp_server/policy.py` rather than
    described.
    """
    quoted = (
        '@id("project-members-may-read-project-orders")\n'
        "permit (\n"
        '  principal in Project::"orders-eu",\n'
        '  action == Action::"orders.read",\n'
        '  resource in Project::"orders-eu"\n'
        ");"
    )
    page = Path("docs/agents.md").read_text(encoding="utf-8")

    assert quoted in page, "docs/agents.md no longer quotes the policy this test pins"
    assert quoted in MCP_POLICY_TEXT, "the example's policy has drifted from the quoted one"


@pytest.mark.integration
def test_the_agents_page_promise_that_governed_tool_hands_the_callable_back(
    agent: Agent[Caller, str],
) -> None:
    """`docs/agents.md` — the quickstarts both write `governed_tool(agent)(search_orders)`.

    That spelling only reads sensibly because the callable comes back unchanged, so the module
    keeps its function. Asserted on both integrations, since the page shows both.
    """
    store = build_agent_grants()
    sentrykit.install(AGENT_POLICY_TEXT, grant_store=store)
    built: Agent[Caller, str] = Agent(TestModel(), deps_type=Caller)
    server: MCPServer = MCPServer("orders")

    from_agent = governed_tool(built, provider=PydanticAIProvider(grants=store))(
        agent_search_orders
    )
    from_server = mcp_governed_tool(server)(agent_search_orders)

    assert from_agent is agent_search_orders
    assert from_server is agent_search_orders
    assert sentrykit.is_protected(agent_search_orders)


@pytest.mark.integration
def test_both_examples_really_do_run_offline(agent: Agent[Caller, str]) -> None:
    """`docs/agents.md` — "Both run offline, with no API key and no network call".

    The agent example's default model is the checkable half: `default_model()` returns a
    `TestModel` unless `SENTRYKIT_EXAMPLE_MODEL` is set, and the root `conftest` strips every
    `SENTRYKIT_*` variable, so this is the state a reader with no configuration is in. The MCP
    example has no model at all — its client speaks to the server over an in-memory transport,
    which every other test in this module has already demonstrated by not opening a socket.
    """
    assert isinstance(default_model(), TestModel)
    assert isinstance(agent.model, TestModel)


@pytest.mark.integration
def test_the_agents_page_warning_about_omittable_none_is_true(
    agent: Agent[Caller, str],
) -> None:
    """`docs/agents.md`'s admonition: an omittable parameter cannot carry a meaningful `None`.

    Same hazard as the pydantic-ai README's, pinned here too because this is the page a reader
    meets first and the one that says "do not list a genuinely nullable parameter". If the shim
    ever started forwarding `None`, both texts would have to change.
    """
    dispatched = asyncio.run(propose(agent, Caller("alice"), "search_orders", region=None, limit=5))

    assert isinstance(dispatched, Mapping)
    assert dispatched["region"] == "eu"
    assert dispatched["_authz"]["defaults_applied"] == {"region": "eu"}
