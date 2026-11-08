"""The agent examples in the docs do what they say, down to the printed values.

The unit-suite `test_documented_examples*.py` modules pin the quickstart and the store pages
and `test_documented_examples_web.py` pins the web page; this pins the two agent examples —
`examples/fastmcp_server/README.md`, `examples/pydantic_ai_agent/README.md` — and the module
docstrings of `sentrykit.integrations.fastmcp`, `sentrykit.integrations.pydantic_ai` and
`sentrykit.integrations.tools`. It also pins `docs/agents.md`, the page a reader meets before
either README — including the five blocks it reproduces from what `run-agent` prints, each
checked by running the section that prints it and reading the block back out of the page.

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
import contextlib
import io
import json
import re
from collections.abc import AsyncGenerator, Callable, Coroutine, Mapping
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")
pytest.importorskip("pydantic_ai")

import mcp
from examples import ollama
from examples.fastmcp_server import service as mcp_service
from examples.fastmcp_server.policy import POLICY_TEXT as MCP_POLICY_TEXT
from examples.fastmcp_server.policy import build_grants as build_mcp_grants
from examples.fastmcp_server.server import FLOWS as MCP_FLOWS
from examples.fastmcp_server.server import create_server
from examples.pydantic_ai_agent.agent import FLOWS as AGENT_FLOWS
from examples.pydantic_ai_agent.agent import (
    Caller,
    build_agent,
    default_model,
    dispatch_context,
    propose,
    show_ceiling,
    show_flows,
    show_free_form,
    show_nesting,
    show_who_decided,
)
from examples.pydantic_ai_agent.agent import offered_tools as offered_tools_for
from examples.pydantic_ai_agent.policy import POLICY_TEXT as AGENT_POLICY_TEXT
from examples.pydantic_ai_agent.policy import build_grants as build_agent_grants
from examples.pydantic_ai_agent.service import brief_orders as agent_brief_orders
from examples.pydantic_ai_agent.service import search_orders as agent_search_orders
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult
from pydantic_ai import Agent, RunContext, ToolDefinition
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel
from pydantic_ai.usage import RunUsage

import sentrykit
from sentrykit.context import principal_context
from sentrykit.decorator import protect
from sentrykit.envelope import narrowing_guidance
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
from sentrykit.stores.memory import InMemoryAuditSink

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


def _without_job_id(body: Mapping[str, Any]) -> dict[str, Any]:
    """The body minus the export job's allocated id.

    Two export calls that agree about every argument still book two different rows, and the
    row's id is the one field that cannot be equal. Dropping it is what lets an assertion be
    about the arguments, which is what the tests using this are claiming.
    """
    return {name: value for name, value in body.items() if name != "job_id"}


@asynccontextmanager
async def serving(*, severed: bool = False) -> AsyncGenerator[mcp.Client, None]:
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
    """The README — "The manifest is per-caller": all three printed lists, in order.

    Seven tools are registered and no caller is offered all seven. `desk_status` is in every
    list because its permit names no principal; `approve_refund` is in dana's alone; and
    `issue_refund` is in alice's and dana's because the permit authorizing it is
    unconditional — a permit reading `context.args` would evaluate to false against a probe
    that proposes nothing and hide the tool from the people who may use it.
    """
    assert asyncio.run(offered_tools_for(agent, Caller("alice"))) == [
        "desk_status",
        "brief_orders",
        "search_orders",
        "read_order",
        "issue_refund",
    ]
    assert asyncio.run(offered_tools_for(agent, Caller("bob"))) == ["desk_status", "export_orders"]
    assert asyncio.run(offered_tools_for(agent, Caller("dana"))) == [
        "desk_status",
        "brief_orders",
        "search_orders",
        "read_order",
        "issue_refund",
        "approve_refund",
    ]


@pytest.mark.integration
def test_a_protected_callable_that_is_no_tool_is_decided_inside_the_tool_that_calls_it(
    agent: Agent[Caller, str],
) -> None:
    """The README — "a protected callable that is not a tool": two envelopes, one tool call.

    `summarize_orders` is protected and registered nowhere, so no model was ever told it
    exists and none could propose it. It is decided anyway, against the same ambient
    principal, because the gate is on the *call* and not on the registration — and its own
    envelope survives in place under `brief`, rather than being merged into the outer one.
    """
    assert asyncio.run(propose(agent, Caller("alice"), "brief_orders")) == {
        "brief": {
            "open_orders": 198,
            "regions": {"eu": 81, "uk": 54, "us": 63},
            "oldest_open": "ord-0319",
            "_authz": {
                "decision": "allow",
                "action": 'Action::"orders.summarize"',
                "resource": ORDERS,
                "principal": 'User::"alice"',
            },
        },
        "open_orders": 198,
        "headline": "198 open orders across 3 regions, oldest ord-0319",
        "orders": ["ord-0001", "ord-0003", "ord-0006"],
        "_authz": {
            "decision": "allow",
            "action": 'Action::"orders.brief"',
            "resource": ORDERS,
            "principal": 'User::"alice"',
        },
    }


@pytest.mark.integration
def test_the_protected_callable_that_is_no_tool_is_offered_to_nobody(
    agent: Agent[Caller, str],
) -> None:
    """`summarize_orders` is in no principal's manifest, because it is registered as no tool.

    The companion to the test above, and the half that would rot silently: a registration
    added by accident would still make every assertion about the *decision* pass, while
    handing every model a tool the example says it was never offered.
    """
    for who in ("alice", "bob", "dana"):
        assert "summarize_orders" not in asyncio.run(offered_tools_for(agent, Caller(who)))


@pytest.mark.integration
def test_a_refusal_inside_the_nested_callable_travels_out_unchanged() -> None:
    """The README — "an inner refusal propagates out unchanged".

    Driven against a policy set that permits `orders.brief` and nothing else, because on the
    example's own policy alice may do both and the refusal is unreachable. What comes out of
    `brief_orders` is the *inner* `AuthzDenied`, still naming `Action::"orders.summarize"` —
    not a partial answer, not a re-wrapped outer refusal, and not the outer action.
    """
    permits_only_the_outer_call = (
        '@id("support-may-brief")\n'
        "permit (\n"
        '  principal in Role::"support",\n'
        '  action == Action::"orders.brief",\n'
        '  resource == Tool::"orders"\n'
        ");"
    )
    store = build_agent_grants()
    sentrykit.install(permits_only_the_outer_call, grant_store=store)
    alice = store.get_principal("alice")
    assert alice is not None

    with principal_context(alice), pytest.raises(sentrykit.AuthzDenied) as refusal:
        agent_brief_orders()

    assert refusal.value.action == 'Action::"orders.summarize"'
    assert refusal.value.resource == ORDERS


@pytest.mark.integration
def test_the_narrowed_search_returns_exactly_what_the_readme_prints(
    agent: Agent[Caller, str],
) -> None:
    """The README — "an allow-set, rejected and refilled".

    The envelope is asserted whole, because every field in it is a claim the README makes. The
    rows are asserted by count and by region instead of by value: ten customer names and ten
    totals would pin the seeder's own random choices to this test, which is a different
    contract from the one here, and the thing worth asserting about them is that the surviving
    bound decided how many came back and the refilled region decided which.
    """
    body = asyncio.run(propose(agent, Caller("alice"), "search_orders", region="cn", limit=5))

    assert body["region"] == "eu"
    assert body["limit"] == 5
    assert body["status"] == "open"
    assert body["count"] == 5
    assert len(body["orders"]) == 5
    assert {row["region"] for row in body["orders"]} == {"eu"}
    assert body["_authz"] == {
        "decision": "allow",
        "action": SEARCH,
        "resource": ORDERS,
        "principal": 'User::"alice"',
        "processed": {"limit": 5, "status": "open", "region": "eu"},
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
        # The outcome half of the envelope. ``region`` was proposed as "cn", rejected,
        # and refilled from alice's own default, so the call ran on a value she may use
        # and the guidance leads with "valid". ``limit=5`` survived untouched and is
        # therefore absent from ``narrowed_arguments``: narrowing is defined against the
        # proposal, not against ``rejected``.
        "narrowed": True,
        "narrowed_arguments": ["region"],
        "guidance": narrowing_guidance(["region"]),
    }


@pytest.mark.integration
def test_the_model_may_omit_both_arguments_and_gets_what_the_readme_prints(
    agent: Agent[Caller, str],
) -> None:
    """The README — "default injection", proposed by the *model*.

    The whole dict, because every part of it is a claim: the values, the empty proposal behind
    them, and `defaults_applied` naming `region` and `limit` and *not* `status` — which is the
    envelope distinguishing a value policy supplied from one Python had already answered for.
    """
    body = asyncio.run(propose(agent, Caller("alice"), "search_orders"))

    assert body["region"] == "eu"
    assert body["limit"] == 10
    assert body["status"] == "open"
    # Both defaults reached the call, and the one that is a bound decided the answer's size.
    assert body["count"] == 10
    assert len(body["orders"]) == 10
    assert body["_authz"] == {
        "decision": "allow",
        "action": SEARCH,
        "resource": ORDERS,
        "principal": 'User::"alice"',
        "processed": {"status": "open", "region": "eu", "limit": 10},
        "defaults_applied": {"region": "eu", "limit": 10},
    }


@pytest.mark.integration
def test_a_call_whose_every_argument_was_refused_is_itself_refused(
    agent: Agent[Caller, str],
) -> None:
    """The README — "narrowing refines a proposal, it does not rescue one".

    The README reaches this refusal through `issue_refund`, and the reason is a real property
    of the boundary rather than a choice of tool. Pydantic-AI materializes the advertised
    schema's defaults before dispatch, so a parameter carrying a Python default arrives as a
    proposed argument whether or not the model named it — and any tool that has one can never
    run out of surviving arguments. `issue_refund` has none, so both proposed values can be
    refused with nothing left behind them.

    `amount` has a default of 50 and does not rescue the call: a default fills a gap in a
    proposal, it does not stand in for one.
    """
    refused = asyncio.run(
        propose(agent, Caller("alice"), "issue_refund", order_id="refund-me", amount=900)
    )

    assert isinstance(refused, Mapping)
    assert refused["detail"] == "Every supplied argument was rejected by policy."
    assert refused["error"] == "NoValidArguments"
    envelope = refused["_authz"]
    assert [item["name"] for item in envelope["rejected"]] == ["order_id", "amount"]
    assert envelope["allowed"]["order_id"] == {
        "pattern": "ord-[0-9]{4}",
        "policy": "alice-order-id",
        "required": False,
        "has_default": False,
    }
    assert envelope["allowed"]["amount"]["maximum"] == 750
    assert envelope["allowed"]["amount"]["has_default"] is True
    # `allowed` is not an `AuthzEnvelope` field: its presence is the tell that this report was
    # built from the refusal rather than from a decision, which is also why it names no action.
    assert "action" not in envelope
    assert "resource" not in envelope


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

    assert correction == (
        "Unknown tool name: 'search_orders'. Available tools: 'desk_status', 'export_orders'"
    )


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
    """The README — "a policy that reads the proposed argument": csv allowed, pdf refused.

    The allocated ``job_id`` is matched by shape. Exporting books a row and takes the next id,
    so its exact value depends on what else booked one first in this process, and an
    assertion that has to be renumbered whenever a neighbouring test is added is one nobody
    will keep.
    """
    allowed = asyncio.run(propose(agent, Caller("bob"), "export_orders", fmt="csv"))

    assert re.fullmatch(r"exp-\d{4}", str(allowed.pop("job_id")))
    assert allowed == {
        "fmt": "csv",
        "scope": "open",
        "region": "eu",
        "rows": 81,
        "requested_by": "bob",
        "_authz": {
            "decision": "allow",
            "action": EXPORT,
            "resource": ORDERS,
            "principal": 'User::"bob"',
            "processed": {"fmt": "csv", "scope": "open"},
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
    """The README — "keyword-only and optional", and which parameters stay out of that set.

    The advertised schema *is* the mechanism: a model reads it and nothing else, so a
    parameter it marks `required` can never be omitted and no policy default for that
    parameter is ever reachable. The README names the split — `region`, `limit`, `fmt`,
    `amount`, `order_id` and `refund_id` are omittable, while `status` and `scope` keep their
    Python defaults — and it is the *contrast* that is the claim, so both halves are asserted
    on one tool: `search_orders` advertises no `required` list at all, `region` is nullable
    with a `None` default, and `status` is a plain string with its own default, untouched.
    """
    offered = {
        definition.name: definition.parameters_json_schema
        for caller in (Caller("alice"), Caller("bob"), Caller("dana"))
        for definition in _definitions_offered_to(agent, caller)
    }

    search = offered["search_orders"]
    assert "required" not in search
    assert search["properties"]["region"] == {
        "anyOf": [{"type": "string"}, {"type": "null"}],
        "default": None,
        "description": "Which region to search. Constrained per principal.",
    }
    assert search["properties"]["status"]["type"] == "string"
    assert search["properties"]["status"]["default"] == "open"

    export = offered["export_orders"]
    assert "required" not in export
    assert export["properties"]["fmt"]["anyOf"] == [{"type": "string"}, {"type": "null"}]
    assert export["properties"]["fmt"]["default"] is None
    assert export["properties"]["scope"] == {
        "default": "open",
        "description": (
            "Which orders to include. The caller's own business, so it keeps a Python\ndefault."
        ),
        "type": "string",
    }

    # A tool whose every parameter is policy-suppliable loses `required` too, which is what
    # makes a wholly refused proposal reachable at this boundary at all.
    refund = offered["issue_refund"]
    assert "required" not in refund
    assert sorted(refund["properties"]) == ["amount", "order_id", "region"]


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
    exact failure the fail-closed rule exists to prevent" — so a protected tool with no
    governor is a `ConfigurationError`, not a shrug.
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

DANA = {DEFAULT_PRINCIPAL_HEADER: "dana"}
"""The README's `DANA`, verbatim."""


@pytest.mark.integration
async def test_the_manifest_the_mcp_readme_prints_is_the_manifest_served() -> None:
    """The README — "The manifest is per-principal", all four printed lists.

    The anonymous list is the one that keeps the other three honest: no principal means no
    entitlement to anything, so the manifest is empty rather than unfiltered.
    """
    async with serving() as client:
        alice = await client.list_tools(meta=ALICE)
        bob = await client.list_tools(meta=BOB)
        dana = await client.list_tools(meta=DANA)
        anonymous = await client.list_tools(meta={})

    assert [tool.name for tool in alice.tools] == [
        "desk_status",
        "brief_orders",
        "search_orders",
        "read_order",
        "issue_refund",
    ]
    assert [tool.name for tool in bob.tools] == ["desk_status", "export_orders"]
    assert [tool.name for tool in dana.tools] == [
        "desk_status",
        "brief_orders",
        "search_orders",
        "read_order",
        "issue_refund",
        "approve_refund",
    ]
    assert [tool.name for tool in anonymous.tools] == []


@pytest.mark.integration
async def test_one_dispatch_of_brief_orders_writes_the_two_records_the_mcp_readme_prints() -> None:
    """The README — "One dispatch, two audit records, the outer one written **before** the
    body ran".

    Two protected callables entered in one dispatch means two decisions and two records, and
    their order is the claim rather than a detail: the gate refuses a side effect *before* it
    happens, so the outer record cannot wait for the body to finish. Only the delta this one
    dispatch appended is read — a ``tools/list`` probe decides every tool and writes records of
    its own, and counting those would make the assertion about the harness instead.

    ``summarize_orders`` is registered as no tool and still has a record of its own, which is
    the audit trail agreeing with the manifest about what happened rather than about what was
    advertised.
    """
    sink = InMemoryAuditSink()

    async with mcp.Client(create_server(audit_sink=sink)) as client:
        mark = len(sink.records)
        result = await client.call_tool("brief_orders", {}, meta=ALICE)
        written = sink.records[mark:]

    assert result.is_error is not True
    assert [record.action for record in written] == [
        'Action::"orders.brief"',
        'Action::"orders.summarize"',
    ]
    assert [record.decision for record in written] == ["allow", "allow"]
    assert [record.callable_name for record in written] == [
        "examples.fastmcp_server.service.brief_orders",
        "examples.fastmcp_server.service.summarize_orders",
    ]


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
async def test_the_bare_protect_is_served_under_the_derived_ids_the_mcp_readme_prints() -> None:
    """The README — "The bare `@protect`": the action *and* the resource, both derived.

    `desk_status` declares neither, so both come from the callable's import path and the
    reviewed policy has to name that exact string. Which is the fragility the README warns
    about, and the reason to pass an explicit `action=` as soon as the policy is expected to
    outlive the module layout: moving the function changes the id and the permit stops
    matching, with nothing to say so.
    """
    async with serving() as client:
        result = await client.call_tool("desk_status", {}, meta=ALICE)

    envelope = body_of(result)["_authz"]
    assert result.is_error is not True
    assert envelope["action"] == 'Action::"examples.fastmcp_server.service.desk_status"'
    assert envelope["resource"] == 'Resource::"examples.fastmcp_server.service.desk_status"'


@pytest.mark.integration
async def test_the_reviewed_ceiling_prints_what_the_mcp_readme_says_it_does() -> None:
    """The README — "The reviewed ceiling, and why the answer is not the ceiling".

    Dana asks for 500, the ceiling declared in `policies/10-orders.cedar` is 100, and she runs
    with **25**. The rejection is asserted whole because its `policy` is the load-bearing part:
    `support-may-search` names the reviewed file, which is what distinguishes a ceiling refusal
    from a grant one. Nothing was clamped — a refused value is discarded and the principal's
    own default takes its place.
    """
    async with serving() as client:
        result = await client.call_tool(
            "search_orders", {"limit": 500, "status": "open"}, meta=DANA
        )

    body = body_of(result)
    assert body["limit"] == 25
    assert body["_authz"]["rejected"] == [
        {
            "name": "limit",
            "rule": "maximum",
            "reason": "Value is above the maximum of 100",
            "policy": "support-may-search",
            "value": 500,
        }
    ]
    assert body["_authz"]["defaults_applied"] == {"limit": 25, "region": "eu"}


@pytest.mark.integration
async def test_the_two_argument_rules_print_what_the_mcp_readme_says_they_do() -> None:
    """The README — "Two arguments that are only wrong together" and the desk limit.

    Three claims the README makes as one story. `region="uk"` and `amount=750` are each within
    alice's grants and the pair is refused anyway, by a rule no per-argument bound could
    express. Push past the desk limit and a *different* `forbid` refuses, this one reading the
    proposed amount together with the principal — so the identical call is permitted for dana.
    Both refusals name the `forbid` that fired, because a `forbid` that fires is determining.
    """
    order: dict[str, Any] = {"order_id": "ord-0007"}

    async with serving() as client:
        # After the server is built, not before: `create_server` calls `configure()` itself,
        # so a verbosity set beforehand would be the one this line was meant to replace.
        sentrykit.configure(verbosity="debug")
        call = partial(client.call_tool, "issue_refund")
        fine = await call(order | {"amount": 100, "region": "uk"}, meta=ALICE)
        pair = await call(order | {"amount": 750, "region": "uk"}, meta=ALICE)
        over = await call(order | {"amount": 5000, "region": "eu"}, meta=ALICE)
        admin = await call(order | {"amount": 5000, "region": "eu"}, meta=DANA)

    assert fine.is_error is not True
    assert body_of(fine)["region"] == "uk"
    assert pair.is_error is True
    assert body_of(pair)["_authz"]["determining_policies"] == ["no-large-cross-region-refunds"]
    assert over.is_error is True
    assert body_of(over)["_authz"]["determining_policies"] == [
        "refunds-above-the-desk-limit-need-an-admin"
    ]
    assert admin.is_error is not True
    assert body_of(admin)["amount"] == 5000


@pytest.mark.integration
async def test_the_two_refusals_that_are_not_the_gate_print_what_the_mcp_readme_says() -> None:
    """The README — "Two refusals that are not the gate", both shapes and both text lines.

    Both come from the argument layer after the gate said yes, so neither names an action or a
    resource: there was no denied decision to name. `NoValidArguments` carries an `allowed`
    block describing what alice may pass instead — the thing a model needs in order to retry,
    and the tell that a report was built from a refusal rather than from a decision.
    `DefaultUnavailable` is the other shape: `amount` survived, so the call was not refused for
    want of arguments; the one that failed simply had no answer available.
    """
    async with serving() as client:
        nothing_left = await client.call_tool(
            "issue_refund", {"order_id": "refund-me", "amount": 900}, meta=ALICE
        )
        no_refill = await client.call_tool(
            "issue_refund", {"order_id": "refund-me", "amount": 100, "region": "eu"}, meta=ALICE
        )

    refused = body_of(nothing_left)
    assert refused["error"] == "NoValidArguments"
    assert nothing_left.content[0].text == "Every supplied argument was rejected by policy."
    assert [item["name"] for item in refused["_authz"]["rejected"]] == ["order_id", "amount"]
    assert sorted(refused["_authz"]["allowed"]) == ["amount", "order_id", "region"]
    assert "action" not in refused["_authz"]

    unavailable = body_of(no_refill)
    assert unavailable["error"] == "DefaultUnavailable"
    assert no_refill.content[0].text == (
        "Argument 'order_id' is required and no policy default is configured."
    )
    assert unavailable["_authz"]["rejected"] == [
        {"name": "order_id", "reason": "No policy default is configured."}
    ]
    assert "action" not in unavailable["_authz"]


@pytest.mark.integration
async def test_a_schema_default_reaches_the_decorator_even_when_the_caller_named_none() -> None:
    """The README's boundary note: mcp materializes a schema default before dispatch.

    So `export_orders(fmt="xml")` narrows here rather than running out of arguments — `scope`
    carries a Python default, is advertised with it, and arrives as a proposed argument
    whichever way the caller wrote the call. The two proposals below are byte-for-byte
    different and reach the decorator identically.

    A web route forwards only what the caller sent, so the same lone `fmt="xml"` is a
    `NoValidArguments` refusal there. That is a real difference between the boundaries rather
    than a disagreement about the rule, and both are pinned as they are.

    An *omittable* parameter is advertised as nullable instead, which is how an omission stays
    an omission across the wire: `fmt` left out entirely lands in `defaults_applied` and in no
    rejection at all.
    """
    async with serving() as client:
        alone = await client.call_tool("export_orders", {"fmt": "xml"}, meta=BOB)
        beside = await client.call_tool("export_orders", {"fmt": "xml", "scope": "open"}, meta=BOB)
        omitted = await client.call_tool("export_orders", {"scope": "open"}, meta=BOB)

    assert alone.is_error is not True
    # Compared without the booked job's id. Each call writes its own export row and takes the
    # next id in sequence, so two calls can agree about every argument -- which is the claim
    # here -- while disagreeing about which row they created.
    assert _without_job_id(body_of(alone)) == _without_job_id(body_of(beside))
    assert body_of(alone)["fmt"] == "csv"
    assert body_of(alone)["scope"] == "open"
    assert body_of(alone)["_authz"]["rejected"][0]["rule"] == "deny-set"
    assert body_of(alone)["_authz"]["defaults_applied"] == {"fmt": "csv"}

    assert body_of(omitted)["_authz"]["defaults_applied"] == {"fmt": "csv"}
    assert "rejected" not in body_of(omitted)["_authz"]


@pytest.mark.integration
async def test_the_mcp_readme_argument_filtering_prints_what_it_says() -> None:
    """The README — "Argument filtering": `-> eu 5`, the exact rejection, the exact default.

    Also pins the second "detail worth copying": the caller's own proposal reaches the
    decorator untouched, which is why `cn` is in `rejected` at all rather than having been
    quietly overwritten before the decision.
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
        result = await client.call_tool("read_order", {"order_id": "ord-0003"}, meta=BOB)

    body = body_of(result)
    assert result.is_error is True
    assert body["error"] == "AuthzDenied"
    assert body["_authz"]["resource"] == 'Order::"ord-0003"'


@pytest.mark.integration
async def test_the_multi_hop_read_the_mcp_readme_showcases() -> None:
    """The README — "Four hops, resolved by Cedar": `-> False ord-0003`, then `-> allow`."""
    async with serving() as client:
        result = await client.call_tool("read_order", {"order_id": "ord-0003"}, meta=ALICE)

    body = body_of(result)
    assert result.is_error is not True
    assert body["order_id"] == "ord-0003"
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
        refused = await severed.call_tool("read_order", {"order_id": "ord-0003"}, meta=ALICE)
        listed = await severed.list_tools(meta=ALICE)
        still_allowed = await severed.call_tool("search_orders", {}, meta=ALICE)

    assert refused.is_error is True
    assert body_of(refused)["error"] == "AuthzDenied"
    assert [tool.name for tool in listed.tools] == [
        "desk_status",
        "brief_orders",
        "search_orders",
        "issue_refund",
    ]
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

    @mcp_governed_tool(server, action='Action::"orders.read"', resource='Order::"ord-0003"')
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
    """Pins the module docstring's warning and `docs/agents.md`'s admonition.

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
# The page a reader arrives at before either README. `test_documented_examples_web.py` pins
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
        hidden_called_anyway = await client.call_tool(
            "read_order", {"order_id": "ord-0003"}, meta=BOB
        )
        offered_and_run = await client.call_tool("read_order", {"order_id": "ord-0003"}, meta=ALICE)

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
def test_with_no_daemon_reachable_both_examples_run_on_a_deterministic_model(
    agent: Agent[Caller, str],
) -> None:
    """With no daemon reachable, both agent examples fall back to a deterministic model.

    Which is also the guarantee this whole suite rests on, so it is pinned rather than
    assumed. Both examples ask `examples.ollama.choose_model()` whether a local model is
    within reach, and on a machine running a daemon the honest answer is *yes* — so a suite
    that let them ask would drive one example against whatever model that laptop happened to
    have pulled. `examples.ollama` documents the off switch for exactly this: setting
    `SENTRYKIT_OLLAMA_URL` to an empty value returns before any socket is opened. The root
    `conftest` sets it for every test, and this is the test that notices if it stops working.

    The MCP example asks the same question through the same module, so `choose_model()`
    answering `None` covers both. Its client speaks to the server over an in-memory transport
    and has no model of its own, which every other test here demonstrates by not opening a
    socket.
    """
    assert ollama.endpoint() == ""
    assert ollama.choose_model() is None
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


# --- what `pixi run -e agent run-agent` prints -------------------------------------------------
#
# `docs/agents.md` reproduces five of the example's printed blocks. Each is pinned by running
# the section that prints it and reading the block back out of the page, rather than by
# transcribing it here: a transcription agrees with itself forever, and what has to hold is
# that the page and the program say the same thing.


AGENTS_PAGE = Path("docs/agents.md")
"""The page these tests pin, read rather than transcribed."""


def page_block(opens_with: str) -> list[str]:
    """Return the non-blank lines of the one page block whose first line starts as given.

    Args:
        opens_with: How the block's first line begins.

    Returns:
        The block's lines, blanks dropped so the page's own spacing is not the assertion.

    Raises:
        AssertionError: If the page carries no such block, or more than one.
    """
    text = AGENTS_PAGE.read_text(encoding="utf-8")
    blocks = [
        block
        for block in re.findall(r"^```[a-z]*\n(.*?)^```", text, re.S | re.M)
        if block.lstrip().startswith(opens_with)
    ]
    assert len(blocks) == 1, f"agents.md has {len(blocks)} blocks opening with {opens_with!r}"
    return [line for line in blocks[0].splitlines() if line.strip()]


def printed_by(
    section: Callable[[Agent[Caller, str]], Coroutine[Any, Any, None]], agent: Agent[Caller, str]
) -> list[str]:
    """Run one section of the example's self-drive and return the lines it printed.

    Args:
        section: The example's ``show_*`` coroutine function.
        agent: The agent it drives.

    Returns:
        The captured lines with the section banner and the blanks dropped, so what is left is
        what the page reproduces.
    """
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        asyncio.run(section(agent))
    lines = [line for line in captured.getvalue().splitlines() if line.strip()]
    return [line for line in lines if not line.startswith("===")]


@pytest.mark.integration
def test_the_flow_table_the_agents_page_prints_is_the_table_run_agent_prints(
    agent: Agent[Caller, str],
) -> None:
    """`docs/agents.md` — "Every flow, decided": every row, including the three starred ones.

    Twenty-two rows covering the whole decision surface at an agent boundary, so one equality
    here stands in for a page-sized list of literals. The `*` on flows 8, 14 and 22 is the part
    that could rot silently: it marks a tool hidden from that principal, dispatched by name
    with no model in the loop, and it is the page's evidence for the second half of the
    filtering guarantee. A tool that stopped being hidden would still be refused, and the row
    would still read `denied` — only the marker would be wrong.
    """
    page = page_block("#  who")

    printed = printed_by(show_flows, agent)

    assert len(page) == 23, "one header and 22 flows"
    assert printed[: len(page)] == page
    assert [row[:4] for row in page if row[3:4] == "*"] == ["  8*", " 14*", " 22*"]


@pytest.mark.integration
def test_the_ceiling_block_the_agents_page_prints_is_what_run_agent_prints(
    agent: Agent[Caller, str],
) -> None:
    """`docs/agents.md` — "The ceiling, and why the answer is never the ceiling", all three lines.

    The three lines are one argument: she asked for 500, the reviewed bound is 100, and she ran
    with 25. The last is the load-bearing one, and it is load-bearing *because* of the other
    two — a page that printed only the answer would be indistinguishable from a page describing
    a clamp.
    """
    page = page_block("dana proposed")

    printed = printed_by(show_ceiling, agent)

    assert printed[: len(page)] == page
    assert page == [
        "dana proposed limit=500.",
        "The ceiling declared in policies/10-orders.cedar is 100.",
        "She ran with limit=25, which is her own default.",
    ]


@pytest.mark.integration
def test_the_nesting_block_the_agents_page_prints_is_what_run_agent_prints(
    agent: Agent[Caller, str],
) -> None:
    """`docs/agents.md` — "a protected callable that is not a tool": the outer and inner lines.

    One dispatch, two decisions. The inner action is the one no model was ever offered and none
    could propose, and it is named here because it was decided all the same.
    """
    page = page_block("outer")

    printed = printed_by(show_nesting, agent)

    assert printed[: len(page)] == page
    assert page == [
        'outer  Action::"orders.brief"  allow',
        'inner  Action::"orders.summarize"  allow',
    ]


@pytest.mark.integration
def test_the_debug_block_the_agents_page_prints_is_what_run_agent_prints(
    agent: Agent[Caller, str],
) -> None:
    """`docs/agents.md` — "Both refusals are **named**": the three-line `debug` block.

    The absence on the third line is the assertion. Flows 13 and 18 each tripped a `forbid`,
    and a `forbid` that fires is determining, so each carries its policy id in brackets. Flow
    14 matched no permit at all, so nothing was determining and there is no bracket — reporting
    one would be inventing a rule that never ran.
    """
    page = page_block("13  bob")

    printed = printed_by(show_who_decided, agent)

    assert printed[: len(page)] == page
    assert page[0].endswith("[no-pdf-exports]")
    assert page[1].endswith("[refunds-above-the-desk-limit-need-an-admin]")
    assert page[2].endswith('denied: The policy denied action Action::"orders.search".')
    assert "[" not in page[2]


@pytest.mark.integration
def test_the_fallback_banner_the_agents_page_prints_is_what_run_agent_prints(
    agent: Agent[Caller, str],
) -> None:
    """`docs/agents.md` — The optional live model: the two lines printed with no model in play.

    Which is also the switch this whole suite rests on. An empty `SENTRYKIT_OPENROUTER_URL` or
    `SENTRYKIT_OLLAMA_URL` is the documented way to turn a tier off outright, the root
    `conftest` sets both for every test and empties the key besides, and this is the banner a
    reader gets when they reach for it themselves. No socket is opened to produce either line.

    The second line names *both* tiers, and it has to: "no model" has two independent causes and
    a reader who turned one off still wants to know what happened to the other. It also has to
    be the same sentence on every machine, which is why the fixture empties the key rather than
    leaving `.env` to decide what this test expects.
    """
    page = page_block("model: TestModel")

    printed = printed_by(show_free_form, agent)

    assert printed[: len(page)] == page
    assert page == [
        "model: TestModel",
        "  -- no OPENROUTER_API_KEY is set, and locally the search for one is turned off "
        "(SENTRYKIT_OLLAMA_URL is set to an empty value)",
    ]


# --- the page's own MCP snippets ---------------------------------------------------------------


@pytest.mark.integration
async def test_the_agents_page_prints_flow_five_and_flow_three_as_the_server_answers_them() -> None:
    """`docs/agents.md` — "Several arguments decided in one call", both halves of it.

    Flow 5 is the page's snippet: `limit` proposed, rejected and refilled; `region` never
    proposed and injected; `status` left alone because no constraint governs it. Flow 3 is the
    sentence under it — the model proposes nothing, both governed arguments turn up in
    `defaults_applied` and neither in `rejected`, and `processed` comes out identical. That
    identity is the claim worth pinning: the two calls end in the same place by different
    routes, and only the envelope says which route was taken.
    """
    async with serving() as client:
        proposed = await client.call_tool(
            "search_orders", {"limit": 500, "status": "open"}, meta=ALICE
        )
        omitted = await client.call_tool("search_orders", {}, meta=ALICE)

    narrowed = body_of(proposed)["_authz"]
    defaulted = body_of(omitted)["_authz"]

    assert narrowed["processed"] == {"status": "open", "region": "eu", "limit": 10}
    assert narrowed["rejected"][0]["reason"] == "Value is above the maximum of 50"
    assert narrowed["defaults_applied"] == {"region": "eu", "limit": 10}

    assert defaulted["processed"] == narrowed["processed"]
    assert defaulted["defaults_applied"] == {"region": "eu", "limit": 10}
    assert "rejected" not in defaulted


@pytest.mark.integration
def test_the_boundary_note_holds_on_the_pydantic_ai_boundary_too(
    agent: Agent[Caller, str],
) -> None:
    """`docs/agents.md` — "A parameter with a Python default arrives whether or not the model
    proposed it", which the page states of *both* agent boundaries and shows on one.

    So the unshown half is the one asserted here. `export_orders(fmt="xml")` is a
    `NoValidArguments` refusal at a web boundary and a narrowed call at both agent ones, for the
    same reason in both: `scope` carries a Python default, is advertised with it, and arrives as
    a proposed argument that survives filtering. The MCP half is pinned beside the fastmcp
    README; if these two ever disagreed, the page's "both frameworks" would be wrong.
    """
    narrowed = asyncio.run(propose(agent, Caller("bob"), "export_orders", fmt="xml"))

    assert isinstance(narrowed, Mapping)
    assert "error" not in narrowed
    assert narrowed["_authz"]["processed"] == {"scope": "open", "fmt": "csv"}
    assert narrowed["_authz"]["rejected"][0]["rule"] == "deny-set"


# --- the counts the page and the README both state ---------------------------------------------


@pytest.mark.integration
def test_both_agent_examples_hold_the_flows_and_the_tools_the_page_counts() -> None:
    """`docs/agents.md` — "Seven governed tools, plus one protected callable that is
    deliberately registered as no tool at all"; and the README's "22-flow table".

    The page also says the MCP server "prints the same 22 flows in its own format", which is a
    claim about two independently written tables, so it is checked as one: the same principal,
    the same tool and the same proposed arguments, row for row. A flow added to one example and
    not the other would leave both tables 22 rows long and the sentence wrong.
    """
    registered = sorted(registered_tools(create_server()))
    protected = sorted(
        name
        for name, value in vars(mcp_service).items()
        if callable(value) and sentrykit.is_protected(value)
    )

    assert len(AGENT_FLOWS) == 22
    assert len(MCP_FLOWS) == 22
    assert [(flow.principal, flow.fn.__name__, dict(flow.arguments)) for flow in AGENT_FLOWS] == [
        (principal, tool, dict(arguments)) for principal, tool, arguments, _ in MCP_FLOWS
    ]
    assert len(registered) == 7
    assert protected == sorted([*registered, "summarize_orders"])
