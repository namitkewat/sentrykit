"""The Pydantic-AI provider, driven by deterministic local models on the example agent.

No live model and no API key anywhere: :class:`~pydantic_ai.models.function.FunctionModel`
scripts the exact tool call a test needs and reports back the exact tool manifest the model
was offered, and :class:`~pydantic_ai.models.test.TestModel` calls whatever it is shown.
Those two are the right pair — one gives control of the *proposal*, the other makes the
*manifest* observable through the output.

What is peculiar to this integration, and what these tests are mostly about:

* **On-behalf-of.** The principal is the human named in ``deps``, resolved per run. Two runs
  of one agent object, on one model, with two different callers get two different answers —
  which is only true if nothing about the principal is bound at registration time.
* **`prepare` is `tools/list`.** The manifest is narrowed per run, by the same gate that
  enforces dispatch, and the hidden-implies-denied invariant
  (:mod:`sentrykit.integrations.tools`) is asserted from both ends.
* **A refusal is data.** It comes back as the tool's *result*, so the run continues and the
  model can adapt, rather than as an exception that aborts the run and tells the user nothing.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from examples.pydantic_ai_agent.agent import Caller, build_agent
from examples.pydantic_ai_agent.policy import POLICY_TEXT, build_grants
from examples.pydantic_ai_agent.service import export_orders as service_export_orders
from examples.pydantic_ai_agent.service import search_orders as service_search_orders
from pydantic_ai import Agent, RunContext, ToolDefinition
from pydantic_ai.messages import (
    ModelMessage,
    ModelResponse,
    RetryPromptPart,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel
from pydantic_ai.usage import RunUsage

import sentrykit
from sentrykit.decorator import protect
from sentrykit.integrations.pydantic_ai import (
    PydanticAIProvider,
    governed_tool,
    tool_adapter,
    tool_prepare,
)

Script = Callable[[Sequence[ModelMessage], AgentInfo], ModelResponse]
"""What a :class:`FunctionModel` is: one function standing in for a model's whole turn."""


def proposing(tool: str, arguments: dict[str, Any]) -> Script:
    """Build a model that proposes one specific tool call and then stops.

    The two things a live model would decide — *which* tool and *which* arguments — are fixed
    here, so a test's subject is the authorization of a proposal rather than a model's taste
    in proposals. The second turn answers with plain text whether the first turn produced a
    tool result or a retry prompt; without the retry case a proposal the model was not offered
    would loop until Pydantic-AI gave up.

    Args:
        tool: The tool to propose.
        arguments: The arguments to propose.

    Returns:
        The model function.
    """

    def script(messages: Sequence[ModelMessage], info: AgentInfo) -> ModelResponse:
        """Propose the call on the first turn; wrap up once anything has come back."""
        answered = any(
            isinstance(part, ToolReturnPart | RetryPromptPart)
            for message in messages
            for part in message.parts
        )
        if answered:
            return ModelResponse(parts=[TextPart("noted")])
        return ModelResponse(parts=[ToolCallPart(tool, dict(arguments))])

    return script


def run_context(caller: Caller | None, *, tool: str = "search_orders") -> RunContext[Any]:
    """Build the run context one tool dispatch is handed, without running an agent.

    What the provider actually reads off it is ``deps``, ``run_id``, ``tool_name`` and
    ``tool_call_id``; the rest is Pydantic-AI's own bookkeeping. Constructing it directly is
    how a test reaches a *single* dispatch — a run would give the model a say in how many
    there were.

    Args:
        caller: The run's ``deps``.
        tool: The tool name the dispatch is for.

    Returns:
        The run context.
    """
    return RunContext(
        deps=caller,
        model=TestModel(),
        usage=RunUsage(),
        tool_name=tool,
        tool_call_id="call-1",
        run_id="run-1",
    )


def offered_tools(agent: Agent[Caller, str], caller: Caller | None) -> list[str]:
    """Run the agent once and report which tools the model was offered for ``caller``.

    The ``prepare`` hooks run as part of building the request, so the manifest is only
    observable from inside a real run. The model proposes nothing, so nothing is dispatched
    and this is a pure manifest probe.

    Args:
        agent: The agent under test.
        caller: The run's ``deps``.

    Returns:
        The tool names offered.
    """
    seen: list[list[str]] = []

    def script(messages: Sequence[ModelMessage], info: AgentInfo) -> ModelResponse:
        """Record the manifest and answer with plain text, proposing no call."""
        seen.append([definition.name for definition in info.function_tools])
        return ModelResponse(parts=[TextPart("nothing to do")])

    agent.run_sync("what can you do?", deps=caller, model=FunctionModel(script))
    return seen[0]


def run_tool(
    agent: Agent[Caller, str],
    caller: Caller | None,
    tool: str,
    arguments: dict[str, Any],
) -> Any:
    """Drive one scripted tool call through a whole run and return what came back to the model.

    A dispatched tool answers with a ``ToolReturnPart`` — its result, refusal payload included.
    A tool the run never offered answers with a ``RetryPromptPart`` instead, because
    Pydantic-AI rejects the proposal before any adapter sees it; returning that too is what
    lets a test tell "refused by policy" from "was never in the manifest".

    Args:
        agent: The agent under test.
        caller: The run's ``deps`` — the human the agent is acting for.
        tool: The tool the model proposes.
        arguments: The arguments it proposes.

    Returns:
        The tool's return value, or the retry prompt's content.
    """
    result = agent.run_sync("do it", deps=caller, model=FunctionModel(proposing(tool, arguments)))
    for message in result.all_messages():
        for part in message.parts:
            if isinstance(part, ToolReturnPart | RetryPromptPart):
                return part.content
    raise AssertionError(f"nothing came back from proposing {tool}({arguments})")


@pytest.fixture
def agent() -> Agent[Caller, str]:
    """A freshly built example agent.

    Built per test rather than imported: ``build_agent()`` calls ``install()``, and the root
    ``conftest`` tears it down between tests — so an agent built once at import time would be
    registering tools against a governor that no longer exists.
    """
    return build_agent()


@pytest.fixture
def unfiltered_agent() -> Agent[Caller, str]:
    """The example's two tools, registered with the manifest filter turned off.

    ``filter_manifest=False`` is a supported configuration for a server that would rather
    advertise one stable manifest to everybody. It is used here because it is the only way to
    put an unentitled proposal *in front of the gate*: with filtering on, Pydantic-AI rejects a
    tool the run never offered, and the refusal a test would see would be the framework's, not
    sentrykit's.
    """
    store = build_grants()
    sentrykit.configure(verbosity="verbose")
    sentrykit.install(POLICY_TEXT, grant_store=store)
    provider = PydanticAIProvider(grants=store)

    built: Agent[Caller, str] = Agent(TestModel(), deps_type=Caller)
    register = governed_tool(built, provider=provider, filter_manifest=False)
    register(service_search_orders)
    register(service_export_orders)
    return built


# --- on-behalf-of ----------------------------------------------------------------------------


@pytest.mark.integration
def test_a_run_is_authorized_as_the_human_the_agent_acts_for(agent: Agent[Caller, str]) -> None:
    """The principal on the decision is alice, not an identity for the agent process.

    Nothing in the agent, the model or the tool named a principal; the run's ``deps`` did, and
    the envelope reports the entity Cedar actually decided about. That is the whole claim.
    """
    body = run_tool(agent, Caller("alice"), "search_orders", {"region": "uk", "limit": 5})

    assert body["region"] == "uk"
    assert body["limit"] == 5
    assert body["_authz"]["decision"] == "allow"
    assert body["_authz"]["principal"] == 'User::"alice"'


@pytest.mark.integration
async def test_policy_defaults_fill_the_arguments_the_caller_never_proposed() -> None:
    """``search_orders`` declares no Python defaults, so both values came from alice's grants.

    Driven at the adapter rather than through a run, and that is not a shortcut: Pydantic-AI
    validates a proposal against the advertised schema *before* dispatch, so a model cannot
    omit a required parameter at all. Host code can, and this is the path on which an argument
    is genuinely unproposed — which is the only way "policy decided it" is distinguishable
    from "the function's own default decided it".
    """
    store = build_grants()
    sentrykit.configure(verbosity="verbose")
    sentrykit.install(POLICY_TEXT, grant_store=store)

    adapter = tool_adapter(service_search_orders, provider=PydanticAIProvider(grants=store))
    body = await adapter(run_context(Caller("alice")))

    assert body["region"] == "eu"
    assert body["limit"] == 10
    assert body["_authz"]["decision"] == "allow"
    assert set(body["_authz"]["defaults_applied"]) == {"region", "limit"}


@pytest.mark.integration
def test_the_principal_is_per_run_and_not_bound_to_the_agent(agent: Agent[Caller, str]) -> None:
    """One agent object, one model, two callers, two disjoint capabilities.

    Alice's run searches and cannot export; bob's exports and cannot search. Nothing about
    either principal was decided when the tools were registered, so the difference can only
    have come from ``deps`` — which is what "per run" means.
    """
    alice_may = run_tool(agent, Caller("alice"), "search_orders", {"region": "uk", "limit": 5})
    bob_may = run_tool(agent, Caller("bob"), "export_orders", {"fmt": "csv"})

    assert alice_may["_authz"]["decision"] == "allow"
    assert alice_may["_authz"]["principal"] == 'User::"alice"'
    assert bob_may["fmt"] == "csv"
    assert bob_may["_authz"]["principal"] == 'User::"bob"'
    assert "search_orders" not in offered_tools(agent, Caller("bob"))
    assert "export_orders" not in offered_tools(agent, Caller("alice"))


@pytest.mark.integration
def test_a_narrowed_argument_is_reported_rather_than_silently_substituted(
    agent: Agent[Caller, str],
) -> None:
    """The model proposed ``cn``; the tool ran on ``eu`` and the envelope says which.

    Silence here would be the worst outcome: the model would report to its user that it had
    searched China.
    """
    sentrykit.configure(verbosity="verbose")

    body = run_tool(agent, Caller("alice"), "search_orders", {"region": "cn", "limit": 5})

    assert body["region"] == "eu"
    assert body["limit"] == 5
    rejections = body["_authz"]["rejected"]
    assert [item["name"] for item in rejections] == ["region"]
    assert rejections[0]["value"] == "cn"


# --- forbid beats permit ---------------------------------------------------------------------


@pytest.mark.integration
def test_a_forbid_on_one_argument_value_beats_the_permit_that_allowed_the_action(
    agent: Agent[Caller, str],
) -> None:
    """Bob may export, and still may not export a PDF — Cedar's forbid always wins.

    Both formats are exercised in one test so the refusal cannot be read as "bob may not
    export at all".
    """
    refused = run_tool(agent, Caller("bob"), "export_orders", {"fmt": "pdf"})
    allowed = run_tool(agent, Caller("bob"), "export_orders", {"fmt": "csv"})

    assert refused["error"] == "AuthzDenied"
    assert refused["_authz"]["decision"] == "deny"
    assert allowed["fmt"] == "csv"


# --- the per-run manifest, and the invariant that it is not the enforcement --------------------


@pytest.mark.integration
def test_the_manifest_offered_to_the_model_is_narrowed_per_run(agent: Agent[Caller, str]) -> None:
    """``prepare`` is Pydantic-AI's ``tools/list``, and it answers per ``deps``.

    ``search_orders`` is offered to alice and absent for bob, with everything else about the
    two runs identical.
    """
    for_alice = offered_tools(agent, Caller("alice"))
    for_bob = offered_tools(agent, Caller("bob"))

    assert "search_orders" in for_alice
    assert "search_orders" not in for_bob
    assert "export_orders" in for_bob


@pytest.mark.integration
async def test_a_hidden_tool_is_still_refused_when_the_model_proposes_it_anyway() -> None:
    """The other half of the invariant, driven straight at the registered adapter.

    :func:`~sentrykit.integrations.pydantic_ai.tool_adapter` builds exactly the callable
    ``governed_tool`` registers, so calling it with a hand-made
    :class:`~pydantic_ai.RunContext` is a caller that skipped the manifest entirely. Hiding is
    a usability affordance; the gate below it is the access control.
    """
    store = build_grants()
    sentrykit.install(POLICY_TEXT, grant_store=store)
    provider = PydanticAIProvider(grants=store)

    @protect(action='Action::"orders.search"', resource='Tool::"orders"')
    def search_orders(region: str, limit: int) -> dict[str, object]:
        """Search orders. Never reached for bob."""
        return {"region": region, "limit": limit}

    adapter = tool_adapter(search_orders, provider=provider)
    hidden = tool_prepare(search_orders, provider=provider)
    bob = run_context(Caller("bob"))

    manifest_answer = await hidden(bob, ToolDefinition(name="search_orders"))
    dispatched = await adapter(bob)

    assert manifest_answer is None, "bob may not search, so the tool must be hidden"
    assert dispatched["error"] == "AuthzDenied"
    assert dispatched["_authz"]["decision"] == "deny"


@pytest.mark.integration
def test_a_tool_the_principal_may_invoke_is_never_hidden(agent: Agent[Caller, str]) -> None:
    """The *if* half. ``search_orders`` takes two arguments and has no Python defaults.

    A filter that read the argument-level refusal of an argument-free probe as a denial would
    hide it from everybody, alice included.
    """
    assert "search_orders" in offered_tools(agent, Caller("alice"))


@pytest.mark.integration
def test_the_model_is_shown_and_runs_only_what_its_caller_may_do(
    agent: Agent[Caller, str],
) -> None:
    """``TestModel`` calls every tool it is offered, so the output *is* the manifest.

    The end-to-end form of the invariant: whatever bob's model was allowed to try, it tried,
    and none of it was a search.
    """
    result = agent.run_sync("do everything", deps=Caller("bob"), model=TestModel())

    invoked = json.loads(result.output)
    assert "search_orders" not in invoked
    assert "export_orders" in invoked


# --- failing closed ----------------------------------------------------------------------------
#
# These run on ``unfiltered_agent`` on purpose. With the manifest filter on, an unentitled
# caller's proposal never reaches an adapter at all — Pydantic-AI rejects a tool it was not
# offered — so the *gate's* answer would be untestable through a run. Turning the filter off is
# a supported configuration and leaves enforcement completely intact, which is exactly the
# claim these three tests then check.


@pytest.mark.integration
def test_a_run_that_ignores_the_manifest_is_still_refused_by_the_gate(
    unfiltered_agent: Agent[Caller, str],
) -> None:
    """``filter_manifest=False``, so bob's model *is* offered the search — and still refused.

    The run-level statement of the invariant in :mod:`sentrykit.integrations.tools`: hiding a
    tool and refusing it are the same decision made twice, and removing the first one changes
    nothing about the second.
    """
    body = run_tool(unfiltered_agent, Caller("bob"), "search_orders", {"region": "uk", "limit": 5})

    assert body["error"] == "AuthzDenied"
    assert body["_authz"]["decision"] == "deny"


@pytest.mark.integration
def test_a_run_with_no_caller_fails_closed(unfiltered_agent: Agent[Caller, str]) -> None:
    """``deps=None`` is a legitimate state — an agent run with no human behind it.

    It is not an error at the boundary; it is a refusal a few frames later, which is the same
    fail-closed rule an unauthenticated HTTP request gets.
    """
    body = run_tool(unfiltered_agent, None, "search_orders", {"region": "uk", "limit": 5})

    assert body["error"] == "NoContext"
    assert body["_authz"]["decision"] == "deny"


@pytest.mark.integration
def test_a_caller_the_grant_store_never_heard_of_fails_closed(
    unfiltered_agent: Agent[Caller, str],
) -> None:
    """An id nobody granted anything to resolves to no principal, not to an empty one."""
    body = run_tool(
        unfiltered_agent, Caller("mallory"), "search_orders", {"region": "uk", "limit": 5}
    )

    assert body["error"] == "NoContext"


@pytest.mark.integration
def test_an_unknown_caller_is_offered_no_governed_tools(agent: Agent[Caller, str]) -> None:
    """Fail closed, applied to the manifest: no principal, no entitlement, nothing to show."""
    assert offered_tools(agent, None) == []


# --- the provider itself -------------------------------------------------------------------------


@pytest.mark.integration
def test_the_provider_refuses_to_narrow_a_request_from_another_framework() -> None:
    """A provider wired to the wrong boundary says so, naming both sides."""
    provider = PydanticAIProvider(grants=build_grants())

    with pytest.raises(sentrykit.ConfigurationError, match="wrong framework"):
        provider.narrow(object())


@pytest.mark.integration
def test_the_adapter_hides_ctx_from_the_schema_the_model_is_shown() -> None:
    """``ctx`` is the adapter's business and never a proposed argument.

    If it leaked into the tool definition, the model would try to fill it in, the Cedar request
    would carry it, and pydantic validation would reject the call — wrong three times over.
    """
    store = build_grants()
    sentrykit.install(POLICY_TEXT, grant_store=store)
    agent: Agent[Caller, str] = Agent(TestModel(), deps_type=Caller)

    @governed_tool(agent, provider=PydanticAIProvider(grants=store))
    @protect(action='Action::"orders.search"', resource='Tool::"orders"')
    def search_orders(region: str, limit: int = 5) -> dict[str, object]:
        """Search orders.

        Args:
            region: Which region to search.
            limit: How many orders to return.
        """
        return {"region": region, "limit": limit}

    seen: list[AgentInfo] = []

    def script(messages: Sequence[ModelMessage], info: AgentInfo) -> ModelResponse:
        """Capture the tool definitions and answer without proposing a call."""
        seen.append(info)
        return ModelResponse(parts=[TextPart("noted")])

    agent.run_sync("hello", deps=Caller("alice"), model=FunctionModel(script))

    definition = next(item for item in seen[0].function_tools if item.name == "search_orders")
    properties = definition.parameters_json_schema["properties"]
    assert "ctx" not in properties
    assert set(properties) == {"region", "limit"}
    assert properties["region"]["description"] == "Which region to search."


@pytest.mark.integration
def test_governed_tool_returns_the_function_unchanged_and_still_callable() -> None:
    """Registering a tool must not take the function away from the rest of the program."""
    store = build_grants()
    sentrykit.install(POLICY_TEXT, grant_store=store)
    agent: Agent[Caller, str] = Agent(TestModel(), deps_type=Caller)

    @governed_tool(agent, provider=PydanticAIProvider(grants=store))
    @protect(action='Action::"orders.search"', resource='Tool::"orders"')
    def search_orders(region: str, limit: int) -> dict[str, object]:
        """Search orders."""
        return {"region": region, "limit": limit}

    with sentrykit.establish(store.get_principal("alice")):  # type: ignore[arg-type]
        direct = search_orders()

    assert sentrykit.is_protected(search_orders)
    assert direct["region"] == "eu"
    assert direct["limit"] == 10
