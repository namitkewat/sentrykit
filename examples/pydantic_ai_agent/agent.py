"""A Pydantic-AI agent that acts *for* a human, and a policy that knows which human.

Run it with `pixi run -e agent run-agent`. It needs no API key and makes no network call: the
default model is `pydantic_ai.models.test.TestModel`, and the narrative is driven by
`pydantic_ai.models.function.FunctionModel`, which lets the example show **exactly which tools
the model was offered** rather than asserting it in prose. Set `SENTRYKIT_EXAMPLE_MODEL` to a
model name to point the free-form run at a real model instead.

## What it demonstrates

One agent, two registered tools, and two callers:

* `alice` is `support`. She may search orders, with a constrained `region` and a capped
  `limit`. `export_orders` is **not in the manifest her model is offered**.
* `bob` is `auditor`. He may export orders — but not as a PDF, which a `forbid` policy
  refuses by reading the proposed argument. `search_orders` is **not in the manifest his model
  is offered**, and calling it anyway is still refused.

The agent process has no identity of its own. Whoever the application names in `deps` is the
principal, and that is the whole of ADR-008: an agent acting for a human *is* that human. The
model cannot influence it — `deps` is supplied by the application at `run()` time and never
appears in anything the model can write.

## Nothing is wired at import

`build_agent()` calls `configure()` and `install()`, which mutate process-global state. A
module-level `agent = build_agent()` would run that wiring for anyone who so much as imported
the module — including a test collector, and including a second example app in the same
process. `pixi run -e agent run-agent` invokes `main()` through `__main__` instead, and every
test builds its own.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass

from pydantic_ai import Agent, RunContext
from pydantic_ai.messages import (
    ModelMessage,
    ModelResponse,
    RetryPromptPart,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
)
from pydantic_ai.models import Model, infer_model
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel
from pydantic_ai.usage import RunUsage

from examples.pydantic_ai_agent.policy import POLICY_TEXT, build_grants
from examples.pydantic_ai_agent.service import export_orders, search_orders
from sentrykit import configure, install
from sentrykit.integrations.pydantic_ai import PydanticAIProvider, governed_tool, tool_adapter

MODEL_ENV_VAR = "SENTRYKIT_EXAMPLE_MODEL"
"""Environment variable that opts the free-form run into a real model. Unset means offline."""

PROMPT = "Look at the orders you are allowed to look at."
"""The user turn. The scripted models ignore it; a real model does not."""


@dataclass(frozen=True)
class Caller:
    """The agent's dependencies — which is to say, whose behalf it is acting on.

    One field, on purpose. A richer application would carry a session, a tenant and a request
    id here and hand the provider an ``identify=`` callback to pick the principal out of them;
    the default provider reads the ``principal`` attribute, which is all this example needs.

    Attributes:
        principal: The **human** the agent is acting for. Never a service identity for the
            agent process — see ADR-008 and this module's docstring.
    """

    principal: str


def default_model() -> Model:
    """The model the agent runs on when the caller names none.

    Offline by default: an example that needed an API key to run would not be run. Setting
    :data:`MODEL_ENV_VAR` to a Pydantic-AI model name (``openai:gpt-4o``,
    ``anthropic:claude-sonnet-4-5``, …) opts into a real one, which is the only thing in this
    file that can reach the network.

    Returns:
        The inferred model when :data:`MODEL_ENV_VAR` is set, otherwise a ``TestModel`` that
        calls every visible tool and reports what they returned.
    """
    named = os.environ.get(MODEL_ENV_VAR)
    return infer_model(named) if named else TestModel()


def build_agent(model: Model | None = None) -> Agent[Caller, str]:
    """Wire settings, grants, policy, the provider and the two governed tools into one agent.

    Args:
        model: The model to run on. Defaults to :func:`default_model`.

    Returns:
        The agent, with both tools registered, each governed and each hidden from any run
        whose principal could not invoke it.
    """
    # ``verbose`` so the ``_authz`` envelope actually carries processed values, applied
    # defaults and rejection reasons — the model is one of the audiences for that explanation.
    # A production agent would leave this at ``summary``.
    configure(verbosity="verbose")

    store = build_grants()
    provider = PydanticAIProvider(grants=store)
    install(POLICY_TEXT, grant_store=store, context_provider=provider)

    agent: Agent[Caller, str] = Agent(model or default_model(), deps_type=Caller)
    # ``governed_tool`` returns the protected callable unchanged, so ``search_orders`` here is
    # still the same function the rest of the program imports and calls directly.
    governed_tool(agent, provider=provider)(search_orders)
    # ``optional=()`` overrides the default and keeps ``fmt`` required. Nothing about it is
    # policy's to supply — it is a genuine choice by whoever wants the export — so letting the
    # model leave it out would only produce a refusal it could not have predicted.
    governed_tool(agent, provider=provider, optional=())(export_orders)
    return agent


async def offered_tools(agent: Agent[Caller, str], caller: Caller) -> list[str]:
    """Return the names of the tools ``agent``'s model is offered when acting for ``caller``.

    Runs one turn on a :class:`~pydantic_ai.models.function.FunctionModel` that calls nothing
    and merely reports ``AgentInfo.function_tools``. That is the only way to observe the
    manifest as the *model* sees it, which is the claim worth checking: a hidden tool is one
    the model was never told about.

    Args:
        agent: The agent to inspect.
        caller: Whose behalf the run acts on.

    Returns:
        The offered tool names, in registration order.
    """
    offered: list[str] = []

    def observe(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        """Record the manifest and answer without proposing anything."""
        offered.clear()
        offered.extend(definition.name for definition in info.function_tools)
        return ModelResponse(parts=[TextPart("noted")])

    await agent.run(PROMPT, deps=caller, model=FunctionModel(observe))
    return offered


async def propose(
    agent: Agent[Caller, str], caller: Caller, tool: str, **arguments: object
) -> object:
    """Make the model propose exactly one tool call, and return what came back.

    The deterministic stand-in for "the model decided to call this". A real model's choice is
    not reproducible; the *authorization* of that choice is, and that is what the example is
    about.

    Args:
        agent: The agent to run.
        caller: Whose behalf the run acts on.
        tool: The tool name to propose.
        **arguments: The arguments to propose. Omitting one is a state ``governed_tool``
            deliberately keeps expressible, so that policy can fill it in — see the README.

    Returns:
        The tool's result — the ordinary mapping with its ``_authz`` envelope when the call was
        allowed, the refusal payload when policy refused it — or the message the model was sent
        instead when the tool was not in its manifest at all.
    """

    def script(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        """Propose the call on the first turn; wrap up once anything has come back."""
        answered = any(
            isinstance(part, ToolReturnPart | RetryPromptPart)
            for message in messages
            for part in message.parts
        )
        if answered:
            return ModelResponse(parts=[TextPart("noted")])
        return ModelResponse(parts=[ToolCallPart(tool_name=tool, args=dict(arguments))])

    result = await agent.run(PROMPT, deps=caller, model=FunctionModel(script))
    for message in result.all_messages():
        for part in message.parts:
            if isinstance(part, ToolReturnPart | RetryPromptPart):
                return part.content
    return None


def dispatch_context(agent: Agent[Caller, str], caller: Caller) -> RunContext[Caller]:
    """Build the run context a host uses to invoke a governed tool with no model in the loop.

    What it exists for is the invariant: a caller that ignores the manifest and dispatches a
    tool it was never offered meets the identical gate. Reaching that path means going around
    the model, since a model can only propose what it was shown.

    Args:
        agent: The agent whose model the context borrows. Nothing calls it.
        caller: Whose behalf the dispatch acts on.

    Returns:
        A run context carrying ``deps`` and nothing else of consequence.
    """
    return RunContext(deps=caller, model=agent.model, usage=RunUsage())


async def demonstrate(agent: Agent[Caller, str]) -> None:
    """Print the manifest and the outcomes for both callers.

    Args:
        agent: The agent to drive.
    """
    for caller in (Caller("alice"), Caller("bob")):
        print(f"\n=== acting for {caller.principal} " + "=" * 44)
        print(f"tools the model is offered : {await offered_tools(agent, caller)}")
        for label, tool, arguments in (
            ("search, nothing proposed ", "search_orders", {}),
            ("search, region=uk limit=5", "search_orders", {"region": "uk", "limit": 5}),
            ("search, region=cn limit=5", "search_orders", {"region": "cn", "limit": 5}),
            ("search, region=cn lim=999", "search_orders", {"region": "cn", "limit": 999}),
            ("export, fmt=csv          ", "export_orders", {"fmt": "csv"}),
            ("export, fmt=pdf          ", "export_orders", {"fmt": "pdf"}),
        ):
            print(f"{label} -> {await propose(agent, caller, tool, **arguments)}")

    # The manifest is an affordance for the model, never the gate. Bob was never offered the
    # search, so his model cannot propose it -- but a host that ignores the manifest and
    # dispatches the adapter itself meets the identical decision.
    print("\n=== bypassing the manifest, with no model in the loop " + "=" * 13)
    outcome = await tool_adapter(search_orders)(dispatch_context(agent, Caller("bob")))
    print(f"search_orders(), acting for bob -> {outcome}")

    print("\n=== free-form, on the agent's own model " + "=" * 27)
    print(f"model: {type(agent.model).__name__} (set {MODEL_ENV_VAR} to use a real one)")
    for caller in (Caller("alice"), Caller("bob")):
        result = await agent.run(PROMPT, deps=caller)
        print(f"{caller.principal}: {result.output}")


def main() -> None:
    """Build the agent and run the whole demonstration offline."""
    asyncio.run(demonstrate(build_agent()))


if __name__ == "__main__":
    main()
