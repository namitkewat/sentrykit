"""A Pydantic-AI agent that acts *for* a human, and a policy that knows which human.

Run it with `pixi run -e agent run-agent`. It needs nothing installed beyond the `agent`
environment, and the free-form section at the end runs on the best model within reach.
`examples.models` is what decides which that is: a frontier model over
[OpenRouter](https://openrouter.ai) when an `OPENROUTER_API_KEY` is set — in the environment,
or in the untracked `.env` at the repository root — otherwise a local
[Ollama](https://ollama.com) daemon with a tool-capable model, otherwise
`pydantic_ai.models.test.TestModel`. Every authorization outcome is identical whichever tier
answers, because the decision is made from the principal and the proposed arguments and never
from which model proposed them. `SENTRYKIT_OPENROUTER_MODEL` and `SENTRYKIT_OLLAMA_MODEL` pin
which model a tier asks for, and `SENTRYKIT_OPENROUTER_URL` and `SENTRYKIT_OLLAMA_URL` point a
tier elsewhere or, set to an empty value, switch it off; all four are optional, and
`examples.models` documents them together.

## What it demonstrates

Seven governed tools, one protected callable that is deliberately *not* a tool, three humans,
and one manifest that changes depending on whose behalf the agent is running. Between them
they exercise every surface an argument rule can be written on:

* the **decorator** — `@protect` bare, and with an explicit action and resource;
* the **grant store** — allow-sets, deny-sets, patterns, bounds and defaults, per principal
  and per action;
* **reviewed policy** — an argument ceiling declared in `policies/10-orders.cedar`, and two
  rules that decide on the *relationship between* two proposed arguments.

The model **proposes**. The policy **decides**. When a proposed value is not one the principal
may pass, it is rejected and their own default refills the gap — reject-and-refill, so the
value the call runs with is the principal's default and never the bound that refused them.

And the tools do real work: each one reads or writes a seeded SQLite orders desk, so a narrowed
argument selects different *rows* rather than putting a different number in a report. The
demonstration resets that desk before it starts, so the refund and export ids it prints are the
same on every run. `build_agent()` does not touch it.

## On-behalf-of

The agent process has no identity of its own. Whoever the application names in `deps` is the
principal, and that is the whole idea: an agent acting for a human *is* that human. The model
cannot influence it — `deps` is supplied by the application at `run()` time and never appears
in anything the model can write: not in the prompt, not in the tool schemas, not in the
arguments it proposes.

## Nothing is wired at import

`build_agent()` calls `configure()` and `install()`, which mutate process-global state, and
`default_model()` probes for a live model. A module-level `agent = build_agent()` would run
all of that for anyone who so much as imported the module — including a test collector.
`pixi run -e agent run-agent` invokes `main()` through `__main__` instead, and every test
builds its own.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from pydantic_ai import Agent, RunContext
from pydantic_ai.messages import (
    ModelMessage,
    ModelResponse,
    RetryPromptPart,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
)
from pydantic_ai.models import Model
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel
from pydantic_ai.usage import RunUsage

from examples import desk, models
from examples.pydantic_ai_agent.policy import POLICY_DIR, build_grants
from examples.pydantic_ai_agent.service import (
    approve_refund,
    brief_orders,
    desk_status,
    export_orders,
    issue_refund,
    read_order,
    search_orders,
)
from sentrykit import configure, install
from sentrykit.integrations.pydantic_ai import PydanticAIProvider, governed_tool, tool_adapter
from sentrykit.stores.filesystem import FilesystemPolicySource

PROMPT = (
    "Look at the orders on this desk and tell me what you found. Use the tools you have and "
    "do not ask me for details: leave out any argument you are unsure of, because policy "
    "fills those in."
)
"""The user turn. The scripted models ignore it; a real model does not.

The last sentence is doing real work. An argument the model omits is one the principal's own
default supplies, so a model that guesses less gets *more* done — which is only true because
the tool schema was re-declared to let it omit them.
"""


@dataclass(frozen=True)
class Caller:
    """The agent's dependencies — which is to say, whose behalf it is acting on.

    One field, on purpose. A richer application would carry a session, a tenant and a request
    id here and hand the provider an ``identify=`` callback to pick the principal out of them;
    the default provider reads the ``principal`` attribute, which is all this example needs.

    Attributes:
        principal: The **human** the agent is acting for. Never a service identity for the
            agent process — see this module's docstring.
    """

    principal: str


def default_model() -> Model:
    """Pick the model to run the free-form section on: the best one within reach.

    :mod:`examples.models` answers which tier that is, and this turns its answer into the
    ``Model`` the agent runs on. Both live tiers speak the same OpenAI-compatible protocol, so
    one model class covers both and only the provider differs: the frontier tier needs a
    credential alongside the base URL, the local daemon needs the base URL alone.

    That frontier provider is the generic OpenAI-compatible one rather than pydantic-ai's
    OpenRouter-specific provider, which pins the base URL itself. ``examples.models`` keeps
    that URL configurable because emptying it is how the test suite switches the tier off, and
    a provider that supplied its own would quietly make that switch do nothing.

    Returns:
        An ``OpenAIChatModel`` over whichever live tier answered, otherwise a ``TestModel``.
        Which of the three it is changes no authorization outcome anywhere in this example.
    """
    choice = models.choose()
    if choice.model is None:
        return TestModel()
    try:
        # Imported here rather than at module scope: all three come from the optional
        # ``openai`` package, and the example has to keep running where it is absent.
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.ollama import OllamaProvider
        from pydantic_ai.providers.openai import OpenAIProvider
    except ImportError:
        return TestModel()
    if choice.tier is models.Tier.OPENROUTER:
        return OpenAIChatModel(
            choice.model,
            provider=OpenAIProvider(base_url=choice.base_url, api_key=choice.api_key),
        )
    return OpenAIChatModel(choice.model, provider=OllamaProvider(base_url=choice.base_url))


def describe_model(model: Model) -> str:
    """Name a model the way the demonstration prints it: which tier, and which model id.

    Read back off the model rather than remembered from :func:`default_model`, because
    ``build_agent`` takes a model from its caller too and the banner has to be right about
    whichever one it was handed. ``Model.system`` is pydantic-ai's own name for the provider a
    model is reached through, and that is what separates the live tiers here: Ollama's provider
    for the local daemon, the generic OpenAI-compatible one for the frontier tier.

    A credential never appears and cannot: it is held by the provider rather than by the
    model, and :class:`examples.models.Choice` keeps it out of its own repr for the same
    reason.

    Args:
        model: The model in use.

    Returns:
        ``<tier> (<model id>)`` for a live model, and the class name for the stand-in, which
        has no id worth showing.
    """
    tiers = {"ollama": models.Tier.OLLAMA, "openai": models.Tier.OPENROUTER}
    tier = tiers.get(str(getattr(model, "system", "")))
    name = str(getattr(model, "model_name", ""))
    return f"{tier} ({name})" if tier is not None and name else type(model).__name__


def build_agent(model: Model | None = None) -> Agent[Caller, str]:
    """Wire settings, grants, reviewed policy, the provider and the governed tools.

    Args:
        model: The model to run on. Defaults to :func:`default_model`, which probes for a
            live one; passing one explicitly skips the probe entirely.

    Returns:
        The agent, with every tool registered, governed, and hidden from any run whose
        principal could not invoke it.
    """
    # ``verbose`` so the ``_authz`` envelope carries processed values, applied defaults and
    # rejection reasons — the model is one of the audiences for that explanation, and it is
    # what lets it choose a different call instead of guessing. Production would use
    # ``summary``.
    configure(verbosity="verbose")

    store = build_grants()
    provider = PydanticAIProvider(grants=store)
    # Policy logic comes off disk, reviewed in git; grants come from the store, mutable as
    # data. ``policies=`` and ``policy_source=`` are mutually exclusive, which is the wiring
    # saying out loud that there is one place policy logic lives.
    install(
        policy_source=FilesystemPolicySource(POLICY_DIR),
        grant_store=store,
        context_provider=provider,
    )

    agent: Agent[Caller, str] = Agent(model or default_model(), deps_type=Caller)
    register = governed_tool(agent, provider=provider)

    # ``governed_tool`` returns the protected callable unchanged, so every name below is still
    # the same function the rest of the program imports and calls directly. Registering a tool
    # does not take a function away from anybody.

    # The bare-@protect callable. Its action id is this module's neighbour's import path —
    # ``Action::"examples.pydantic_ai_agent.service.desk_status"`` — which is what the policy
    # permitting it has to name.
    register(desk_status)

    # Its body calls ``summarize_orders``, which is protected and is NOT registered here. The
    # inner call is decided separately against the same principal, so watch for two decisions
    # from one tool call: the gate is on the call, never on the registration.
    register(brief_orders)

    # ``region`` and ``limit`` have no Python defaults, so ``optional`` defaults to exactly
    # those two and the model may omit either — which is what makes alice's defaults, and
    # dana's, reachable at all. ``status`` has a Python default, is therefore never absent,
    # and is left alone. Watch ``_authz.defaults_applied`` for what policy filled in and
    # ``_authz.rejected`` for what it threw away first.
    register(search_orders)

    # The relationship case: nothing in the permit names a principal. Watch ``_authz.decision``
    # flip between alice and bob on the identical call and identical arguments.
    register(read_order)

    # ``fmt`` is omittable for the same reason ``region`` is: bob's grant gives it a default,
    # so leaving it out is a policy-supplied value rather than a refusal he could not have
    # predicted. (Keeping it required with ``optional=()`` would be right only if no principal
    # had a default for it — an argument that can never be absent can never be filled in.)
    # Watch the two fates of one argument here: ``xml`` is refilled with ``csv`` by his grant,
    # while ``pdf`` is denied outright by reviewed policy and there is nothing to refill.
    register(export_orders)

    # Three arguments decided by three different mechanisms in one call: ``order_id`` by a
    # pattern with no default, ``amount`` by a bounded range *and* by a forbid weighing it
    # against the principal, ``region`` by an allow-set *and* by a forbid weighing it against
    # ``amount``. It is in alice's and dana's manifests because the permit granting it is
    # unconditional — a permit that read ``context.args`` would evaluate to false against a
    # manifest probe, which proposes nothing, and the tool would be hidden from everybody.
    # ``governed_tool(..., filter_manifest=False)`` is the escape hatch when a policy has to be
    # written that way; enforcement is intact either way.
    register(issue_refund)

    # The admin action, and the clearest look at the manifest filter: it is in dana's manifest
    # and absent from alice's, because alice would be refused whatever she passed.
    register(approve_refund)
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
            deliberately keeps expressible, so that policy can fill it in.

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


async def dispatch(
    agent: Agent[Caller, str], caller: Caller, fn: Callable[..., object], **arguments: object
) -> object:
    """Invoke a governed tool directly, with no model and no manifest in the way.

    Args:
        agent: The agent whose run context is borrowed.
        caller: Whose behalf the dispatch acts on.
        fn: The protected callable to dispatch.
        **arguments: The arguments to pass.

    Returns:
        Whatever the adapter returned — the result with its envelope, or the refusal payload.
    """
    adapter = tool_adapter(fn)
    return await adapter(dispatch_context(agent, caller), **arguments)


@dataclass(frozen=True)
class Flow:
    """One call the demonstration makes, and how it makes it.

    Attributes:
        number: Its row in the printed table.
        principal: Whose behalf it runs on.
        fn: The protected callable being called. Its ``__name__`` is also its tool name.
        arguments: What is proposed. An absent argument is the interesting case.
        mark: ``" "`` when the model proposes the call. ``"*"`` when the tool is hidden from
            this principal, so the demonstration dispatches it directly instead — footnoted
            under the table.
    """

    number: int
    principal: str
    fn: Callable[..., object]
    arguments: Mapping[str, object] = field(default_factory=dict)
    mark: str = " "


FLOWS: tuple[Flow, ...] = (
    Flow(1, "alice", desk_status),
    Flow(2, "alice", brief_orders),
    Flow(3, "alice", search_orders),
    Flow(4, "alice", search_orders, {"region": "cn", "limit": 5}),
    Flow(5, "alice", search_orders, {"limit": 500, "status": "open"}),
    Flow(6, "dana", search_orders, {"limit": 500, "status": "open"}),
    Flow(7, "alice", read_order, {"order_id": "ord-0003"}),
    Flow(8, "bob", read_order, {"order_id": "ord-0003"}, mark="*"),
    Flow(9, "bob", export_orders, {"fmt": "csv"}),
    Flow(10, "bob", export_orders, {"scope": "open"}),
    Flow(11, "bob", export_orders, {"fmt": "xml", "scope": "open"}),
    Flow(12, "alice", issue_refund, {"order_id": "refund-me", "amount": 900}),
    Flow(13, "bob", export_orders, {"fmt": "pdf"}),
    Flow(14, "bob", search_orders, mark="*"),
    Flow(15, "alice", issue_refund, {"order_id": "ord-0007", "amount": 100, "region": "uk"}),
    Flow(16, "alice", issue_refund, {"order_id": "ord-0007", "amount": 750, "region": "uk"}),
    Flow(17, "alice", issue_refund, {"order_id": "ord-0007", "amount": 900, "region": "eu"}),
    Flow(18, "alice", issue_refund, {"order_id": "ord-0007", "amount": 5000, "region": "eu"}),
    Flow(19, "dana", issue_refund, {"order_id": "ord-0007", "amount": 5000, "region": "eu"}),
    Flow(20, "alice", issue_refund, {"order_id": "refund-me", "amount": 100, "region": "eu"}),
    Flow(21, "dana", approve_refund, {"refund_id": "rf-0002"}),
    Flow(22, "alice", approve_refund, {"refund_id": "rf-0002"}, mark="*"),
)
"""Every flow the example prints, in the order it prints them."""


def render_call(flow: Flow) -> str:
    """Render a flow as the Python call it is.

    Args:
        flow: The flow.

    Returns:
        Something like ``search_orders(region='cn', limit=5)``.
    """
    inner = ", ".join(f"{name}={value!r}" for name, value in flow.arguments.items())
    return f"{flow.fn.__name__}({inner})"


def render_outcome(payload: object) -> str:
    """Turn what a governed tool returned into one legible line.

    Reads only the ``_authz`` envelope and the refusal payload — the same two things a model,
    or a caller, has to work from.

    Args:
        payload: The tool's return value, or the retry message a model got instead.

    Returns:
        ``allowed``, ``narrowed: …``, ``defaulted: …``, ``denied: …``, or the error name.
    """
    if not isinstance(payload, Mapping):
        return f"not offered: {payload}"

    envelope = payload.get("_authz")
    envelope = envelope if isinstance(envelope, Mapping) else {}
    error = payload.get("error")
    if error == "AuthzDenied":
        reason = envelope.get("reason") or payload.get("detail")
        policies = envelope.get("determining_policies") or ()
        named = f" [{', '.join(str(p) for p in policies)}]" if policies else ""
        return f"denied: {reason}{named}"
    if error is not None:
        # NoValidArguments and DefaultUnavailable come from the argument layer, not the gate.
        # Their ``_authz`` is built from the exception rather than from a decision, so it
        # names the rejected arguments and what would have been accepted, and carries no
        # ``action`` or ``resource`` — the gate is not what refused. The error name and the
        # detail are the whole story, so those are what this line prints.
        return f"{error}: {payload.get('detail')}"

    rejected = envelope.get("rejected") or ()
    defaults = dict(envelope.get("defaults_applied") or {})
    notes: list[str] = []
    for item in rejected:
        if not isinstance(item, Mapping):  # pragma: no cover - defensive
            continue
        name = str(item.get("name"))
        rule = item.get("rule")
        policy = item.get("policy")
        refill = defaults.pop(name, None)
        source = f", {policy}" if policy else ""
        # "refilled with" and never "clamped to": the value that breached a bound is thrown
        # away, and the principal's own default takes its place.
        notes.append(f"{name}={item.get('value')!r} rejected ({rule}{source}) -> {name}={refill!r}")
    filled = ", ".join(f"{name}={value!r}" for name, value in defaults.items())
    if notes:
        tail = f"; defaulted: {filled}" if filled else ""
        return f"narrowed: {'; '.join(notes)}{tail}"
    if filled:
        return f"defaulted: {filled}"
    return "allowed"


async def run_flow(agent: Agent[Caller, str], flow: Flow) -> str:
    """Run one flow and render its outcome.

    Args:
        agent: The agent to drive.
        flow: The flow to run.

    Returns:
        The rendered outcome.
    """
    caller = Caller(flow.principal)
    if flow.mark != " ":
        # Around the model, straight to the adapter. The tool is hidden from this principal,
        # so no model could propose it — and dispatching it by name anyway is what proves
        # hiding is an affordance and the gate is the enforcement.
        return render_outcome(await dispatch(agent, caller, flow.fn, **flow.arguments))
    return render_outcome(await propose(agent, caller, flow.fn.__name__, **flow.arguments))


def abbreviate(text: str, limit: int = 220) -> str:
    """Shorten a model's answer to something a terminal can show on a few lines.

    Args:
        text: The answer.
        limit: How many characters to keep.

    Returns:
        The answer, truncated with an ellipsis when it was longer.
    """
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else f"{flat[:limit]} [...]"


def banner(title: str) -> None:
    """Print a section heading.

    Args:
        title: The heading text.
    """
    print(f"\n=== {title} " + "=" * max(0, 92 - len(title)))


async def show_manifests(agent: Agent[Caller, str]) -> None:
    """Print each principal's tool manifest, as the model is given it.

    Args:
        agent: The agent to inspect.
    """
    banner("the manifest each model is offered")
    for name in ("alice", "bob", "dana"):
        offered = await offered_tools(agent, Caller(name))
        print(f"{name:<6}: {', '.join(offered)}")
    print(
        "\nA tool is hidden exactly when this principal would be refused whatever they passed."
        "\nA model can only propose what it was shown, so bob's model never asks to search."
    )


async def show_flows(agent: Agent[Caller, str]) -> None:
    """Run every flow and print the table.

    Args:
        agent: The agent to drive.
    """
    banner("every flow, decided")
    print(f"{'#':>3}  {'who':<5}  {'call':<59}  outcome")
    for flow in FLOWS:
        print(f"{flow.number:>3}{flow.mark} {flow.principal:<5}  {render_call(flow):<59}  ", end="")
        print(await run_flow(agent, flow))
    print(
        "\n* Hidden from that principal's manifest, so dispatched by name with no model in the"
        "\n  loop. The gate refuses it exactly as if it had never been hidden."
        "\n\nA tool call carries the advertised schema's defaults, so an argument with a Python"
        "\ndefault arrives even when the model did not propose it -- which is why flow 11 still"
        "\nnarrows: scope survives, and a surviving argument is what a rejected one is refilled"
        "\nalongside. Flow 12 proposes two arguments and both are rejected, so nothing is left"
        "\nto run with: narrowing refines a proposal, it does not rescue one."
    )


async def show_ceiling(agent: Agent[Caller, str]) -> None:
    """Spell out the ceiling case, which is the one worth reading twice.

    Args:
        agent: The agent to drive.
    """
    banner("the ceiling, read twice")
    result = await propose(agent, Caller("dana"), "search_orders", limit=500, status="open")
    limit = result.get("limit") if isinstance(result, Mapping) else None
    print(
        "dana proposed limit=500.\n"
        "The ceiling declared in policies/10-orders.cedar is 100.\n"
        f"She ran with limit={limit}, which is her own default.\n\n"
        "That is reject-and-refill: a value the principal may not pass is thrown away and\n"
        "their default fills the gap. The result is never the bound that refused it, so it\n"
        "is not 100 and could not be. The rejection names support-may-search because the\n"
        "reviewed ceiling is what refused her; a rejection from her own grant would name the\n"
        "grant instead."
    )


async def show_nesting(agent: Agent[Caller, str]) -> None:
    """Show one tool call producing two decisions, against a callable that is not a tool.

    Args:
        agent: The agent to drive.
    """
    banner("one tool call, two decisions")
    result = await propose(agent, Caller("alice"), "brief_orders")
    outer = result.get("_authz", {}) if isinstance(result, Mapping) else {}
    inner_result = result.get("brief", {}) if isinstance(result, Mapping) else {}
    inner = inner_result.get("_authz", {}) if isinstance(inner_result, Mapping) else {}
    print(f"outer  {outer.get('action')}  {outer.get('decision')}")
    print(f"inner  {inner.get('action')}  {inner.get('decision')}")
    print(
        "\nsummarize_orders is protected and is not registered as a tool, so no model was ever"
        "\ntold it exists and none could propose it. It is still decided, because the gate is"
        "\non the call and not on the registration. Two decisions means two audit records at"
        "\nwhatever sink is wired, and the outer one is written before the body runs, so a"
        "\nrefusal inside cannot erase the fact that the outer call was permitted. An inner"
        "\nrefusal propagates out unchanged rather than becoming a partial answer."
    )


async def show_who_decided(agent: Agent[Caller, str]) -> None:
    """Re-run three refusals at ``debug`` verbosity, where the envelope names the policies.

    Args:
        agent: The agent to drive.
    """
    banner("which policy decided, and when nothing did")
    # ``debug`` adds ``determining_policies`` to the envelope. It is off by default because it
    # tells a caller which reviewed policy rules govern them, which is more than most callers
    # should learn from a refusal. Restored below, so the rest of the run is unaffected.
    configure(verbosity="debug")
    try:
        pdf = await propose(agent, Caller("bob"), "export_orders", fmt="pdf")
        over = await propose(
            agent, Caller("alice"), "issue_refund", order_id="ord-0007", amount=5000, region="eu"
        )
        gated = await dispatch(agent, Caller("bob"), search_orders)
    finally:
        configure(verbosity="verbose")
    print(f"13  bob    export_orders(fmt='pdf')       {render_outcome(pdf)}")
    print(f"18  alice  issue_refund(.., amount=5000)  {render_outcome(over)}")
    print(f"14  bob    search_orders()                {render_outcome(gated)}")
    print(
        "\nA forbid that fires is named, and both of these refusals are one. Flow 14 is the"
        "\nother shape: no permit matched bob at all, so the decision is the default deny and"
        "\nnothing was determining. It names no policy because there is no rule to point at,"
        "\nand saying otherwise would be inventing one."
    )


async def show_free_form(agent: Agent[Caller, str]) -> None:
    """Let the agent's own model choose what to do, and print what it managed.

    Args:
        agent: The agent to drive.
    """
    banner("free-form, on the agent's own model")
    print(f"model: {describe_model(agent.model)}")
    if isinstance(agent.model, TestModel):
        print(
            f"  -- {models.why_no_model()}\n"
            "This section runs on a stand-in that calls every visible tool with generated\n"
            f"arguments. An {models.OPENROUTER_KEY_ENV_VAR} in .env at the repository root\n"
            "opts into a frontier model; a local Ollama daemon with a tool-capable model is\n"
            "the path that needs no account. Every authorization outcome above is the same\n"
            "whichever of the three answers."
        )
    print()

    for name in ("alice", "bob", "dana"):
        try:
            result = await agent.run(PROMPT, deps=Caller(name))
        # Deliberately broad: a small local model fails in a lot of ways, and the point of
        # this section is that none of them are the policy layer's problem.
        except Exception as exc:
            # A small model may propose malformed arguments, insist on a tool it was never
            # offered, or exhaust its retries. None of that reaches the policy layer: the
            # decision already happened, or never had to. sentrykit refusing a call the model
            # should not have proposed is the point, not a failure of the demonstration.
            print(f"{name:<6}: run did not finish -- {type(exc).__name__}: {exc}")
            continue
        called = [
            part.tool_name
            for message in result.all_messages()
            for part in message.parts
            if isinstance(part, ToolCallPart)
        ]
        print(f"{name:<6}: proposed {', '.join(called) or 'nothing'}")
        print(f"{'':<6}  answered {abbreviate(str(result.output))}")


async def demonstrate(agent: Agent[Caller, str]) -> None:
    """Print the manifests, every flow, the ceiling case and the free-form run.

    Resets the orders desk before driving anything, so the run is reproducible. Nothing else
    here writes to it.

    Args:
        agent: The agent to drive.
    """
    # Several flows WRITE: each permitted refund books a row with a freshly allocated id, and
    # each export books a job. Starting from identical rows is what makes two runs agree — the
    # table below is reproduced in the documentation and checked against it line for line, and
    # "line for line" has to mean the same thing twice.
    #
    # ``build_agent()`` deliberately does not do this: a service that emptied its database on
    # startup would be a poor example of anything.
    desk.reset_desk()
    print(
        "sentrykit logs a `Argument dropped by policy` warning on every rejection. They are\n"
        "this run's own log lines arriving on stderr, one per narrowed argument below."
    )
    await show_manifests(agent)
    await show_flows(agent)
    await show_ceiling(agent)
    await show_nesting(agent)
    await show_who_decided(agent)
    await show_free_form(agent)


def main() -> None:
    """Build the agent and run the whole demonstration."""
    asyncio.run(demonstrate(build_agent()))


if __name__ == "__main__":
    main()
