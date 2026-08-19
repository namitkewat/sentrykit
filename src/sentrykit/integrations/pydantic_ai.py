"""The Pydantic-AI context provider — an agent acts *for* a human, and policy knows it.

Wire it per tool and every call the model proposes is authorized as the person the agent is
running on behalf of:

```python
from dataclasses import dataclass

from pydantic_ai import Agent
from sentrykit.decorator import protect
from sentrykit.integrations.pydantic_ai import governed_tool


@dataclass
class Caller:
    principal: str          # the human, not the agent


agent = Agent("...", deps_type=Caller)


@governed_tool(agent, action="order.read", resource='Order::"o-1"')
@protect(action="order.read", resource='Order::"o-1"')
def read_order(order_id: str, limit: int = 10) -> dict[str, object]:
    \"\"\"Read an order.\"\"\"
    ...


result = await agent.run("what is on order o-1?", deps=Caller(principal="alice"))
```

`governed_tool` registers the tool, bridges ``RunContext.deps`` to ambient context for the
duration of each dispatch, and installs the per-run manifest filter. `@protect` is the same
decorator a Flask view uses; nothing about the tool's body knows it is being called by a
model.

## On-behalf-of is the whole point, and it is not a special mechanism

An agent acting for a human **is** that human, as far as the policy is concerned. The
principal established here is the one named in ``deps`` — never a service identity for the
agent process — so a delegation chain, a team edge or an expiry granted to *alice* is what
governs the call the model proposed on alice's behalf. Cedar resolves the chain; the model
never sees it, and could not influence it if it tried, because ``deps`` is supplied by the
application at ``run()`` time and the model has no way to write to it.

## Why the tool is a plain function and the adapter is synthesized

A ``@agent.tool`` function takes ``ctx: RunContext[…]`` as its first parameter. Wrapping *that*
in ``@protect`` would make ``ctx`` a **proposed argument**: it would go into the Cedar request
context, through the per-principal argument filter, and into the pydantic validation model —
wrong three times over, and the last one raises.

So the tool you write is a plain, ``ctx``-free, ``@protect``-ed function, and
:func:`tool_adapter` builds the ``ctx``-taking callable Pydantic-AI actually registers. The
adapter carries a synthesized ``__signature__`` that prepends ``ctx``, which produces exactly
the right tool definition: ``ctx`` absent from the JSON schema, the docstring's argument
descriptions intact. The author still writes one decorator, which is the whole promise.

## …and why the adapter re-declares the arguments as optional

The same synthesis solves a second problem, and it is the one that decides whether *default
injection* exists on this boundary at all. Pydantic-AI validates the model's proposal against
the advertised JSON schema **before** dispatch, so a parameter the schema marks ``required``
can never be omitted — and an argument that can never be omitted can never be filled in from
the principal's policy default. The whole "which defaults to inject when they pass none" half
of what sentrykit does would be unreachable from an agent.

:func:`~sentrykit.integrations.tools.proposable` is therefore applied inside
:func:`tool_adapter`, between the protected callable and the ``ctx``-prepending layer. It
re-declares every parameter that has no Python-level default as keyword-only and optional, and
forwards only the arguments the model genuinely proposed. The result is that a model may leave
``region`` out, the omission reaches the decorator as a real omission, and policy supplies the
value — which is exactly what the FastAPI example's route does one layer out when it writes
``if region is not None``. Name the set yourself with ``optional=`` when the default is wrong
for your tool.

## Establish per dispatch, not per run

`release` happens in a ``finally`` around each individual tool call, not around the whole
``agent.run(...)``. A run is a loop: the model proposes, a tool runs, the model proposes again.
Holding one establishment across all of that would mean a principal outliving the dispatch it
was established for — and the no-leak test asserts exactly that it does not, by driving two
dispatches inside one ``contextvars`` context and checking the principal is gone in between.

## Refusals come back as data, not as exceptions

A refused tool returns the ``_authz`` payload as its result — the same body a FastAPI caller
would get for the same refusal — with ``is_error`` implied by ``decision: "deny"``. The side
effect never happened, and the model is told *why* in a form it can act on: pick a different
tool, ask the user for authorization, or explain the refusal. Letting the error propagate
would abort the run and tell the user's agent nothing useful. Hosts that would rather fail the
run outright pass ``on_refusal="raise"``.
"""

from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final, Literal

from pydantic_ai import Agent, RunContext, ToolDefinition

from sentrykit.context import Channel, Principal
from sentrykit.decorator import protect, protected_meta
from sentrykit.errors import ConfigurationError, SentrykitError
from sentrykit.integrations.base import (
    DEFAULT_PRINCIPAL_HEADER,
    DEFAULT_REQUEST_ID_HEADER,
    BaseContextProvider,
    EnvironmentFactory,
    Identify,
    Identity,
)
from sentrykit.integrations.tools import decide_tool, proposable
from sentrykit.registry import DSN, register_context_provider
from sentrykit.stores.base import GrantStore

__all__ = [
    "DEFAULT_DEPS_ATTRIBUTE",
    "OnRefusal",
    "PydanticAIProvider",
    "governed_tool",
    "tool_adapter",
    "tool_filter",
    "tool_prepare",
]

_LOGGER: Final = logging.getLogger("sentrykit.integrations.pydantic_ai")

_CTX_PARAMETER: Final = "ctx"
"""Name of the parameter the adapter prepends. Pydantic-AI recognizes it by *position*, but
the name is what a tool author must not already be using — see :func:`tool_adapter`."""

DEFAULT_DEPS_ATTRIBUTE: str = "principal"
"""Attribute (or mapping key) on ``RunContext.deps`` the principal id is read from."""

OnRefusal = Literal["return", "raise"]
"""What a governed tool does with a refusal.

``return``
    Hand the ``_authz`` payload back as the tool's result. The run continues and the model
    can adapt. The default, and the reason is in this module's docstring.
``raise``
    Let the :class:`~sentrykit.errors.SentrykitError` propagate and end the run. For a host
    that treats any refusal as a bug in its own prompt or wiring.
"""


@register_context_provider("pydantic-ai")
class PydanticAIProvider(BaseContextProvider["RunContext[Any]"]):
    """Establishes ambient context from ``RunContext.deps`` and renders refusals as results.

    Construction is inherited from :class:`~sentrykit.integrations.base.BaseContextProvider`
    with one addition, ``deps_attribute``; see there for ``identify``, ``grants`` and
    ``environment``. The channel defaults to ``agent``.

    Args:
        deps_attribute: Where the principal id lives on ``deps`` — a mapping key when ``deps``
            is a mapping, an attribute otherwise. Ignored when ``identify`` is given, which is
            what an application with a richer ``deps`` type should pass.
        identify: As for the base class, but receiving the :class:`~pydantic_ai.RunContext`.
        grants: As for the base class.
        environment: As for the base class.
        principal_header: Fallback key read from ``deps`` when ``deps_attribute`` yields
            nothing, so a plain ``dict`` deps shaped like a request also works.
        request_id_header: Fallback key for a correlation id. Rarely needed — see
            :meth:`request_id`.
        channel: The channel established for every dispatch.
    """

    __slots__ = ("_deps_attribute",)

    def __init__(
        self,
        *,
        deps_attribute: str = DEFAULT_DEPS_ATTRIBUTE,
        identify: Identify[RunContext[Any]] | None = None,
        grants: GrantStore | None = None,
        environment: EnvironmentFactory[RunContext[Any]] | None = None,
        principal_header: str = DEFAULT_PRINCIPAL_HEADER,
        request_id_header: str = DEFAULT_REQUEST_ID_HEADER,
        channel: Channel = "agent",
    ) -> None:
        super().__init__(
            identify=identify,
            grants=grants,
            environment=environment,
            principal_header=principal_header,
            request_id_header=request_id_header,
            channel=channel,
        )
        self._deps_attribute = deps_attribute

    @classmethod
    def from_dsn(cls, dsn: DSN) -> PydanticAIProvider:
        """Build from ``pydantic-ai://`` — the registry's door, used by ``install()``.

        Args:
            dsn: The parsed address. Options: ``deps_attribute``, ``header``,
                ``request_id_header``.

        Returns:
            The provider.
        """
        # ``or`` rather than each option's own default, so an empty value falls back to the
        # shipped name instead of wiring a provider that reads ``""``.
        return cls(
            deps_attribute=dsn.option("deps_attribute") or DEFAULT_DEPS_ATTRIBUTE,
            principal_header=dsn.option("header") or DEFAULT_PRINCIPAL_HEADER,
            request_id_header=dsn.option("request_id_header") or DEFAULT_REQUEST_ID_HEADER,
        )

    @property
    def name(self) -> str:
        """``pydantic-ai``."""
        return "pydantic-ai"

    @property
    def deps_attribute(self) -> str:
        """Where the principal id is read from on ``deps``."""
        return self._deps_attribute

    def narrow(self, request: object) -> RunContext[Any]:
        """Check that ``request`` is a Pydantic-AI run context.

        Args:
            request: The object the boundary handed over.

        Returns:
            The same object, typed.

        Raises:
            ConfigurationError: If it is not a :class:`~pydantic_ai.RunContext` — which means
                this provider was wired to the wrong framework.
        """
        if isinstance(request, RunContext):
            return request
        actual = type(request)
        raise ConfigurationError(
            "the pydantic-ai context provider expects a pydantic_ai.RunContext but was given "
            f"a {actual.__module__}.{actual.__qualname__}; it is wired to the wrong framework"
        )

    def identity_of(self, request: RunContext[Any]) -> Identity | None:
        """Resolve who this dispatch acts for, from ``deps``.

        Overrides the base class's header-reading default because ``deps`` is a typed object
        an application designed, not a bag of strings. In order: the app's ``identify``
        callback when one was given; then ``deps`` itself when it is already a
        :class:`~sentrykit.context.Principal` or a bare id; then
        :attr:`deps_attribute` on it; then :attr:`principal_header`.

        ``deps=None`` means unauthenticated, which is a legitimate state — an agent run with
        no caller — and every governed tool in it will fail closed.

        Args:
            request: The run context.

        Returns:
            The identity, or ``None``.
        """
        if self._identify is not None:
            return self._identify(request)
        deps = request.deps
        if deps is None:
            return None
        # A ``deps`` that *is* the principal is the shortest wiring there is, and the two forms
        # are the two halves of :data:`~sentrykit.integrations.base.Identity` an app can hand
        # over without a callback: a materialized principal, or a bare id to look up.
        if isinstance(deps, Principal | str):
            return deps
        found = self.read_header(request, self._deps_attribute)
        if found is not None:
            return found
        return self.read_header(request, self._principal_header)

    def read_header(self, request: RunContext[Any], name: str) -> str | None:
        """Read one named value from ``deps``.

        Args:
            request: The run context.
            name: A mapping key when ``deps`` is a mapping; otherwise an attribute name, with
                ``-`` read as ``_`` so a header-shaped name still resolves.

        Returns:
            The value as a string, or ``None``.
        """
        deps = request.deps
        if deps is None:
            return None
        found = (
            deps.get(name)
            if isinstance(deps, Mapping)
            else getattr(deps, name.replace("-", "_"), None)
        )
        if isinstance(found, str):
            return found
        # A numeric id is stringified because ``User::"7"`` is a perfectly ordinary principal.
        # Anything else — a nested object, a list, a ``Principal`` parked under the attribute —
        # is left alone: guessing at its string form would fabricate an identity.
        if isinstance(found, int | float) and not isinstance(found, bool):
            return str(found)
        return None

    def request_id(self, request: RunContext[Any]) -> str:
        """Return the correlation id for one dispatch.

        Pydantic-AI already has one: ``RunContext.run_id`` is stable across every tool call in
        a run, which is exactly the correlation an audit trail wants — one id spanning the
        model's whole chain of proposals rather than a fresh UUID per tool. The tool call's own
        id goes into the environment instead, so a record can still be traced to a single
        dispatch.

        Args:
            request: The run context.

        Returns:
            The run id, falling back to the base class's behaviour when there is none.
        """
        # Bound to an annotated local rather than returned directly, so the module still
        # type-checks in the ``default`` environment where pydantic-ai is absent and every
        # symbol imported from it is ``Any``.
        run_id: str | None = request.run_id
        if run_id and run_id.strip():
            return run_id.strip()
        return super().request_id(request)

    def environment_for(self, request: RunContext[Any]) -> dict[str, object]:
        """Build the Cedar request context for one dispatch.

        Adds ``tool`` (the tool the model proposed) and ``tool_call_id`` to what the base class
        contributes, so a policy can condition on which tool is being invoked without the
        action id having to encode it, and an audit record names the individual proposal.

        Args:
            request: The run context.

        Returns:
            The environment to establish.
        """
        environment = super().environment_for(request)
        tool_name: str | None = request.tool_name
        tool_call_id: str | None = request.tool_call_id
        # ``setdefault`` rather than assignment: the base class merges the app's ``environment``
        # factory *last* precisely so the app wins, and adding these on top would quietly
        # reverse that for two keys. A host that computes its own ``tool`` keeps it.
        if tool_name is not None:
            environment.setdefault("tool", tool_name)
        if tool_call_id is not None:
            environment.setdefault("tool_call_id", tool_call_id)
        return environment

    def render_error(self, error: Exception) -> dict[str, object]:
        """Render a sentrykit refusal as the mapping a governed tool returns.

        The body is :func:`~sentrykit.integrations.base.error_payload`'s — the same one the
        web providers put in an HTTP response and the MCP provider puts in a tool result — so
        ``_authz`` reads identically wherever a refusal surfaces.

        Args:
            error: A :class:`~sentrykit.errors.SentrykitError`.

        Returns:
            The refusal payload, carrying ``detail``, ``error`` and ``_authz``.
        """
        # The status is dropped, not unused: an agent tool has nowhere to put one, and the
        # decision it encodes is already in ``_authz.decision``.
        return self.error_response(error)[1]


def _effective_provider(provider: PydanticAIProvider | None) -> PydanticAIProvider:
    """Resolve the provider a tool hook should establish with.

    The one place the defaulting rule lives, so :func:`tool_adapter`, :func:`tool_prepare` and
    :func:`tool_filter` cannot drift apart. Resolution is deferred to call time on purpose:
    ``install(context_provider=...)`` and the agent wiring may then happen in either order,
    which is the difference between a documented ordering constraint and none at all.

    A governor wired to some *other* framework's provider is ignored rather than treated as an
    error, since one process may legitimately run an agent beside an HTTP app. The fallback is
    a bare ``deps``-reading provider, which fails closed for any run whose ``deps`` names
    nobody.

    Args:
        provider: An explicitly supplied provider, or ``None``.

    Returns:
        The explicit provider, the installed governor's when it is a
        :class:`PydanticAIProvider`, or a freshly built default.
    """
    if provider is not None:
        return provider
    # Imported in the body rather than at module scope: the engine pulls in the whole decision
    # path, and a framework adapter should not dictate the library's import order.
    from sentrykit.engine import current_governor

    governor = current_governor()
    wired = governor.context_provider if governor is not None else None
    if isinstance(wired, PydanticAIProvider):
        return wired
    return PydanticAIProvider()


def tool_adapter(
    fn: Callable[..., object],
    *,
    provider: PydanticAIProvider | None = None,
    on_refusal: OnRefusal = "return",
    optional: Sequence[str] | None = None,
) -> Callable[..., Any]:
    """Wrap a plain protected callable as the ``ctx``-taking function Pydantic-AI registers.

    The returned adapter establishes ambient context from ``ctx``, calls ``fn`` with the
    arguments the model proposed, and releases in a ``finally``.

    Its signature is built in two layers, and both are load-bearing. Innermost,
    :func:`~sentrykit.integrations.tools.proposable` re-declares ``fn``'s parameters so the
    ones policy could supply are **omittable** — without which the model must invent a value
    for every parameter and default injection never happens, per this module's docstring.
    Outermost, a synthesized ``__signature__`` prepends ``ctx: RunContext[Any]``. What the
    model is shown is therefore ``fn``'s tool definition with ``ctx`` excluded, the docstring's
    argument descriptions intact, and ``required`` empty for the omittable parameters.

    Both layers record what they wrap under ``__wrapped__``, and
    :func:`~sentrykit.integrations.tools.governed_meta` walks the whole chain, so the
    ``@protect`` metadata is still reachable from the registered adapter.

    Args:
        fn: The tool body — a plain, ``ctx``-free callable, normally ``@protect``-ed. Sync and
            async are both supported; the adapter is always async, since Pydantic-AI awaits it
            either way.
        provider: The provider to establish with. Defaults to the one wired into the installed
            governor, and failing that to a ``deps``-reading :class:`PydanticAIProvider`.
        on_refusal: What to do with a :class:`~sentrykit.errors.SentrykitError`.
        optional: Which parameters the model may omit, as for
            :func:`~sentrykit.integrations.tools.proposable`. Defaults to every parameter with
            no Python-level default. Name the set explicitly when a parameter takes a
            meaningful ``None``, which the shim would otherwise read as *not proposed*.

    Returns:
        The adapter.

    Raises:
        ConfigurationError: If ``fn``'s signature cannot be introspected, if it already
            declares a parameter named ``ctx``, or if ``optional`` names a parameter it does
            not declare.
    """
    try:
        declared = inspect.signature(fn)
    except (TypeError, ValueError) as exc:  # pragma: no cover - builtins and C callables
        raise ConfigurationError(
            f"cannot register {getattr(fn, '__qualname__', fn)!r} as a governed tool: its "
            "signature cannot be introspected, so the adapter has no parameters to advertise"
        ) from exc
    # Checked against what the *author* wrote, so the message names their parameter rather than
    # one of the two synthesized layers below.
    if _CTX_PARAMETER in declared.parameters:
        raise ConfigurationError(
            f"the tool {getattr(fn, '__qualname__', fn)!r} already declares a parameter named "
            f"{_CTX_PARAMETER!r}; a governed tool is a plain, context-free callable and the "
            "adapter prepends that name itself — rename the parameter"
        )
    # The inner layer: parameters policy could supply become omittable, so the model is able to
    # propose nothing for them and the decorator sees a genuine omission.
    inner = proposable(fn, optional=optional)
    signature = inspect.signature(inner)
    awaitable = inspect.iscoroutinefunction(inner)

    async def adapter(ctx: RunContext[Any], *args: Any, **kwargs: Any) -> Any:
        """Establish for one dispatch, call the tool, release however it ends."""
        active = _effective_provider(provider)
        established = active.establish(ctx)
        try:
            result = inner(*args, **kwargs)
            return await result if awaitable else result
        except SentrykitError as exc:
            if on_refusal == "raise":
                raise
            _LOGGER.info(
                "Returning a refusal to the model as the tool result",
                extra={
                    "tool": ctx.tool_name,
                    "request_id": active.request_id(active.narrow(ctx)),
                    "reason": type(exc).__name__,
                },
            )
            return active.render_error(exc)
        finally:
            # Not tidiness. A run is a loop of dispatches on one task; a principal that
            # outlived its own dispatch would authorize the next one. See the module docstring.
            active.release(established)

    functools.update_wrapper(adapter, inner)
    # ``update_wrapper`` copies ``inner.__dict__`` — including the ``__sentrykit__`` the shim
    # itself inherited from ``fn`` — and then sets ``__wrapped__`` to ``inner``, giving
    # ``governed_meta`` the chain adapter → shim → protected callable to walk. The explicit
    # ``__signature__`` is assigned after, because the copied ``__dict__`` carries the shim's.
    adapter.__signature__ = signature.replace(  # type: ignore[attr-defined]
        parameters=[
            inspect.Parameter(
                _CTX_PARAMETER,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=RunContext[Any],
            ),
            *signature.parameters.values(),
        ]
    )
    # Rebuilt from the shim's signature rather than copied from ``fn.__annotations__``: those
    # are the *original* required annotations, and under ``from __future__ import annotations``
    # they are unresolved strings that a framework would later evaluate against this module's
    # globals. The shim resolved them against the tool's own, so its signature is the truth.
    annotations: dict[str, object] = {
        name: parameter.annotation
        for name, parameter in signature.parameters.items()
        if parameter.annotation is not inspect.Parameter.empty
    }
    if signature.return_annotation is not inspect.Signature.empty:
        annotations["return"] = signature.return_annotation
    annotations[_CTX_PARAMETER] = RunContext[Any]
    adapter.__annotations__ = annotations
    return adapter


def tool_prepare(
    fn: Callable[..., object],
    *,
    provider: PydanticAIProvider | None = None,
) -> Callable[[RunContext[Any], ToolDefinition], Any]:
    """Build the per-tool ``prepare`` hook that hides ``fn`` when its principal may not run it.

    This is Pydantic-AI's ``list_tools``: returning ``None`` from ``prepare`` drops the tool
    from the definitions offered to the model **for that run**. The decision is
    :func:`~sentrykit.integrations.tools.decide_tool`'s — the same gate the dispatch path runs
    — so a hidden tool is a denied tool and vice versa. See
    :mod:`sentrykit.integrations.tools` for why that equivalence is stated as an invariant and
    why hiding is never the enforcement.

    Args:
        fn: The tool body, or the adapter around it. Either resolves to the same metadata.
        provider: The provider whose environment the probe runs under. Defaults as for
            :func:`tool_adapter`.

    Returns:
        A :data:`~pydantic_ai.tools.ToolPrepareFunc`, ready to pass to ``agent.tool``.
    """

    async def prepare(ctx: RunContext[Any], tool_def: ToolDefinition) -> ToolDefinition | None:
        """Offer ``tool_def`` to this run, or withhold it."""
        active = _effective_provider(provider)
        narrowed = active.narrow(ctx)
        principal = active.resolve_principal(narrowed)
        if principal is None:
            # No caller means no entitlement to reason about, and a manifest is not the place
            # to be generous: an anonymous run is offered nothing rather than everything.
            _LOGGER.debug(
                "Hiding a governed tool from an unauthenticated run",
                extra={"tool": tool_def.name, "request_id": active.request_id(narrowed)},
            )
            return None
        decision = decide_tool(
            tool_def.name,
            fn,
            principal=principal,
            environment=active.environment_for(narrowed),
        )
        return tool_def if decision.visible else None

    return prepare


def tool_filter(
    tools: Mapping[str, Callable[..., object]],
    *,
    provider: PydanticAIProvider | None = None,
) -> Callable[[RunContext[Any], list[ToolDefinition]], Any]:
    """Build a whole-agent ``prepare_tools`` hook over an explicit tool mapping.

    The one-hook alternative to a ``prepare`` per tool, for an agent assembled from tools it
    did not register through :func:`governed_tool`:

    ```python
    agent = Agent(model, deps_type=Caller, prepare_tools=tool_filter({"read_order": read_order}))
    ```

    A definition whose name is absent from ``tools`` is left alone rather than dropped — this
    hook governs what it was told about and does not quietly remove an agent's other tools.

    Args:
        tools: Tool name → the callable behind it.
        provider: Defaults as for :func:`tool_adapter`.

    Returns:
        A :data:`~pydantic_ai.tools.ToolsPrepareFunc`, ready to pass to ``Agent(...)``.
    """

    async def filter_tools(
        ctx: RunContext[Any], tool_defs: list[ToolDefinition]
    ) -> list[ToolDefinition]:
        """Keep the definitions this run's principal may be offered, plus the unknown ones."""
        active = _effective_provider(provider)
        narrowed = active.narrow(ctx)
        principal = active.resolve_principal(narrowed)
        if principal is None:
            # Every *governed* tool goes; the rest are not this hook's to remove.
            return [definition for definition in tool_defs if definition.name not in tools]
        environment = active.environment_for(narrowed)
        kept: list[ToolDefinition] = []
        for definition in tool_defs:
            fn = tools.get(definition.name)
            if (
                fn is None
                or decide_tool(
                    definition.name, fn, principal=principal, environment=environment
                ).visible
            ):
                kept.append(definition)
        return kept

    return filter_tools


def governed_tool(
    agent: Agent[Any, Any],
    *,
    action: str | None = None,
    resource: str | None = None,
    provider: PydanticAIProvider | None = None,
    name: str | None = None,
    description: str | None = None,
    on_refusal: OnRefusal = "return",
    filter_manifest: bool = True,
    optional: Sequence[str] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register a protected callable on ``agent`` as a governed tool.

    Does the three things a governed tool needs, so a host does not have to remember them
    separately: applies ``@protect`` when the callable does not already carry it, registers
    :func:`tool_adapter`'s adapter via ``agent.tool``, and attaches :func:`tool_prepare` so
    the tool is hidden from any run whose principal could not invoke it.

    The **decorated function is returned unchanged** — protected, and still directly callable
    by ordinary application code under an established context. Registering a tool should not
    take a function away from the rest of the program.

    Args:
        agent: The agent to register on.
        action: The Cedar action, as for :func:`~sentrykit.decorator.protect`. Ignored when
            the callable is already protected.
        resource: The Cedar resource, as for :func:`~sentrykit.decorator.protect`. Ignored
            when the callable is already protected.
        provider: Defaults as for :func:`tool_adapter`.
        name: Tool name advertised to the model. Defaults to the function's name.
        description: Tool description. Defaults to the function's docstring.
        on_refusal: What to do with a refusal.
        filter_manifest: Whether to hide the tool from runs that could not invoke it. Turning
            it off leaves enforcement completely intact.
        optional: Which parameters the model may omit so policy can supply them, as for
            :func:`tool_adapter`. Defaults to every parameter with no Python-level default.

    Returns:
        The decorator, which returns the protected callable.
    """

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        """Protect, adapt, register — and hand the protected callable straight back."""
        # An already-protected callable keeps its own action and resource. Re-protecting it
        # would stack two gates and silently discard whichever pair the author wrote first.
        target = (
            fn if protected_meta(fn) is not None else protect(action=action, resource=resource)(fn)
        )
        # The keyword form, applied to an already-built adapter. Passing the callable
        # positionally *alongside* keywords works at runtime but is not one of ``tool``'s
        # declared overloads, and a public integration should type-check as its host declares.
        register = agent.tool(
            name=name,
            description=description,
            prepare=tool_prepare(target, provider=provider) if filter_manifest else None,
        )
        register(tool_adapter(target, provider=provider, on_refusal=on_refusal, optional=optional))
        return target

    return decorate
