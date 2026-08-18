"""Tool-manifest filtering: deciding what a principal is even *shown*.

The agent half of ADR-009. A web provider has one job — establish context at the boundary —
because an HTTP client already knows which URLs exist. An agent boundary has a second job: it
tells the model what it may *attempt*, and that manifest is per-caller.

This module is the shared half of that, and it is deliberately framework-free. It imports no
`mcp` and no `pydantic_ai`; MCP's ``tools/list`` and Pydantic-AI's ``prepare`` are two
spellings of the same question, and they get one answer so they cannot drift apart.

## The invariant

> **A tool is hidden from a principal if and only if invoking it would be refused by the
> authorization gate.**

Both halves matter, and the tests assert both together.

*Only if* — hiding is never the enforcement. The dispatch path runs the identical decision, so
a client that ignores the manifest and calls a hidden tool by name is refused exactly as if it
had never been hidden. Manifest filtering that *were* the enforcement would be a hole the
moment a caller skipped ``tools/list``, and "the model did not know the tool existed" is not
an access-control argument.

*If* — a tool the principal may invoke is never hidden. Hiding is a usability affordance: it
stops the model proposing calls that cannot succeed, burning turns and context on refusals it
could not have predicted. A filter that hid more than it had to would silently narrow what the
agent can do for its user.

## Why "the gate" and not "the whole pipeline"

:meth:`~sentrykit.engine.Governor.plan` is run in full — this is the mechanism
:mod:`sentrykit.engine` was split for, in as many words — but its outcomes are read in two
groups:

* :class:`~sentrykit.errors.AuthzDenied` and :class:`~sentrykit.errors.NoContext` are about
  **entitlement**. The principal may not perform this action at all, whatever they pass.
  ⇒ hidden.
* :class:`~sentrykit.errors.DefaultUnavailable`,
  :class:`~sentrykit.errors.NoValidArguments`,
  :class:`~sentrykit.errors.ArgumentRejected` and
  :class:`~sentrykit.errors.ValidationFailed` are about **arguments**, and the manifest probe
  supplies none. A tool with a required parameter and no policy default raises
  ``DefaultUnavailable`` for *everybody*; treating that as "denied" would hide every such tool
  from every principal. ⇒ visible, and enforced on dispatch once the model has proposed
  something to enforce against.

So the manifest answers the only question that is decidable before the model has proposed
anything, and the argument-level pipeline answers the rest at dispatch. That split is the
honest reading of the invariant above, and :data:`ENTITLEMENT_ERRORS` is the one place it is
written down.

## An unprotected tool is not a governed tool

A callable with no ``@protect`` wrapper carries no action, no resource and no argument spec,
so there is nothing to decide about it. It is reported as :attr:`ToolDecision.governed`
``False`` and left **visible**: sentrykit does not silently hide a tool its author never asked
it to govern, and pretending to have made a decision about one would be worse than saying so.
Hosts that want everything governed assert that themselves — which is a one-line test over
:func:`decide_tools`, and the shipped examples have it.
"""

from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sentrykit.context import Principal
from sentrykit.decorator import ProtectedMeta, protected_meta
from sentrykit.engine import Governor, Plan, current_governor
from sentrykit.errors import AuthzDenied, ConfigurationError, NoContext, SentrykitError

__all__ = [
    "ENTITLEMENT_ERRORS",
    "ToolDecision",
    "decide_tool",
    "decide_tools",
    "governed_meta",
    "permitted_tools",
    "proposable",
]

_LOGGER: Final = logging.getLogger("sentrykit.integrations.tools")

ENTITLEMENT_ERRORS: Final[tuple[type[SentrykitError], ...]] = (AuthzDenied, NoContext)
"""Refusals that mean *this principal may not do this at all*, so the tool is hidden.

Every other :class:`~sentrykit.errors.SentrykitError` is about the arguments of a particular
call, which a manifest probe has not got — see this module's docstring. Matched with
``isinstance``, so a host subclassing one of these inherits its meaning.
"""


@dataclass(frozen=True, slots=True)
class ToolDecision:
    """What the shared gate concluded about one tool, for one principal.

    Returned rather than a bare ``bool`` because the two agent providers need different parts
    of it: MCP drops the hidden names from a ``tools/list`` result, Pydantic-AI returns
    ``None`` from ``prepare`` for the same tools, and both want the refusal for a debug log
    that explains *why* a tool the developer expected to see is missing.

    Attributes:
        name: The advertised tool name.
        visible: Whether the tool should appear in this principal's manifest.
        governed: Whether the underlying callable carries a ``@protect`` wrapper. ``False``
            means no decision was made and :attr:`visible` is ``True`` by default — see the
            module docstring.
        error: The refusal that hid it, or the argument-level refusal that did not. ``None``
            when the plan succeeded or the tool is ungoverned.
        plan: The successful plan, when there was one. Carries the action, the resource and
            the principal's argument constraints, which is what an optional schema-narrowing
            pass reads.
    """

    name: str
    visible: bool
    governed: bool
    error: SentrykitError | None = None
    plan: Plan | None = None


def governed_meta(fn: object) -> ProtectedMeta | None:
    """Return the ``@protect`` metadata for a tool's callable, unwrapping one adapter layer.

    An agent provider rarely registers the protected function itself. MCP registers a
    :func:`proposable` shim; Pydantic-AI registers a ``ctx``-taking adapter around that shim,
    which is **two** hops. Each layer records what it wraps under ``__wrapped__``, so the whole
    chain is walked rather than a fixed number of links -- a filter that stopped one hop short
    would read a governed tool as ungoverned and advertise it to everybody, which is ADR-017's
    failure mode exactly.

    Args:
        fn: The registered tool callable.

    Returns:
        The metadata, or ``None`` when nothing in the chain is protected.
    """
    # Bounded by identity rather than by a hop count: a chain that loops back on itself is a
    # host's bug, and hanging inside a live tools/list would be a worse way to report it.
    seen: set[int] = set()
    current: object | None = fn
    while current is not None and id(current) not in seen:
        meta = protected_meta(current)
        if meta is not None:
            return meta
        seen.add(id(current))
        current = getattr(current, "__wrapped__", None)
    return None


def _governor_for(name: str, meta: ProtectedMeta, governor: Governor | None) -> Governor:
    """Resolve the governor a manifest probe decides against.

    Same precedence as the decorator's: an explicitly passed governor, then one pinned to the
    protected callable, then the process-installed one.

    Args:
        name: The tool name, for the error message.
        meta: The protected callable's metadata.
        governor: An explicitly supplied governor, or ``None``.

    Returns:
        The governor.

    Raises:
        ConfigurationError: If none can be resolved. Refusing here rather than defaulting to
            "show everything" is the fail-closed rule applied to the manifest.
    """
    resolved = governor or meta.governor or current_governor()
    if resolved is None:
        raise ConfigurationError(
            f"cannot decide whether to advertise the protected tool {name!r}: no governor is "
            "installed; call install(...) before filtering a tool manifest"
        )
    return resolved


def decide_tool(
    name: str,
    fn: Callable[..., object],
    *,
    principal: Principal,
    governor: Governor | None = None,
    environment: Mapping[str, object] | None = None,
) -> ToolDecision:
    """Decide whether one tool belongs in ``principal``'s manifest.

    Runs :meth:`~sentrykit.engine.Governor.plan` with **no proposed arguments** — the same
    call the enforcement path makes, minus the arguments the model has not proposed yet — and
    reads the outcome per this module's docstring.

    Args:
        name: The advertised tool name, for the returned decision and the logs.
        fn: The registered callable. Unprotected callables are reported ungoverned and
            visible.
        principal: Who the manifest is for.
        governor: The governor to decide against. Defaults to the one pinned to the protected
            callable, and failing that to the process-installed one.
        environment: Cedar request context for the probe, merged over the ambient
            environment. A provider passes the same environment it would establish for a
            dispatch, so a policy conditioning on ``context.channel`` sees ``agent`` here too.

    Returns:
        The decision.

    Raises:
        ConfigurationError: If ``fn`` is protected but no governor can be resolved. A manifest
            that silently showed everything because nothing was installed would be the exact
            failure mode ADR-003 exists to prevent.
    """
    meta = governed_meta(fn)
    if meta is None:
        return ToolDecision(name=name, visible=True, governed=False)

    active = _governor_for(name, meta, governor)
    try:
        plan = active.plan(
            meta.spec,
            principal=principal,
            action=meta.action,
            resource=meta.resource,
            # No proposed arguments: the model has not proposed any yet. This is what makes
            # the probe answer an entitlement question and nothing else.
            proposed=None,
            environment=environment,
        )
    except ENTITLEMENT_ERRORS as exc:
        _LOGGER.debug(
            "Hiding tool from the manifest",
            extra={
                "tool": name,
                "principal": str(principal.uid),
                "action": str(meta.action),
                "reason": type(exc).__name__,
            },
        )
        return ToolDecision(name=name, visible=False, governed=True, error=exc)
    except SentrykitError as exc:
        # An argument-level refusal of an argument-free probe. It says nothing about whether
        # this principal is entitled to the action, only that the call as probed is
        # incomplete -- which every such call is. Advertise it; the dispatch path decides once
        # the model has proposed something to decide about.
        return ToolDecision(name=name, visible=True, governed=True, error=exc)
    return ToolDecision(name=name, visible=True, governed=True, plan=plan)


def decide_tools(
    tools: Mapping[str, Callable[..., object]] | Iterable[tuple[str, Callable[..., object]]],
    *,
    principal: Principal,
    governor: Governor | None = None,
    environment: Mapping[str, object] | None = None,
) -> tuple[ToolDecision, ...]:
    """Decide a whole manifest, in the order the tools were given.

    Args:
        tools: The registered tools, as a mapping or as ``(name, callable)`` pairs.
        principal: Who the manifest is for.
        governor: As for :func:`decide_tool`.
        environment: As for :func:`decide_tool`.

    Returns:
        One decision per tool, in input order.

    Raises:
        ConfigurationError: As for :func:`decide_tool`.
    """
    entries = tools.items() if isinstance(tools, Mapping) else tools
    return tuple(
        decide_tool(name, fn, principal=principal, governor=governor, environment=environment)
        for name, fn in entries
    )


def permitted_tools(
    tools: Mapping[str, Callable[..., object]] | Iterable[tuple[str, Callable[..., object]]],
    *,
    principal: Principal,
    governor: Governor | None = None,
    environment: Mapping[str, object] | None = None,
) -> tuple[str, ...]:
    """Return the names ``principal`` may be shown, in the order the tools were given.

    The convenience form of :func:`decide_tools` for a caller that needs only the names.

    Args:
        tools: The registered tools, as a mapping or as ``(name, callable)`` pairs.
        principal: Who the manifest is for.
        governor: As for :func:`decide_tool`.
        environment: As for :func:`decide_tool`.

    Returns:
        The permitted names.

    Raises:
        ConfigurationError: As for :func:`decide_tool`.
    """
    return tuple(
        decision.name
        for decision in decide_tools(
            tools, principal=principal, governor=governor, environment=environment
        )
        if decision.visible
    )


def proposable(
    fn: Callable[..., Any],
    *,
    optional: Sequence[str] | None = None,
) -> Callable[..., Any]:
    """Re-declare a protected callable so a caller may **omit** the arguments policy supplies.

    Both agent frameworks validate a proposal against the tool's advertised JSON schema
    *before* dispatch, so an argument the schema marks ``required`` can never be left out and
    can therefore never be filled in from the principal's defaults --
    `dev-docs/notes/phase-4-research.md` §10 measured it on each of them independently. Without
    this shim, default injection is unreachable from an agent at all, which would leave one of
    the three things sentrykit does undemonstrable at the very boundary Phase 4 exists to
    govern.

    This is the same move the FastAPI example already makes one layer out: its route declares
    ``region: str | None = None`` and forwards only what the caller actually supplied. An
    absent argument has to be *expressible at the boundary*, and on an agent boundary the
    boundary is the tool signature.

    The returned shim satisfies two introspections at once, which is the whole trick:

    * :func:`inspect.signature` reports the **shim's** parameters, because a callable carrying
      its own ``__signature__`` stops the unwrapping walk -- so the framework advertises the
      optional schema; while
    * :func:`inspect.unwrap` still reaches the protected callable through ``__wrapped__``, so
      :func:`governed_meta` finds the ``@protect`` metadata and the manifest filter governs the
      tool instead of waving it through as unprotected.

    Every synthesized parameter is made **keyword-only**. Agent frameworks propose arguments by
    name, so nothing is lost, and it removes the ordering trap where making one parameter
    optional would leave a non-default parameter standing after a default one.

    !!! warning
        A parameter listed in ``optional`` cannot carry a meaningful ``None``: the shim reads
        ``None`` as *not proposed* and drops it, exactly as the FastAPI example's
        ``if region is not None`` does. Do not list a genuinely nullable parameter.

    Args:
        fn: The protected callable to register as a tool. Sync or async; the shim matches.
        optional: Which parameters become omittable. Defaults to every parameter with no
            Python-level default -- precisely the set whose value could only have come from
            policy, and so precisely the set worth making omittable.

    Returns:
        The shim, to hand to ``@server.tool()`` or to
        :func:`~sentrykit.integrations.pydantic_ai.tool_adapter`.

    Raises:
        ConfigurationError: If ``fn``'s signature cannot be introspected, or if ``optional``
            names a parameter it does not declare or declares positional-only -- which could
            not be proposed by name and so could not be omitted either.
    """
    label = getattr(fn, "__qualname__", repr(fn))
    try:
        # ``eval_str=True`` because every module here carries ``from __future__ import
        # annotations``, so the raw annotations are *strings*. Two things then go wrong if they
        # are left alone: ``str | None`` is a TypeError on a string, and the framework would
        # later resolve the surviving forward references against the **shim's** ``__globals__``
        # -- this module's -- rather than the tool's own. Resolving here, against ``fn``'s
        # globals, removes both problems at once. It cannot fail for a callable ``@protect``
        # accepted, since ArgumentSpec already resolved the same annotations at decoration.
        signature = inspect.signature(fn, eval_str=True)
    except (TypeError, ValueError, NameError, AttributeError) as exc:
        raise ConfigurationError(f"cannot introspect the signature of {label}: {exc}") from exc

    # ``*args``/``**kwargs`` are not parameters a caller proposes by name, and the engine's own
    # ArgumentSpec does not model them either.
    declared = {
        key: parameter
        for key, parameter in signature.parameters.items()
        if parameter.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    }

    if optional is None:
        chosen: tuple[str, ...] = tuple(
            key
            for key, parameter in declared.items()
            if parameter.default is inspect.Parameter.empty
        )
    else:
        chosen = tuple(optional)
        unknown = sorted(key for key in chosen if key not in declared)
        if unknown:
            raise ConfigurationError(
                f"{label} declares no proposable parameter named {', '.join(unknown)}; "
                f"it declares {', '.join(declared) or 'none'}"
            )
        positional = sorted(
            key for key in chosen if declared[key].kind is inspect.Parameter.POSITIONAL_ONLY
        )
        if positional:
            raise ConfigurationError(
                f"{label} declares {', '.join(positional)} positional-only, so it cannot be "
                "proposed by name and cannot be made omittable"
            )

    omittable = frozenset(chosen)
    parameters = [
        parameter.replace(
            kind=inspect.Parameter.KEYWORD_ONLY,
            default=None if key in omittable else parameter.default,
            annotation=(
                parameter.annotation | None
                if key in omittable and parameter.annotation is not inspect.Parameter.empty
                else parameter.annotation
            ),
        )
        for key, parameter in declared.items()
    ]

    def winnow(proposed: Mapping[str, object]) -> dict[str, object]:
        """Drop the omittable arguments the caller did not actually propose."""
        return {
            key: value
            for key, value in proposed.items()
            if not (key in omittable and value is None)
        }

    shim: Callable[..., Any]
    if inspect.iscoroutinefunction(fn):

        async def async_shim(**proposed: object) -> object:
            """Forward only the genuinely proposed arguments to the protected coroutine."""
            return await fn(**winnow(proposed))

        shim = async_shim
    else:

        def sync_shim(**proposed: object) -> object:
            """Forward only the genuinely proposed arguments to the protected callable."""
            return fn(**winnow(proposed))

        shim = sync_shim

    # ``update_wrapper`` copies __name__/__qualname__/__doc__/__module__/__dict__ and sets
    # __wrapped__, which is the half :func:`governed_meta` needs. The explicit __signature__ is
    # the half the framework needs, and it has to be set *after*, because it is the marker that
    # stops ``inspect.signature`` walking __wrapped__ back to the required parameters.
    functools.update_wrapper(shim, fn)
    shim.__signature__ = signature.replace(parameters=parameters)  # type: ignore[attr-defined]
    return shim
