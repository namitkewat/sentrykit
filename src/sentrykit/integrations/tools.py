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

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Final

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

    An agent provider rarely registers the protected function itself: MCP registers it
    directly, but Pydantic-AI registers a synthesized ``ctx``-taking adapter around it. The
    adapter records the protected callable it wraps under ``__wrapped__`` (``functools`` does
    this for free), so one hop is enough to find the metadata from either side.

    Args:
        fn: The registered tool callable.

    Returns:
        The metadata, or ``None`` when nothing in the chain is protected.
    """
    meta = protected_meta(fn)
    if meta is not None:
        return meta
    wrapped = getattr(fn, "__wrapped__", None)
    return protected_meta(wrapped) if wrapped is not None else None


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
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError
