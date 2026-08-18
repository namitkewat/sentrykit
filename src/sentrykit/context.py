"""Ambient authorization context: who is acting, and under what circumstances.

A protected callable almost never receives the principal as an argument — a Flask view takes
a request, an agent tool takes the arguments the model proposed, a background job takes
none. Threading a principal through every signature between the boundary and the call would
be the tax that stops teams from protecting the inner functions at all.

So sentrykit follows ADR-003: a context provider calls :func:`establish` once at the
boundary, and ``@protect`` reads the ambient principal wherever the callable happens to
live. Three rules follow from that, and they are load-bearing:

* An explicit ``_as=`` on the call beats the ambient principal.
* **No principal means deny.** Not "run unauthenticated", not "skip the check".
* ``ContextVar`` values propagate across ``await`` and across ``asyncio.to_thread``, but
  *not* across a bare ``ThreadPoolExecutor.submit``. Offloading through an executor without
  :func:`bind_context` would silently lose the principal — and, because of the previous
  rule, fail closed rather than fail open.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime
from types import TracebackType
from typing import Literal, ParamSpec, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from sentrykit.cedar import EntityRef
from sentrykit.constraints import ConstraintSet

__all__ = [
    "Channel",
    "ContextScope",
    "Invocation",
    "Principal",
    "bind_context",
    "clear_context",
    "current_environment",
    "current_principal",
    "establish",
    "principal_context",
    "require_principal",
]

P = ParamSpec("P")
T = TypeVar("T")

Channel = Literal["http", "agent", "internal"]
"""Where the invocation came from. Policies can condition on it via ``context.channel``."""

WILDCARD_ACTION: str = "*"
"""Key under which a :class:`Principal` may carry constraints that apply to every action."""


class Principal(BaseModel):
    """Who is acting, as sentrykit sees them.

    A principal is a Cedar entity plus the argument constraints that have been granted to
    them. Roles, teams and delegation edges are all just parent edges: Cedar computes the
    transitive closure, which is how a multi-hop relationship — user in team, team on
    project, project owns resource — gets resolved by policy rather than by a chain of
    ``if`` statements in the application.

    Attributes:
        id: The entity id.
        type: The entity type. ``User`` covers the common case; an agent acting for a human
            is still modelled as that human, with the delegation recorded in
            :attr:`attributes`, per ADR-008.
        roles: Convenience for the most common parent edge. Each entry ``r`` becomes a
            parent ``Role::"r"``.
        parents: Any other direct parent edges — teams, projects, delegation targets.
        attributes: Cedar attributes for this principal, snapshotted at decision time.
            Values are coerced for Cedar, so ``None`` entries are dropped.
        constraints: Argument constraints keyed by action. The key may be a full uid
            (``Action::"tool.search"``), a bare action id (``tool.search``), or ``"*"`` for
            constraints that apply to every action. In Phase 2 these are materialized from
            the grant store rather than constructed by hand.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    type: str = "User"
    roles: tuple[str, ...] = ()
    parents: tuple[EntityRef, ...] = ()
    attributes: dict[str, object] = Field(default_factory=dict)
    constraints: dict[str, ConstraintSet] = Field(default_factory=dict)

    @property
    def uid(self) -> EntityRef:
        """This principal as a Cedar entity reference."""
        raise NotImplementedError

    def all_parents(self) -> tuple[EntityRef, ...]:
        """Every parent edge — :attr:`roles` expanded to ``Role::"..."`` plus :attr:`parents`."""
        raise NotImplementedError

    def constraints_for(self, action: EntityRef) -> ConstraintSet:
        """Resolve the argument constraints that apply to ``action``.

        Lookup runs from least to most specific: the ``"*"`` wildcard set first, then the
        bare action id, then the full uid — each layered over the previous, so a
        wildcard baseline can be refined per action.

        Args:
            action: The action being authorized.

        Returns:
            The merged constraint set, empty when nothing applies.
        """
        raise NotImplementedError


class Invocation(BaseModel):
    """One normalized call, as the core sees it — independent of how it arrived.

    This is the object architecture §1 describes: the decorator supplies the action and the
    proposed arguments, a context provider supplies the principal and the environment, and
    nothing downstream can tell whether it came from an HTTP route, an MCP tool dispatch, or
    a plain function call.

    Attributes:
        id: Correlation id, shared by the Cedar result, the operational logs and the audit
            record.
        principal: Who is acting.
        action: What they propose to do.
        resource: What they propose to do it to.
        proposed: The arguments as supplied — untrusted input, before any filtering.
        environment: Cedar request context: ``now``, ``channel``, request id, auth strength,
            delegation chain, break-the-glass flag.
        callable_name: Qualified name of the protected callable, for diagnostics.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    principal: Principal
    action: EntityRef
    resource: EntityRef
    proposed: dict[str, object] = Field(default_factory=dict)
    environment: dict[str, object] = Field(default_factory=dict)
    callable_name: str = ""

    @property
    def channel(self) -> str:
        """The channel from :attr:`environment`, defaulting to ``internal``."""
        raise NotImplementedError

    @property
    def now(self) -> datetime | None:
        """The decision timestamp from :attr:`environment`, if one was established."""
        raise NotImplementedError


class ContextScope:
    """The handle :func:`establish` returns: undo the establishment when the boundary ends.

    Usable two ways, because the two boundaries need different shapes. A framework hook that
    has no enclosing block — Flask's ``before_request``, an MCP dispatch callback — keeps the
    handle and calls :meth:`reset`. Everything else uses it as a context manager, which
    resets even when the body raises.

    Example:
        ```python
        with establish(principal, channel="agent"):
            await run_tool()
        ```
    """

    def reset(self) -> None:
        """Restore the principal and environment that were ambient before establishment.

        Idempotent: resetting an already-reset scope does nothing.
        """
        raise NotImplementedError

    def __enter__(self) -> ContextScope:
        """Return this scope, for use as a context manager."""
        raise NotImplementedError

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Reset the scope, whether or not the block raised."""
        raise NotImplementedError


def establish(principal: Principal, **environment: object) -> ContextScope:
    """Make ``principal`` the ambient principal for this context.

    Called by a context provider at the framework boundary. The environment keys become the
    Cedar request context, so policies can condition on them directly.

    Args:
        principal: Who the subsequent protected calls are acting as.
        **environment: Request environment — ``channel``, ``request_id``, ``auth_strength``,
            ``break_glass``, a delegation chain, and anything else the policy pack expects.
            ``now`` is filled in by the engine at decision time unless supplied here.

    Returns:
        A scope handle. Use it as a context manager, or call :meth:`ContextScope.reset` when
        the boundary has no enclosing block.
    """
    raise NotImplementedError


@contextmanager
def principal_context(principal: Principal, **environment: object) -> Iterator[None]:
    """Establish ``principal`` for the duration of a ``with`` block.

    The generator-based twin of :func:`establish`, for callers who prefer an explicit
    context manager over a handle that happens to be one.

    Args:
        principal: Who the block is acting as.
        **environment: Request environment, as for :func:`establish`.

    Yields:
        ``None``, with the context established.
    """
    raise NotImplementedError


def current_principal() -> Principal | None:
    """Return the ambient principal, or ``None`` if none has been established."""
    raise NotImplementedError


def require_principal(action: str) -> Principal:
    """Return the ambient principal, or refuse the call.

    Args:
        action: The action being attempted, for the error message.

    Returns:
        The ambient principal.

    Raises:
        NoContext: If no principal is ambient. This is the fail-closed rule from ADR-003 and
            it holds regardless of ``fail_mode``: an engine that cannot tell who is calling
            has nothing to authorize.
    """
    raise NotImplementedError


def current_environment() -> Mapping[str, object]:
    """Return the ambient request environment, empty when nothing was established."""
    raise NotImplementedError


def clear_context() -> None:
    """Drop the ambient principal and environment.

    For tests and for long-lived workers that reuse a context between units of work.
    """
    raise NotImplementedError


def bind_context(fn: Callable[P, T], /, *args: P.args, **kwargs: P.kwargs) -> Callable[[], T]:
    """Bind a call to a copy of the current context, for offload to a thread pool.

    ``ContextVar`` values follow ``await`` and ``asyncio.to_thread`` on their own, so most
    code needs nothing. A bare ``ThreadPoolExecutor.submit`` or ``loop.run_in_executor`` is
    the exception: the worker thread starts from an empty context, the ambient principal is
    gone, and every protected call inside it denies. Wrapping the call here carries the
    context across.

    Example:
        ```python
        executor.submit(bind_context(reconcile_orders, batch_id))
        ```

    Args:
        fn: The callable to run in the other thread.
        *args: Positional arguments for ``fn``.
        **kwargs: Keyword arguments for ``fn``.

    Returns:
        A zero-argument thunk that runs ``fn`` inside a copy of the calling context.
    """
    raise NotImplementedError
