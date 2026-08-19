"""Ambient authorization context: who is acting, and under what circumstances.

A protected callable almost never receives the principal as an argument — a Flask view takes
a request, an agent tool takes the arguments the model proposed, a background job takes
none. Threading a principal through every signature between the boundary and the call would
be the tax that stops teams from protecting the inner functions at all.

So sentrykit makes the principal ambient instead: a context provider calls
:func:`establish` once at the boundary, and ``@protect`` reads the ambient principal
wherever the callable happens to live. Three rules follow from that, and they are load-bearing:

* An explicit ``_as=`` on the call beats the ambient principal.
* **No principal means deny.** Not "run unauthenticated", not "skip the check".
* ``ContextVar`` values propagate across ``await`` and across ``asyncio.to_thread``, but
  *not* across a bare ``ThreadPoolExecutor.submit``. Offloading through an executor without
  :func:`bind_context` would silently lose the principal — and, because of the previous
  rule, fail closed rather than fail open.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar, Token, copy_context
from datetime import datetime
from types import MappingProxyType, TracebackType
from typing import Final, Literal, ParamSpec, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from sentrykit.cedar import EntityRef
from sentrykit.constraints import ConstraintSet
from sentrykit.envelope import set_last_envelope
from sentrykit.errors import NoContext

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
V = TypeVar("V")

_logger: Final = logging.getLogger("sentrykit.context")

Channel = Literal["http", "agent", "internal"]
"""Where the invocation came from. Policies can condition on it via ``context.channel``."""

WILDCARD_ACTION: str = "*"
"""Key under which a :class:`Principal` may carry constraints that apply to every action."""

_DEFAULT_CHANNEL: Final = "internal"
"""Channel assumed when a provider established none — a plain in-process call."""

_EMPTY_ENVIRONMENT: Final[Mapping[str, object]] = MappingProxyType({})
"""The environment seen before anything is established.

A read-only proxy rather than a plain ``dict``, so a caller that pokes at the ambient
environment cannot mutate the default that every other context starts from.
"""

_principal_var: ContextVar[Principal | None] = ContextVar("sentrykit_principal", default=None)
_environment_var: ContextVar[Mapping[str, object]] = ContextVar(
    "sentrykit_environment", default=_EMPTY_ENVIRONMENT
)


def _restore(variable: ContextVar[V], token: Token[V], empty: V) -> None:
    """Reset one context variable, clearing it outright if its token belongs elsewhere.

    A scope reset from a different ``Context`` than the one that established it — a provider
    whose teardown hook runs on another task — cannot use its token. Leaving the
    establishment in place would be failing *open*, so the variable is cleared instead and
    the anomaly is logged.

    Args:
        variable: The context variable to restore.
        token: The token captured when the variable was set.
        empty: The value meaning "nothing established", used when the token is unusable.
    """
    try:
        variable.reset(token)
    except ValueError:
        variable.set(empty)
        _logger.warning(
            "Context scope for %s was reset outside its originating context; cleared instead",
            variable.name,
        )


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
            :attr:`attributes`.
        roles: Convenience for the most common parent edge. Each entry ``r`` becomes a
            parent ``Role::"r"``.
        parents: Any other direct parent edges — teams, projects, delegation targets.
        attributes: Cedar attributes for this principal, snapshotted at decision time.
            Values are coerced for Cedar, so ``None`` entries are dropped.
        constraints: Argument constraints keyed by action. The key may be a full uid
            (``Action::"tool.search"``), a bare action id (``tool.search``), or ``"*"`` for
            constraints that apply to every action. In a wired application these are
            materialized from the grant store rather than constructed by hand.
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
        return EntityRef(self.type, self.id)

    def all_parents(self) -> tuple[EntityRef, ...]:
        """Every parent edge — :attr:`roles` expanded to ``Role::"..."`` plus :attr:`parents`."""
        # A dict keyed by the reference deduplicates while preserving first-seen order, so a
        # role also listed explicitly in ``parents`` produces one edge rather than two.
        edges: dict[EntityRef, None] = {}
        for role in self.roles:
            edges.setdefault(EntityRef("Role", role), None)
        for parent in self.parents:
            edges.setdefault(parent, None)
        return tuple(edges)

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
        resolved = ConstraintSet()
        if not self.constraints:
            return resolved
        for key in (WILDCARD_ACTION, action.id, str(action)):
            layer = self.constraints.get(key)
            if layer is not None:
                resolved = resolved.merged_with(layer)
        return resolved


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
        return str(self.environment.get("channel", _DEFAULT_CHANNEL))

    @property
    def now(self) -> datetime | None:
        """The decision timestamp from :attr:`environment`, if one was established."""
        established = self.environment.get("now")
        return established if isinstance(established, datetime) else None


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

    __slots__ = ("_environment_token", "_principal_token", "_reset")

    def __init__(
        self,
        principal_token: Token[Principal | None],
        environment_token: Token[Mapping[str, object]],
    ) -> None:
        """Capture the tokens needed to undo one establishment.

        Constructed by :func:`establish`; there is no reason for application code to build
        one directly.

        Args:
            principal_token: Token returned when the principal was set.
            environment_token: Token returned when the environment was set.
        """
        self._principal_token = principal_token
        self._environment_token = environment_token
        self._reset = False

    def reset(self) -> None:
        """Restore the principal and environment that were ambient before establishment.

        Idempotent: resetting an already-reset scope does nothing.
        """
        if self._reset:
            return
        # Mark first: a failed restore must not leave the scope re-resettable, since the
        # fallback below has already put the context somewhere safe.
        self._reset = True
        _restore(_principal_var, self._principal_token, None)
        _restore(_environment_var, self._environment_token, _EMPTY_ENVIRONMENT)

    def __enter__(self) -> ContextScope:
        """Return this scope, for use as a context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Reset the scope, whether or not the block raised."""
        self.reset()


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
    principal_token = _principal_var.set(principal)
    # Snapshot behind a read-only proxy: the environment a decision was made against should
    # not be able to change under the decision.
    environment_token = _environment_var.set(MappingProxyType(dict(environment)))
    return ContextScope(principal_token, environment_token)


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
    with establish(principal, **environment):
        yield


def current_principal() -> Principal | None:
    """Return the ambient principal, or ``None`` if none has been established."""
    return _principal_var.get()


def require_principal(action: str) -> Principal:
    """Return the ambient principal, or refuse the call.

    Args:
        action: The action being attempted, for the error message.

    Returns:
        The ambient principal.

    Raises:
        NoContext: If no principal is ambient. This is the fail-closed rule, and it holds
            regardless of ``fail_mode``: an engine that cannot tell who is calling
            has nothing to authorize.
    """
    principal = _principal_var.get()
    if principal is None:
        # A missing principal is normal operation for an unauthenticated caller, not an
        # operator-actionable error — hence INFO, per the logging standards.
        _logger.info("No principal in context for action %s; denying", action)
        raise NoContext(action)
    return principal


def current_environment() -> Mapping[str, object]:
    """Return the ambient request environment, empty when nothing was established."""
    return _environment_var.get()


def clear_context() -> None:
    """Drop the ambient principal, the environment, and the last decision envelope.

    For tests and for long-lived workers that reuse a context between units of work. The
    envelope goes too: a worker that has finished one unit of work should not be able to
    report the previous one's decision as if it were its own.
    """
    _principal_var.set(None)
    _environment_var.set(_EMPTY_ENVIRONMENT)
    set_last_envelope(None)


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
    context = copy_context()

    def run_bound() -> T:
        """Run the bound call inside the copied context."""
        return context.run(fn, *args, **kwargs)

    return run_bound
