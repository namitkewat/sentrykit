"""``@protect`` — one decorator, and N context providers behind it.

Everything a framework contributes is a context provider. Everything a developer writes is
this decorator. A Flask view, a background reconciliation job and a FastMCP tool are all
guarded by the same three lines of code, because the decorator only supplies the *action*
and the *proposed arguments*; who is acting comes from the ambient context.

```python
@protect(action='Action::"tool.search_orders"', resource='Tool::"orders"')
async def search_orders(customer_id: str, limit: int = 10) -> list[Order]: ...
```

The wrapper is signature-preserving, so type checkers, IDEs, and — importantly — FastAPI's
and Pydantic-AI's signature introspection see the original function.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Final, ParamSpec, TypeVar, cast, overload

from sentrykit.cedar import EntityRef
from sentrykit.context import Principal, current_principal
from sentrykit.engine import ArgumentSpec, Governor, derive_action, get_governor
from sentrykit.errors import ConfigurationError, NoContext

__all__ = [
    "AS_KEYWORD",
    "ProtectedMeta",
    "is_protected",
    "protect",
    "protected_meta",
]

P = ParamSpec("P")
T = TypeVar("T")

_P = ParamSpec("_P")
_T = TypeVar("_T")

AS_KEYWORD: str = "_as"
"""Call keyword that overrides the ambient principal for a single invocation."""

_META_ATTR: Final = "__sentrykit__"
"""Attribute under which :class:`ProtectedMeta` is stashed on the wrapper."""

_ABSENT: Final = object()
"""Sentinel distinguishing ``_as=None`` from no ``_as`` at all."""


@dataclass(frozen=True, slots=True)
class ProtectedMeta:
    """What ``@protect`` records on the callable it wraps.

    Attached as ``__sentrykit__`` so that tooling can introspect a protected callable without
    calling it — which is exactly what the agent-side ``list_tools`` filtering does to decide
    whether a principal should be shown a tool at all.

    Attributes:
        action: The action this callable is authorized as.
        resource: The declared resource, or ``None`` to let the governor synthesize one.
        spec: The cached argument spec.
        governor: A governor pinned to this callable, or ``None`` to use the process default
            at call time.
    """

    action: EntityRef
    resource: EntityRef | None
    spec: ArgumentSpec
    governor: Governor | None


@overload
def protect(fn: Callable[P, T], /) -> Callable[P, T]: ...


@overload
def protect(
    *,
    action: str | EntityRef | None = None,
    resource: str | EntityRef | None = None,
    governor: Governor | None = None,
) -> Callable[[Callable[P, T]], Callable[P, T]]: ...


def protect(
    fn: Callable[P, T] | None = None,
    /,
    *,
    action: str | EntityRef | None = None,
    resource: str | EntityRef | None = None,
    governor: Governor | None = None,
) -> Callable[P, T] | Callable[[Callable[P, T]], Callable[P, T]]:
    """Guard a callable with pre-action authorization.

    On every call the wrapper resolves the principal, binds the proposed arguments to
    parameter names, and hands both to the governor, which gates, filters, defaults,
    validates and only then invokes. Sync and async callables are both supported; the
    wrapper matches whichever it wraps.

    Usable bare (``@protect``) or with arguments (``@protect(action=...)``).

    The principal comes from the ambient context established by a provider. It can be
    overridden for one call by passing ``_as=<Principal>``, which the wrapper strips before
    binding — useful for a scheduled job that acts for a specific user, and for tests.
    Because the wrapper preserves the wrapped signature, a strictly type-checked caller
    passing ``_as=`` needs a ``type: ignore[call-arg]``; prefer
    :func:`~sentrykit.context.establish` where that matters.

    **No ambient principal and no ``_as=`` means the call is denied**, not run unguarded.
    That is the fail-closed rule, and it is why forgetting to wire a provider surfaces
    immediately rather than as a silent hole.

    Args:
        fn: The callable, when used bare as ``@protect``.
        action: The Cedar action. Accepts a full uid (``Action::"tool.search"``) or a bare
            id, which is read as an ``Action``. Defaults to
            ``Action::"<module>.<qualname>"``.
        resource: The Cedar resource. Accepts a full uid or a bare id read as a
            ``Resource``. Defaults to a resource derived from the action, so that a callable
            with no natural resource still fits Cedar's principal/action/resource model.
        governor: Pin a governor to this callable. Defaults to the process-installed one,
            resolved at call time so wiring order does not matter.

    Returns:
        The guarded callable, with the original signature and an attached
        :class:`ProtectedMeta`.

    Raises:
        ConfigurationError: If ``action`` or ``resource`` cannot be parsed, or the callable's
            signature cannot be introspected.
    """

    def decorate(target: Callable[_P, _T]) -> Callable[_P, _T]:
        spec = ArgumentSpec.from_callable(target)
        meta = ProtectedMeta(
            action=(
                EntityRef.parse(action, default_type="Action")
                if action is not None
                else derive_action(target)
            ),
            resource=(
                EntityRef.parse(resource, default_type="Resource") if resource is not None else None
            ),
            spec=spec,
            governor=governor,
        )
        if spec.is_async:
            asynchronous = _wrap_async(cast("Callable[_P, Awaitable[Any]]", target), meta)
            wrapped = cast("Callable[_P, _T]", asynchronous)
        else:
            wrapped = _wrap_sync(target, meta)
        setattr(wrapped, _META_ATTR, meta)
        return wrapped

    if fn is not None:
        return decorate(fn)
    return decorate


def protected_meta(fn: object) -> ProtectedMeta | None:
    """Return the metadata ``@protect`` attached to ``fn``, if it is protected.

    Args:
        fn: Any object, typically a callable.

    Returns:
        The metadata, or ``None`` when ``fn`` is not protected.
    """
    meta = getattr(fn, _META_ATTR, None)
    return meta if isinstance(meta, ProtectedMeta) else None


def is_protected(fn: object) -> bool:
    """Whether ``fn`` carries a ``@protect`` wrapper."""
    return protected_meta(fn) is not None


def _resolve_principal(meta: ProtectedMeta, override: object) -> Principal:
    """Decide who this call acts as.

    Args:
        meta: The protected callable's metadata, for the error message.
        override: Whatever came in as ``_as=``, or the absent sentinel.

    Returns:
        The explicit override when one was passed, otherwise the ambient principal.

    Raises:
        ConfigurationError: If ``_as=`` was passed something other than a
            :class:`~sentrykit.context.Principal`.
        NoContext: If nothing was passed and no principal is ambient. Fail-closed, and
            deliberately independent of ``fail_mode``: an engine that cannot
            tell who is calling has nothing to authorize.
    """
    if override is not _ABSENT:
        if not isinstance(override, Principal):
            raise ConfigurationError(
                f"{AS_KEYWORD}= must be a Principal, got {type(override).__name__}"
            )
        return override
    principal = current_principal()
    if principal is None:
        raise NoContext(str(meta.action))
    return principal


def _wrap_sync(
    fn: Callable[P, T],
    meta: ProtectedMeta,
) -> Callable[P, T]:
    """Build the synchronous wrapper for ``fn``."""

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        # Stripped before binding: ``_as`` is sentrykit's keyword, not the callable's.
        principal = _resolve_principal(meta, kwargs.pop(AS_KEYWORD, _ABSENT))
        active = meta.governor or get_governor()
        plan = active.plan(
            meta.spec,
            principal=principal,
            action=meta.action,
            resource=meta.resource,
            proposed=meta.spec.bind(args, kwargs),
        )
        return active.invoke(fn, plan)

    return wrapper


def _wrap_async(
    fn: Callable[P, Awaitable[T]],
    meta: ProtectedMeta,
) -> Callable[P, Awaitable[T]]:
    """Build the asynchronous wrapper for ``fn``."""

    @functools.wraps(fn)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        principal = _resolve_principal(meta, kwargs.pop(AS_KEYWORD, _ABSENT))
        active = meta.governor or get_governor()
        plan = active.plan(
            meta.spec,
            principal=principal,
            action=meta.action,
            resource=meta.resource,
            proposed=meta.spec.bind(args, kwargs),
        )
        return await active.ainvoke(fn, plan)

    return wrapper
