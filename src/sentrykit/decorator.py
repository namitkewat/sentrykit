"""``@protect`` — the one decorator, per ADR-009.

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

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import ParamSpec, TypeVar, overload

from sentrykit.cedar import EntityRef
from sentrykit.engine import ArgumentSpec, Governor

__all__ = [
    "AS_KEYWORD",
    "ProtectedMeta",
    "is_protected",
    "protect",
    "protected_meta",
]

P = ParamSpec("P")
T = TypeVar("T")

AS_KEYWORD: str = "_as"
"""Call keyword that overrides the ambient principal for a single invocation."""


@dataclass(frozen=True, slots=True)
class ProtectedMeta:
    """What ``@protect`` records on the callable it wraps.

    Attached as ``__sentrykit__`` so that tooling can introspect a protected callable without
    calling it — which is exactly what Phase 4's ``list_tools`` filtering does to decide
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
    That is ADR-003's fail-closed rule, and it is why forgetting to wire a provider surfaces
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
    raise NotImplementedError


def protected_meta(fn: object) -> ProtectedMeta | None:
    """Return the metadata ``@protect`` attached to ``fn``, if it is protected.

    Args:
        fn: Any object, typically a callable.

    Returns:
        The metadata, or ``None`` when ``fn`` is not protected.
    """
    raise NotImplementedError


def is_protected(fn: object) -> bool:
    """Whether ``fn`` carries a ``@protect`` wrapper."""
    raise NotImplementedError


def _wrap_sync(
    fn: Callable[P, T],
    meta: ProtectedMeta,
) -> Callable[P, T]:
    """Build the synchronous wrapper for ``fn``."""
    raise NotImplementedError


def _wrap_async(
    fn: Callable[P, Awaitable[T]],
    meta: ProtectedMeta,
) -> Callable[P, Awaitable[T]]:
    """Build the asynchronous wrapper for ``fn``."""
    raise NotImplementedError
