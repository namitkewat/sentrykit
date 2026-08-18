"""The FastAPI / Starlette context provider.

Wire it once and every ``@protect``-ed callable reached from a request — the route itself, a
service function three frames deeper, a helper in another module — is governed by the same
ambient principal:

```python
from fastapi import FastAPI
from sentrykit.integrations.fastapi import protect_app

app = FastAPI()
protect_app(app, provider=FastAPIProvider(identify=lambda request: request.headers.get("x-user")))
```

`protect_app` adds a pure-ASGI middleware and registers the exception handlers. Both are
available separately for apps that want to place them by hand.

## Why a pure-ASGI middleware, and never a sync dependency

`dev-docs/notes/phase-3-research.md` §1 measured the four places a provider could establish
context, and only three of them work:

| Established in | reaches an `async def` route | reaches a `def` route |
| --- | --- | --- |
| pure-ASGI middleware | yes | yes |
| `BaseHTTPMiddleware` | yes | yes |
| `async def` dependency | yes | yes |
| **`def` (sync) dependency** | **no** | **no** |

A sync dependency runs in an AnyIO worker thread with a *copy* of the context, so its
establishment is discarded the moment it returns and every protected call downstream then
fails closed. This module ships no sync-dependency form, so there is nothing to reach for by
mistake. A sync *route* is fine — `anyio.to_thread.run_sync` copies the context into the
worker, so the principal established upstream travels with it.

The middleware is pure ASGI rather than `BaseHTTPMiddleware` for two reasons: it needs no task
group and no response buffering, and — because Starlette builds the stack as
`ServerErrorMiddleware → user middleware → ExceptionMiddleware → router` — the context it
establishes is still ambient when an exception handler runs. A yield-dependency's is not: the
`AsyncExitStack` unwinds *below* `ExceptionMiddleware`, so its teardown happens first.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from sentrykit.integrations.base import BaseContextProvider
from sentrykit.registry import DSN, register_context_provider

__all__ = [
    "FastAPIProvider",
    "SentrykitMiddleware",
    "context_dependency",
    "install_error_handlers",
    "protect_app",
]


@register_context_provider("fastapi")
class FastAPIProvider(BaseContextProvider[Request]):
    """Establishes ambient context from a Starlette request and renders refusals as JSON.

    Construction is inherited from :class:`~sentrykit.integrations.base.BaseContextProvider`;
    see there for ``identify``, ``grants``, ``environment`` and the header options. This class
    supplies only the four framework seams.
    """

    @classmethod
    def from_dsn(cls, dsn: DSN) -> FastAPIProvider:
        """Build from ``fastapi://`` — the registry's door, used by ``install()``.

        A DSN-built provider has no application auth to call into, so it identifies callers by
        the header named in ``?header=`` (default
        :data:`~sentrykit.integrations.base.DEFAULT_PRINCIPAL_HEADER`). That suits an example
        app or a service behind a gateway that has already authenticated the caller. Anything
        else should construct the provider directly and pass ``identify=``.

        Args:
            dsn: The parsed address. Options: ``header`` (principal id header),
                ``request_id_header``.

        Returns:
            The provider.
        """
        raise NotImplementedError

    @property
    def name(self) -> str:
        """``fastapi``."""
        raise NotImplementedError

    def narrow(self, request: object) -> Request:
        """Check that ``request`` is a Starlette request.

        Args:
            request: The object the boundary handed over.

        Returns:
            The same object, typed.

        Raises:
            ConfigurationError: If it is not a Starlette request — which means this provider
                was wired to the wrong framework.
        """
        raise NotImplementedError

    def read_header(self, request: Request, name: str) -> str | None:
        """Read one header from a Starlette request. Starlette's headers are case-insensitive."""
        raise NotImplementedError

    def render_error(self, error: Exception) -> JSONResponse:
        """Render a sentrykit refusal as a JSON response carrying the ``_authz`` envelope.

        Args:
            error: A :class:`~sentrykit.errors.SentrykitError`.

        Returns:
            The response, at the status
            :func:`~sentrykit.integrations.base.status_for` maps the error to.
        """
        raise NotImplementedError


class SentrykitMiddleware:
    """Pure-ASGI middleware that establishes context for the request and releases it after.

    The release is in a ``finally`` and is not optional: a reused ASGI task that kept the
    previous request's principal would authorize the next caller as somebody else. See
    :mod:`sentrykit.integrations.base` for the measurement behind that.

    Non-HTTP scopes (``lifespan``, ``websocket``) pass straight through untouched.

    Args:
        app: The next ASGI application in the stack.
        provider: The provider to establish with. Defaults to the one wired into the installed
            governor by ``install(context_provider=...)``, and failing that to a
            header-identifying :class:`FastAPIProvider`.
    """

    def __init__(self, app: ASGIApp, provider: FastAPIProvider | None = None) -> None:
        raise NotImplementedError

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Establish, delegate, release.

        Args:
            scope: The ASGI scope.
            receive: The ASGI receive callable.
            send: The ASGI send callable.
        """
        raise NotImplementedError


def context_dependency(
    provider: FastAPIProvider | None = None,
) -> Callable[[Request], AsyncIterator[None]]:
    """Build an ``async`` yield-dependency that establishes context for one route.

    The route-scoped alternative to :class:`SentrykitMiddleware`, for an app that governs some
    of its routes and not others:

    ```python
    @app.get("/orders", dependencies=[Depends(context_dependency())])
    def list_orders() -> dict[str, object]: ...
    ```

    It must be ``async``: see this module's docstring for why a sync dependency cannot work.
    One difference from the middleware is worth knowing — the dependency's teardown runs
    *before* an exception handler, so ambient context is already released by the time a refusal
    is rendered. That costs nothing, because refusals are rendered from the exception.

    Args:
        provider: The provider to establish with. Defaults as for :class:`SentrykitMiddleware`.

    Returns:
        The dependency callable, ready to hand to ``Depends``.
    """
    raise NotImplementedError


def install_error_handlers(app: FastAPI, provider: FastAPIProvider | None = None) -> None:
    """Register a handler for every sentrykit error on ``app``.

    One handler per entry in :data:`~sentrykit.integrations.base.STATUS_BY_ERROR`, plus
    :class:`~sentrykit.errors.SentrykitError` itself as the catch-all. Starlette resolves a
    handler by walking the exception's MRO, so a host that subclasses a shipped error is
    covered without registering anything.

    Args:
        app: The application.
        provider: The provider whose :meth:`FastAPIProvider.render_error` builds the response.
    """
    raise NotImplementedError


def protect_app(
    app: FastAPI,
    *,
    provider: FastAPIProvider | None = None,
    middleware: bool = True,
    handlers: bool = True,
) -> FastAPIProvider:
    """Wire sentrykit into ``app`` in one call.

    Args:
        app: The application.
        provider: The provider to use. Defaults as for :class:`SentrykitMiddleware`.
        middleware: Whether to add :class:`SentrykitMiddleware`. Turn it off when context is
            established per route with :func:`context_dependency` instead.
        handlers: Whether to register the exception handlers.

    Returns:
        The provider that was wired, so a caller can hold on to it.
    """
    raise NotImplementedError
