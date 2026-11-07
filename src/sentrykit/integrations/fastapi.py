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

There are four places a provider could establish context, and only three of them work:

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
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentrykit.errors import ConfigurationError, SentrykitError
from sentrykit.integrations.base import (
    DEFAULT_PRINCIPAL_HEADER,
    DEFAULT_REQUEST_ID_HEADER,
    STATUS_BY_ERROR,
    BaseContextProvider,
    narrowing_headers,
)
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
        # ``or`` rather than the option's own default, so ``?header=`` with an empty value
        # falls back to the shipped header instead of wiring a provider that reads ``""``.
        return cls(
            principal_header=dsn.option("header") or DEFAULT_PRINCIPAL_HEADER,
            request_id_header=dsn.option("request_id_header") or DEFAULT_REQUEST_ID_HEADER,
        )

    @property
    def name(self) -> str:
        """``fastapi``."""
        return "fastapi"

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
        if isinstance(request, Request):
            return request
        actual = type(request)
        raise ConfigurationError(
            "the fastapi context provider expects a starlette.requests.Request but was given "
            f"a {actual.__module__}.{actual.__qualname__}; it is wired to the wrong framework"
        )

    def read_header(self, request: Request, name: str) -> str | None:
        """Read one header from a Starlette request. Starlette's headers are case-insensitive."""
        # Bound to an annotated local rather than returned directly, so the module still
        # type-checks in the default environment where starlette is absent and every symbol
        # imported from it is ``Any``.
        value: str | None = request.headers.get(name)
        return value

    def render_error(self, error: Exception) -> JSONResponse:
        """Render a sentrykit refusal as a JSON response carrying the ``_authz`` envelope.

        Args:
            error: A :class:`~sentrykit.errors.SentrykitError`.

        Returns:
            The response, at the status
            :func:`~sentrykit.integrations.base.status_for` maps the error to.
        """
        status, body = self.error_response(error)
        return JSONResponse(body, status_code=status)


def _effective_provider(provider: FastAPIProvider | None) -> FastAPIProvider:
    """Resolve the provider a boundary hook should establish with.

    The one place the defaulting rule lives, so the middleware, the dependency, the exception
    handlers and :func:`protect_app` cannot drift apart. Resolution is deferred to call time on
    purpose: ``install(context_provider=...)`` and the app wiring may then happen in either
    order, which is the difference between a documented ordering constraint and none at all.

    A governor wired to some *other* framework's provider is ignored rather than treated as an
    error, since a process may legitimately serve an ASGI app beside a WSGI one. The fallback
    is a bare header-identifying provider, which fails closed for any caller who sends no
    header.

    Args:
        provider: An explicitly supplied provider, or ``None``.

    Returns:
        The explicit provider, the installed governor's when it is a :class:`FastAPIProvider`,
        or a freshly built default.
    """
    if provider is not None:
        return provider
    # Imported in the body rather than at module scope: the engine pulls in the whole decision
    # path, and a framework adapter should not dictate the library's import order.
    from sentrykit.engine import current_governor

    governor = current_governor()
    wired = governor.context_provider if governor is not None else None
    if isinstance(wired, FastAPIProvider):
        return wired
    return FastAPIProvider()


def _narrowing_send(provider: FastAPIProvider, send: Send) -> Send:
    """Wrap ``send`` so the response's start message carries the narrowing headers.

    The headers have to be added at ``http.response.start``, because that is the one moment
    the status and headers are still mutable and every decision the route made has already
    been made. Reading them from the provider's
    :class:`~sentrykit.envelope.EnvelopeRecorder` rather than from
    :func:`~sentrykit.envelope.last_envelope` is what makes this work for a **sync** route:
    that route runs in an AnyIO worker thread holding a context *copy*, so nothing it sets
    survives its return, while a mutation to the recorder the middleware is still holding
    does. See ADR-029.

    Args:
        provider: The provider whose recorder to read.
        send: The ASGI send callable to wrap.

    Returns:
        A send callable that adds the headers to the start message and forwards everything
        else untouched.
    """

    async def wrapped(message: Message) -> None:
        if message["type"] == "http.response.start":
            extra = narrowing_headers(*provider.narrowing())
            if extra:
                # ASGI headers are a list of raw byte pairs, and the list is the server's.
                # Rebuilt rather than appended to, so a server that reuses or inspects the
                # original list is unaffected.
                added = [
                    (name.encode("latin-1"), value.encode("latin-1"))
                    for name, value in extra.items()
                ]
                message = {**message, "headers": [*(message.get("headers") or []), *added]}
        await send(message)

    return wrapped


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
        self.app = app
        self.provider = provider

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Establish, delegate, release.

        Args:
            scope: The ASGI scope.
            receive: The ASGI receive callable.
            send: The ASGI send callable.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        provider = _effective_provider(self.provider)
        # A Starlette request is a lazy view over the scope, so building one here costs
        # nothing and — crucially — does not consume the body the route is about to read.
        established = provider.establish(Request(scope, receive))
        try:
            await self.app(scope, receive, _narrowing_send(provider, send))
        finally:
            provider.release(established)


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

    async def dependency(request: Request) -> AsyncIterator[None]:
        """Establish for the duration of one route, and release however the route ends."""
        resolved = _effective_provider(provider)
        established = resolved.establish(request)
        try:
            yield
        finally:
            resolved.release(established)

    return dependency


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

    async def render(request: Request, exc: Exception) -> Response:
        """Starlette's handler shape. The request is unused: a refusal is built from ``exc``."""
        # Bound to an annotated local for the same reason ``read_header`` is: in an
        # environment where starlette is installed but fastapi is not -- which is exactly the
        # ``agent`` environment, since mcp depends on starlette -- ``JSONResponse`` resolves
        # to ``Any`` while ``Response`` is a real type, and returning it directly is an error.
        response: Response = _effective_provider(provider).render_error(exc)
        return response

    for error_type in STATUS_BY_ERROR:
        # The mapping is keyed by ``BaseException`` so it can describe anything, but Starlette
        # dispatches only on ``Exception`` — and nothing outside it belongs in an HTTP body.
        if issubclass(error_type, Exception):
            app.add_exception_handler(error_type, render)
    # Registered last and unconditionally, so the catch-all is there even if the mapping above
    # is ever trimmed. Re-registering a key with the same handler is a no-op.
    app.add_exception_handler(SentrykitError, render)


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
    # Resolved eagerly, unlike everywhere else, because the return value is the point of the
    # function: a caller asking "what got wired?" must not be answered "whatever is installed
    # by the time the first request arrives".
    resolved = _effective_provider(provider)
    if middleware:
        app.add_middleware(SentrykitMiddleware, provider=resolved)
    if handlers:
        install_error_handlers(app, resolved)
    return resolved
