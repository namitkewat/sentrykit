"""The Flask context provider.

The WSGI half of one-decorator-N-providers. Same decorator, same envelope, same statuses — a
different pair of hooks:

```python
from flask import Flask
from sentrykit.integrations.flask import FlaskProvider, protect_app

app = Flask(__name__)
protect_app(app, provider=FlaskProvider(identify=lambda request: request.headers.get("x-user")))
```

## Establish in `before_request`, release in `teardown_request`

Flask's hook ordering is what makes this work. For a request whose view raises, Flask runs:

```
before_request  ->  view raises  ->  errorhandler renders  ->  teardown_request
```

so the handler still sees the ambient principal, and `teardown_request` is the last hook — the
right place for the release. Three details follow from the same observation and each one is a
bug if ignored:

* `teardown_request` runs **even when `before_request` raised**, so the release has to cope
  with there being no scope to release.
* `before_request` and `teardown_request` fire **even for a 404**, so establishment cannot
  assume a view was matched.
* Everything happens on **one thread**, so the `ContextVar` token captured on the way in is
  always resettable on the way out.

That release is the whole reason this module is careful. Flask serves a request on a pooled
worker thread, and its test client serves one in the caller's own context: an un-reset
`ContextVar` from request *N* is still ambient when request *N+1* starts, and request *N+1*
would be authorized as request *N*'s principal. §5 of the same notes measured it.

Flask `async def` views need the `asgiref` extra and are not exercised here; sync views are
the shape this provider is built for.
"""

from __future__ import annotations

from flask import Blueprint, Flask, Request, Response, g, has_app_context, jsonify
from flask import request as current_request

from sentrykit.context import ContextScope
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
    "SCOPE_KEY",
    "FlaskProvider",
    "install_error_handlers",
    "protect_app",
    "protect_blueprint",
]

SCOPE_KEY: str = "_sentrykit_scope"
"""Attribute on :data:`flask.g` the request's context scope is parked under.

``g`` rather than a module global because it is request-scoped and thread-local already, which
is exactly the lifetime the scope has. The name is public so a host debugging a leak knows what
to look at.
"""


@register_context_provider("flask")
class FlaskProvider(BaseContextProvider[Request]):
    """Establishes ambient context from a Flask request and renders refusals as JSON.

    Construction is inherited from :class:`~sentrykit.integrations.base.BaseContextProvider`;
    see there for ``identify``, ``grants``, ``environment`` and the header options. This class
    supplies only the four framework seams plus the two Flask hooks.
    """

    @classmethod
    def from_dsn(cls, dsn: DSN) -> FlaskProvider:
        """Build from ``flask://`` — the registry's door, used by ``install()``.

        A DSN-built provider has no application auth to call into, so it identifies callers by
        the header named in ``?header=`` (default
        :data:`~sentrykit.integrations.base.DEFAULT_PRINCIPAL_HEADER`). Real deployments
        construct the provider directly and pass ``identify=``.

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
        """``flask``."""
        return "flask"

    def narrow(self, request: object) -> Request:
        """Check that ``request`` is a Flask request, unwrapping the request-local proxy.

        Inside a request, ``flask.request`` is a :class:`werkzeug.local.LocalProxy`, not a
        :class:`flask.Request`. The proxy forwards ``__class__``, so ``isinstance`` alone
        would accept it and quietly hand the *proxy* to the application's ``identify``
        callback — an object whose attribute lookups fail the moment the request context is
        gone. It is unwrapped here instead, so ``identify`` and ``environment`` always receive
        the real request and may keep it.

        Args:
            request: The object the boundary handed over — a request or a proxy to one.

        Returns:
            The underlying request, typed.

        Raises:
            ConfigurationError: If it is not a Flask request — which means this provider was
                wired to the wrong framework.
        """
        unwrap = getattr(request, "_get_current_object", None)
        if callable(unwrap):
            try:
                request = unwrap()
            except RuntimeError as exc:
                raise ConfigurationError(
                    "the flask context provider was handed a request-local proxy bound to no "
                    "request; establish() belongs in a before_request hook"
                ) from exc
        if isinstance(request, Request):
            return request
        actual = type(request)
        raise ConfigurationError(
            "the flask context provider expects a flask.Request but was given a "
            f"{actual.__module__}.{actual.__qualname__}; it is wired to the wrong framework"
        )

    def read_header(self, request: Request, name: str) -> str | None:
        """Read one header from a Flask request. Werkzeug's headers are case-insensitive."""
        # Bound to an annotated local rather than returned directly, so the module still
        # type-checks in the default environment where flask is absent and every symbol
        # imported from it is ``Any``.
        value: str | None = request.headers.get(name)
        return value

    def render_error(self, error: Exception) -> tuple[Response, int]:
        """Render a sentrykit refusal as a JSON response carrying the ``_authz`` envelope.

        Args:
            error: A :class:`~sentrykit.errors.SentrykitError`.

        Returns:
            ``(response, status)`` — the pair Flask accepts from an error handler, at the
            status :func:`~sentrykit.integrations.base.status_for` maps the error to.
        """
        status, body = self.error_response(error)
        # ``jsonify`` needs an application context; an error handler always runs inside one.
        return jsonify(body), status

    def before_request(self) -> None:
        """Establish ambient context for the current request, parking the scope on ``g``.

        Registered as a ``before_request`` hook. Takes no arguments and returns ``None``, which
        is Flask's contract for "carry on with the request" — the provider never short-circuits
        a request itself, because refusing is the decorator's job and an unauthenticated caller
        may well be hitting a route that is not protected at all.
        """
        # Parked even when it is ``None`` (an unauthenticated caller establishes no scope), so
        # ``g`` records that this hook ran rather than leaving teardown to guess.
        setattr(g, SCOPE_KEY, self.establish(current_request))

    def after_request(self, response: Response) -> Response:
        """Add the narrowing headers to the outgoing response.

        Registered as an ``after_request`` hook, which is the last place the headers are still
        mutable and runs before ``teardown_request`` drops the recorder. Flask serves a request
        on one thread in one context, so unlike the ASGI side there is no copied-context
        problem here — the recorder is used anyway, because it is the channel that answers the
        *response-level* question (a view may make several protected calls) and because one
        answer shared by both frameworks is worth more than two shaped by their own plumbing.

        Args:
            response: The response Flask is about to send.

        Returns:
            The same response, with the headers added when anything was narrowed. An
            unprotected route, or one that narrowed nothing, is returned untouched.
        """
        for name, value in narrowing_headers(*self.narrowing()).items():
            response.headers[name] = value
        return response

    def teardown_request(self, error: BaseException | None = None) -> None:
        """Release the context established for the current request.

        Registered as a ``teardown_request`` hook, and total: a request whose
        ``before_request`` never ran, or ran and raised, has no scope on ``g``, and that is a
        no-op rather than a ``KeyError``. It tolerates being called with no application context
        at all, so a host driving the hooks by hand cannot turn a missing context into a
        teardown exception that masks the real one.

        Args:
            error: The exception that ended the request, or ``None``. Accepted because Flask
                passes it; the release is the same either way, since
                :meth:`~sentrykit.integrations.base.BaseContextProvider.release` is what makes
                the *next* request safe and that is owed regardless of how this one ended.
        """
        scope: ContextScope | None = None
        if has_app_context():
            parked = g.pop(SCOPE_KEY, None)
            if isinstance(parked, ContextScope):
                scope = parked
        # ``release`` is total and does not raise: it clears the context outright when there is
        # no scope, and :func:`sentrykit.context._restore` downgrades an unusable token to a
        # clear rather than letting it escape. Nothing here can mask ``error``.
        self.release(scope)


def _effective_provider(provider: FlaskProvider | None) -> FlaskProvider:
    """Resolve the provider the Flask hooks should be bound to.

    The one place the defaulting rule lives, so :func:`install_error_handlers`,
    :func:`protect_app` and :func:`protect_blueprint` cannot drift apart.

    Unlike the ASGI side, resolution happens at *wiring* time rather than per request: Flask's
    hooks are registered as bound methods, and a hook that re-resolved the provider on every
    request could establish with one and release with another. The cost is a documented
    ordering — ``install(context_provider=...)`` before ``protect_app(...)`` — and it buys
    nothing to defer, because the grant store is already resolved lazily by
    :attr:`~sentrykit.integrations.base.BaseContextProvider.grants`.

    A governor wired to some *other* framework's provider is ignored rather than treated as an
    error, since a process may legitimately serve a WSGI app beside an ASGI one. The fallback
    is a bare header-identifying provider, which fails closed for any caller who sends no
    header.

    Args:
        provider: An explicitly supplied provider, or ``None``.

    Returns:
        The explicit provider, the installed governor's when it is a :class:`FlaskProvider`, or
        a freshly built default.
    """
    if provider is not None:
        return provider
    # Imported in the body rather than at module scope: the engine pulls in the whole decision
    # path, and a framework adapter should not dictate the library's import order.
    from sentrykit.engine import current_governor

    governor = current_governor()
    wired = governor.context_provider if governor is not None else None
    if isinstance(wired, FlaskProvider):
        return wired
    return FlaskProvider()


def install_error_handlers(
    target: Flask | Blueprint, provider: FlaskProvider | None = None
) -> None:
    """Register a handler for every sentrykit error on ``target``.

    One handler per entry in :data:`~sentrykit.integrations.base.STATUS_BY_ERROR`, plus
    :class:`~sentrykit.errors.SentrykitError` itself as the catch-all. Flask resolves a handler
    by walking the exception's MRO, so a host that subclasses a shipped error is covered
    without registering anything.

    Args:
        target: The application or blueprint to register on.
        provider: The provider whose :meth:`FlaskProvider.render_error` builds the response.
    """
    resolved = _effective_provider(provider)
    # ``SentrykitError`` is already a key of the mapping; naming it again is a harmless
    # re-registration of the same handler and keeps the catch-all explicit at the call site.
    for error_type in (*STATUS_BY_ERROR, SentrykitError):
        # Flask registers handlers for ``Exception`` subclasses only; the mapping is keyed by
        # ``BaseException`` so a future entry could in principle be neither.
        if issubclass(error_type, Exception):
            target.register_error_handler(error_type, resolved.render_error)


def protect_app(app: Flask, *, provider: FlaskProvider | None = None) -> FlaskProvider:
    """Wire sentrykit into ``app`` in one call.

    Registers the ``before_request`` establishment, the ``after_request`` narrowing headers,
    the ``teardown_request`` release, and the error handlers, application-wide.

    Args:
        app: The application.
        provider: The provider to use. Defaults to the one wired into the installed governor by
            ``install(context_provider=...)``, and failing that to a header-identifying
            :class:`FlaskProvider`. Call ``install()`` first if you want it picked up — see
            :func:`_effective_provider` for why the default is resolved here and not per
            request.

    Returns:
        The provider that was wired, so a caller can hold on to it.
    """
    resolved = _effective_provider(provider)
    # Bound methods: ``before_request`` takes no arguments and ``teardown_request`` takes the
    # exception, which is exactly what Flask passes each hook.
    app.before_request(resolved.before_request)
    app.after_request(resolved.after_request)
    app.teardown_request(resolved.teardown_request)
    install_error_handlers(app, resolved)
    return resolved


def protect_blueprint(
    blueprint: Blueprint, *, provider: FlaskProvider | None = None
) -> FlaskProvider:
    """Wire sentrykit into one blueprint rather than the whole application.

    For an app where only part of the surface is governed — an ``/api`` blueprint in front of
    an unprotected marketing site, or two blueprints authenticating callers differently. The
    hooks are blueprint-scoped (``Blueprint.before_request`` / ``Blueprint.after_request`` /
    ``Blueprint.teardown_request``), so they run only for this blueprint's routes, and its
    error handlers likewise.

    Args:
        blueprint: The blueprint.
        provider: The provider to use. Defaults as for :func:`protect_app`.

    Returns:
        The provider that was wired.
    """
    resolved = _effective_provider(provider)
    blueprint.before_request(resolved.before_request)
    blueprint.after_request(resolved.after_request)
    blueprint.teardown_request(resolved.teardown_request)
    install_error_handlers(blueprint, resolved)
    return resolved
