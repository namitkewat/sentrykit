"""The Flask context provider.

The WSGI half of ADR-009. Same decorator, same envelope, same statuses — a different pair of
hooks:

```python
from flask import Flask
from sentrykit.integrations.flask import FlaskProvider, protect_app

app = Flask(__name__)
protect_app(app, provider=FlaskProvider(identify=lambda request: request.headers.get("x-user")))
```

## Establish in `before_request`, release in `teardown_request`

`dev-docs/notes/phase-3-research.md` §4 pinned the ordering that makes this work. For a
request whose view raises, Flask runs:

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

from flask import Blueprint, Flask, Request, Response

from sentrykit.integrations.base import BaseContextProvider
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
    supplies only the four framework seams.
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
        raise NotImplementedError

    @property
    def name(self) -> str:
        """``flask``."""
        raise NotImplementedError

    def narrow(self, request: object) -> Request:
        """Check that ``request`` is a Flask request.

        Args:
            request: The object the boundary handed over.

        Returns:
            The same object, typed.

        Raises:
            ConfigurationError: If it is not a Flask request — which means this provider was
                wired to the wrong framework.
        """
        raise NotImplementedError

    def read_header(self, request: Request, name: str) -> str | None:
        """Read one header from a Flask request. Werkzeug's headers are case-insensitive."""
        raise NotImplementedError

    def render_error(self, error: Exception) -> tuple[Response, int]:
        """Render a sentrykit refusal as a JSON response carrying the ``_authz`` envelope.

        Args:
            error: A :class:`~sentrykit.errors.SentrykitError`.

        Returns:
            ``(response, status)`` — the pair Flask accepts from an error handler, at the
            status :func:`~sentrykit.integrations.base.status_for` maps the error to.
        """
        raise NotImplementedError

    def before_request(self) -> None:
        """Establish ambient context for the current request, parking the scope on ``g``.

        Registered as a ``before_request`` hook. Takes no arguments and returns ``None``, which
        is Flask's contract for "carry on with the request" — the provider never short-circuits
        a request itself, because refusing is the decorator's job and an unauthenticated caller
        may well be hitting a route that is not protected at all.
        """
        raise NotImplementedError

    def teardown_request(self, error: BaseException | None = None) -> None:
        """Release the context established for the current request.

        Registered as a ``teardown_request`` hook, and total: a request whose
        ``before_request`` never ran, or ran and raised, has no scope on ``g``, and that is a
        no-op rather than a ``KeyError``.

        Args:
            error: The exception that ended the request, or ``None``. Accepted because Flask
                passes it; the release is the same either way.
        """
        raise NotImplementedError


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
    raise NotImplementedError


def protect_app(app: Flask, *, provider: FlaskProvider | None = None) -> FlaskProvider:
    """Wire sentrykit into ``app`` in one call.

    Registers the ``before_request`` establishment, the ``teardown_request`` release, and the
    error handlers, application-wide.

    Args:
        app: The application.
        provider: The provider to use. Defaults to the one wired into the installed governor by
            ``install(context_provider=...)``, and failing that to a header-identifying
            :class:`FlaskProvider`.

    Returns:
        The provider that was wired, so a caller can hold on to it.
    """
    raise NotImplementedError


def protect_blueprint(
    blueprint: Blueprint, *, provider: FlaskProvider | None = None
) -> FlaskProvider:
    """Wire sentrykit into one blueprint rather than the whole application.

    For an app where only part of the surface is governed — an ``/api`` blueprint in front of
    an unprotected marketing site, or two blueprints authenticating callers differently. The
    hooks are blueprint-scoped (``Blueprint.before_request`` /
    ``Blueprint.teardown_request``), so they run only for this blueprint's routes, and its
    error handlers likewise.

    Args:
        blueprint: The blueprint.
        provider: The provider to use. Defaults as for :func:`protect_app`.

    Returns:
        The provider that was wired.
    """
    raise NotImplementedError
