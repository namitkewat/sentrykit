"""A minimal governed Flask app: three routes, one decorator, one provider.

Run it with `pixi run -e web run-flask` and drive it with the `curl` calls in the README.

The wiring order in :func:`create_app` is not arbitrary. ``install()`` runs before the app is
built so that :func:`~sentrykit.integrations.flask.protect_blueprint` has a governor to find,
and the provider is constructed *first* and passed to both, so the app and the engine share
one object rather than two that happen to agree.

The routes are the same URLs as `examples/fastapi_app`, on purpose: the service layer is
identical, the policy is identical, and only the twenty lines below differ between the two
frameworks.
"""

from __future__ import annotations

from flask import Blueprint, Flask, Request, request

from examples.flask_app.policy import POLICY_TEXT, build_grants
from examples.flask_app.service import export_orders, search_orders, summarize_orders
from sentrykit import configure, install
from sentrykit.integrations.flask import FlaskProvider, protect_blueprint


def _identify(request: Request) -> str | None:
    """Read the caller's principal id from ``x-user``.

    An authentication *stub*, and nothing more: a real app returns the subject of a verified
    session or token here. sentrykit stays out of that choice deliberately — it asks only for
    an id, and resolves the authority behind it through the grant store.

    Args:
        request: The Flask request.

    Returns:
        The principal id, or ``None`` for an unauthenticated caller — which fails closed at
        every protected call in the request.
    """
    return request.headers.get("x-user")


def create_app() -> Flask:
    """Build the example application.

    Returns:
        A Flask app whose ``orders`` blueprint is governed by sentrykit.
    """
    # ``verbose`` so the example is legible: the ``_authz`` envelope then carries the processed
    # arguments, the defaults that were injected and the rejections that were dropped. A
    # service would ship at the ``summary`` default.
    configure(verbosity="verbose")

    store = build_grants()
    provider = FlaskProvider(identify=_identify, grants=store)
    install(POLICY_TEXT, grant_store=store, context_provider=provider)

    app = Flask(__name__)
    # A blueprint rather than the whole app, to show the scoped form: only these routes get the
    # establish/release hooks, so an ungoverned surface can live beside them under one app.
    orders = Blueprint("orders", __name__, url_prefix="")

    @orders.get("/orders")
    def list_orders() -> dict[str, object]:
        """Search orders, passing on only the parameters the caller actually supplied.

        The omission is the demonstration: an absent ``region`` or ``limit`` is left out of the
        call entirely so policy can inject Alice's default, rather than being passed as
        ``None`` and rejected.

        Returns:
            The search result, with the ``_authz`` envelope the engine attached.
        """
        proposed: dict[str, object] = {}
        region = request.args.get("region")
        if region is not None:
            proposed["region"] = region
        limit = request.args.get("limit", type=int)
        if limit is not None:
            proposed["limit"] = limit
        return search_orders(**proposed)

    @orders.post("/orders/export")
    def export() -> dict[str, object]:
        """Export orders in the format the caller proposed.

        The format is passed straight through, unvalidated by this handler: refusing
        ``fmt="pdf"`` is the policy's job, and doing it here as well would be the scattered
        ``if`` statement sentrykit exists to remove.

        Returns:
            The export result, with the ``_authz`` envelope.
        """
        body = request.get_json()
        return export_orders(fmt=body["fmt"])

    @orders.get("/orders/summary")
    def summary() -> dict[str, object]:
        """Summarize orders by calling a protected callable that is not itself a route.

        This handler is unprotected. The call inside it is not, and it is authorized against
        the same ambient principal — which is what "action layer, not routing layer" means.

        Returns:
            The summary, with the ``_authz`` envelope.
        """
        return summarize_orders()

    protect_blueprint(orders, provider=provider)
    app.register_blueprint(orders)
    return app


app = create_app()
"""The module-level app `flask --app examples.flask_app.main run` looks for."""
