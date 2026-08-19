"""The Flask provider, driven through the example app over real HTTP.

The shared behaviour table is the same one ``test_fastapi_provider.py`` runs, and the point of
running it twice is that the answers are identical: same statuses, same ``error`` names, same
``_authz`` shape, from a WSGI stack whose hooks have nothing in common with ASGI's.

What is asked only here is what is peculiar to Flask: that ``protect_app`` governs a whole
application, and that ``protect_blueprint`` governs *only* its own blueprint — the second
being the one an app with an ungoverned surface beside a governed one depends on.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

pytest.importorskip("flask")

from examples.flask_app.policy import POLICY_TEXT, build_grants
from examples.flask_app.service import search_orders
from flask import Blueprint, Flask

import sentrykit
from sentrykit.context import Principal, current_principal, principal_context
from sentrykit.integrations.flask import FlaskProvider, protect_app, protect_blueprint

PRINCIPAL_HEADER = "x-user"
"""The example's auth stub, repeated here for the throwaway apps built in this module."""


def _report_principal() -> dict[str, object]:
    """Name the ambient principal, or ``None``. The whole body of the throwaway routes."""
    principal = current_principal()
    return {"principal": principal.id if principal is not None else None}


@pytest.mark.integration
def test_the_shared_web_contract_holds_over_flask(
    flask_client: Any, web_contract_case: Callable[[Any], None]
) -> None:
    """Every row of the shared web behaviour table, answered by the WSGI stack."""
    web_contract_case(flask_client)


@pytest.mark.integration
def test_a_refusal_body_is_trimmed_to_the_configured_verbosity(
    flask_client: Any, refusal_verbosity_case: Callable[[Any], None]
) -> None:
    """A refusal is rendered from the exception, so its trimming needs its own proof."""
    refusal_verbosity_case(flask_client)


@pytest.mark.integration
def test_protect_app_governs_every_route_on_the_application() -> None:
    """The application-wide form: one call, and every route establishes and releases."""
    sentrykit.configure(verbosity="verbose")
    store = build_grants()
    provider = FlaskProvider(
        identify=lambda request: request.headers.get(PRINCIPAL_HEADER), grants=store
    )
    sentrykit.install(POLICY_TEXT, grant_store=store, context_provider=provider)

    app = Flask(__name__)
    protect_app(app, provider=provider)

    @app.get("/orders")
    def list_orders() -> dict[str, object]:
        return search_orders()

    client = app.test_client()

    allowed = client.get("/orders", headers={PRINCIPAL_HEADER: "alice"})
    refused = client.get("/orders")

    assert allowed.status_code == 200
    assert allowed.get_json()["region"] == "eu"
    assert refused.status_code == 403
    assert refused.get_json()["error"] == "NoContext"


@pytest.mark.integration
def test_a_protected_blueprint_leaves_the_routes_outside_it_alone() -> None:
    """Establishment and release are blueprint-scoped, not application-scoped.

    An app that governs its ``/api`` surface must not have the hooks fire for its marketing
    pages — and "fire" is not harmless: ``before_request`` *clears* the ambient context for an
    unauthenticated caller, so an app-wide registration would silently neutralize a principal
    the host had established itself. That is what the ambient block below detects.
    """
    provider = FlaskProvider(
        identify=lambda request: request.headers.get(PRINCIPAL_HEADER), grants=build_grants()
    )
    app = Flask(__name__)
    governed = Blueprint("governed", __name__, url_prefix="/governed")
    governed.get("/who")(_report_principal)
    protect_blueprint(governed, provider=provider)
    app.register_blueprint(governed)
    app.get("/open/who")(_report_principal)

    client = app.test_client()

    with principal_context(Principal(id="ambient")):
        outside = client.get("/open/who")

        assert outside.get_json() == {"principal": "ambient"}
        assert current_principal() is not None
        assert current_principal().id == "ambient"

    inside = client.get("/governed/who", headers={PRINCIPAL_HEADER: "alice"})

    assert inside.get_json() == {"principal": "alice"}
    assert current_principal() is None
