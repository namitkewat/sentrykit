"""The examples in `docs/web-frameworks.md` and the README's web section do what they say.

The unit-suite `test_documented_examples*.py` modules pin the quickstart and the store pages;
this pins the web page. Same reason, restated because it keeps mattering: documentation that
has drifted from the code is worse than none, because a reader trusts it, copies it, and then
debugs the wrong thing.

Every literal asserted here appears verbatim on one of those two pages. If a page and this file
disagree, one of them is a bug.

Two of these tests are unusual: they pin a **warning** rather than a feature. The page tells a
reader that a `response_model` strips the `_authz` envelope, and that a synchronous FastAPI
dependency cannot establish context. A warning nobody checks is a rumour, so both hazards are
reproduced here — if either stops being true, the page has to change.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("flask")

from examples.fastapi_app.main import create_app as create_fastapi_app
from examples.fastapi_app.policy import POLICY_TEXT, build_grants
from examples.fastapi_app.service import summarize_orders
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from flask import Blueprint, Flask
from starlette.requests import Request

from sentrykit import EntityRef, Principal, configure, install
from sentrykit.context import current_principal
from sentrykit.integrations.base import DEFAULT_PRINCIPAL_HEADER
from sentrykit.integrations.fastapi import (
    FastAPIProvider,
    context_dependency,
    protect_app,
)
from sentrykit.integrations.flask import FlaskProvider, protect_blueprint

SEARCH = 'Action::"orders.search"'
"""The action the README's refusal body names."""

ORDERS = 'Tool::"orders"'


@pytest.fixture
def client() -> Iterator[TestClient]:
    """The example app the page's `curl` recipes are run against."""
    with TestClient(create_fastapi_app()) as testclient:
        yield testclient


# --- the refusal body the page and the README both print -------------------------------------


@pytest.mark.integration
def test_the_refusal_body_is_exactly_what_both_pages_print(client: TestClient) -> None:
    """`docs/web-frameworks.md` — Refusals; and the README's web quickstart."""
    configure(verbosity="summary")

    response = client.get("/orders", headers={"x-user": "bob"})

    assert response.status_code == 403
    assert response.json() == {
        "detail": 'The policy denied action Action::"orders.search".',
        "error": "AuthzDenied",
        "_authz": {
            "decision": "deny",
            "reason": 'The policy denied action Action::"orders.search".',
            "action": SEARCH,
            "resource": ORDERS,
        },
    }


@pytest.mark.integration
def test_verbosity_off_returns_the_status_phrase_the_page_shows(client: TestClient) -> None:
    """`docs/web-frameworks.md` — the verbosity table: `{"detail": "Forbidden"}`."""
    configure(verbosity="off")

    response = client.get("/orders", headers={"x-user": "bob"})

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}


# --- the three `curl` recipes ----------------------------------------------------------------


@pytest.mark.integration
def test_the_first_curl_recipe_runs_on_injected_defaults(client: TestClient) -> None:
    """`curl -H 'x-user: alice' localhost:8000/orders`."""
    body = client.get("/orders", headers={"x-user": "alice"}).json()

    assert body["region"] == "eu"
    assert body["limit"] == 10
    assert set(body["_authz"]["defaults_applied"]) == {"region", "limit"}


@pytest.mark.integration
def test_the_second_curl_recipe_is_narrowed_and_says_so(client: TestClient) -> None:
    """`curl -H 'x-user: alice' 'localhost:8000/orders?region=cn&limit=5'`."""
    response = client.get("/orders?region=cn&limit=5", headers={"x-user": "alice"})
    body = response.json()

    assert response.status_code == 200
    assert body["region"] == "eu"
    assert body["limit"] == 5
    assert [item["name"] for item in body["_authz"]["rejected"]] == ["region"]


@pytest.mark.integration
def test_the_third_curl_recipe_is_refused(client: TestClient) -> None:
    """`curl -H 'x-user: bob' localhost:8000/orders`."""
    assert client.get("/orders", headers={"x-user": "bob"}).status_code == 403


# --- what the provider establishes -----------------------------------------------------------


@pytest.mark.integration
def test_the_channel_and_request_id_the_page_documents_are_established() -> None:
    """`docs/web-frameworks.md` — What the provider establishes."""
    store = build_grants()
    provider = FastAPIProvider(identify=lambda request: request.headers.get("x-user"), grants=store)
    install(POLICY_TEXT, grant_store=store, context_provider=provider)

    app = FastAPI()
    protect_app(app, provider=provider)

    @app.get("/env")
    def read_environment() -> dict[str, object]:
        """Report the ambient environment the provider established."""
        from sentrykit import current_environment

        return dict(current_environment())

    with TestClient(app) as client:
        body = client.get("/env", headers={"x-user": "alice", "X-Request-ID": "req-42"}).json()

    assert body["channel"] == "http"
    assert body["request_id"] == "req-42"


@pytest.mark.integration
def test_an_app_that_sends_no_correlation_id_still_gets_one() -> None:
    """The page: "otherwise a fresh UUID4"."""
    provider = FastAPIProvider(grants=build_grants())

    first = provider.request_id(Request({"type": "http", "headers": []}))
    second = provider.request_id(Request({"type": "http", "headers": []}))

    assert first and second and first != second


# --- the identity table ------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize(
    ("identity", "expected"),
    [
        ("alice", "alice"),
        (EntityRef("User", "alice"), "alice"),
        (Principal(id="carol", roles=("auditor",)), "carol"),
        (None, None),
    ],
    ids=["str", "EntityRef", "Principal", "None"],
)
def test_identify_accepts_every_return_value_the_page_lists(
    identity: object, expected: str | None
) -> None:
    """`docs/web-frameworks.md` — Identity: the app supplies the id, the store the authority."""
    provider = FastAPIProvider(identify=lambda _: identity, grants=build_grants())  # type: ignore[arg-type,return-value]

    resolved = provider.resolve_principal(Request({"type": "http", "headers": []}))

    assert (resolved.id if resolved is not None else None) == expected


@pytest.mark.integration
def test_a_dsn_built_provider_reads_the_header_the_page_names() -> None:
    """The page: `x-sentrykit-principal` by default, or `?header=x-user`."""
    from sentrykit.registry import build_context_provider

    assert DEFAULT_PRINCIPAL_HEADER == "x-sentrykit-principal"
    default = build_context_provider("fastapi://")
    named = build_context_provider("flask://?header=x-user")

    assert default is not None
    assert named is not None
    assert default.principal_header == "x-sentrykit-principal"  # type: ignore[attr-defined]
    assert named.principal_header == "x-user"  # type: ignore[attr-defined]


# --- the protected non-route callable ---------------------------------------------------------


@pytest.mark.integration
def test_an_unprotected_route_calling_a_protected_function_is_governed(
    client: TestClient,
) -> None:
    """`docs/web-frameworks.md` — Protected callables that are not routes; and the README."""
    allowed = client.get("/orders/summary", headers={"x-user": "alice"})
    refused = client.get("/orders/summary", headers={"x-user": "bob"})

    assert allowed.status_code == 200
    assert allowed.json()["summary"] == "3 open orders"
    assert refused.status_code == 403
    assert refused.json()["error"] == "AuthzDenied"


# --- the warnings, reproduced ------------------------------------------------------------------


@pytest.mark.integration
def test_a_response_model_really_does_strip_the_authz_envelope() -> None:
    """Pins the page's warning. If this ever passes with `_authz` present, delete the warning."""
    store = build_grants()
    provider = FastAPIProvider(identify=lambda request: request.headers.get("x-user"), grants=store)
    install(POLICY_TEXT, grant_store=store, context_provider=provider)
    configure(verbosity="verbose")

    from pydantic import BaseModel

    class Summary(BaseModel):
        """A response model that, like every response model, does not mention `_authz`."""

        summary: str

    app = FastAPI()
    protect_app(app, provider=provider)

    @app.get("/summary", response_model=Summary)
    def summary() -> dict[str, object]:
        """Return the protected callable's result, envelope and all."""
        return summarize_orders()

    with TestClient(app) as client:
        body = client.get("/summary", headers={"x-user": "alice"}).json()

    assert body == {"summary": "3 open orders"}
    assert "_authz" not in body


@pytest.mark.integration
def test_a_synchronous_dependency_really_cannot_establish_context() -> None:
    """Pins the page's warning about where context can and cannot be established.

    A `def` dependency runs in its own AnyIO worker thread with a copy of the context, so its
    establishment is discarded on return and the route sees nothing. The async yield-dependency
    sentrykit actually ships is asserted alongside it, so the contrast is the assertion.
    """
    store = build_grants()
    provider = FastAPIProvider(identify=lambda request: request.headers.get("x-user"), grants=store)
    install(POLICY_TEXT, grant_store=store, context_provider=provider)

    def sync_dependency(request: Request) -> None:
        """The shape the page warns against: establishment thrown away on return."""
        provider.establish(request)

    app = FastAPI()
    protect_app(app, provider=provider, middleware=False)

    @app.get("/sync-dep", dependencies=[Depends(sync_dependency)])
    def via_sync_dependency() -> dict[str, object]:
        """Report whether a principal survived the sync dependency."""
        principal = current_principal()
        return {"principal": principal.id if principal is not None else None}

    @app.get("/async-dep", dependencies=[Depends(context_dependency(provider))])
    def via_async_dependency() -> dict[str, object]:
        """Report whether a principal survived the shipped async dependency."""
        principal = current_principal()
        return {"principal": principal.id if principal is not None else None}

    with TestClient(app) as client:
        sync_result = client.get("/sync-dep", headers={"x-user": "alice"}).json()
        async_result = client.get("/async-dep", headers={"x-user": "alice"}).json()

    assert sync_result == {"principal": None}, "a sync dependency must not appear to work"
    assert async_result == {"principal": "alice"}


# --- the blueprint snippet ---------------------------------------------------------------------


@pytest.mark.integration
def test_protect_blueprint_governs_only_its_own_routes() -> None:
    """`docs/web-frameworks.md` — Governing one blueprint, with the page's `/api` prefix."""
    store = build_grants()
    provider = FlaskProvider(identify=lambda request: request.headers.get("x-user"), grants=store)
    install(POLICY_TEXT, grant_store=store, context_provider=provider)

    app = Flask(__name__)
    api = Blueprint("api", __name__, url_prefix="/api")

    @api.get("/who")
    def governed() -> dict[str, object]:
        """Inside the blueprint: the provider established a principal."""
        principal = current_principal()
        return {"principal": principal.id if principal is not None else None}

    @app.get("/who")
    def ungoverned() -> dict[str, object]:
        """Outside it: the hooks never ran, so nothing was established."""
        principal = current_principal()
        return {"principal": principal.id if principal is not None else None}

    protect_blueprint(api, provider=provider)
    app.register_blueprint(api)

    client = app.test_client()
    inside = client.get("/api/who", headers={"x-user": "alice"}).get_json()
    outside = client.get("/who", headers={"x-user": "alice"}).get_json()

    assert inside == {"principal": "alice"}
    assert outside == {"principal": None}
