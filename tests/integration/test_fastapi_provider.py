"""The FastAPI provider, driven through the example app over real HTTP.

The shared behaviour table lives in ``conftest.py`` and is answered identically here and in
``test_flask_provider.py`` — that sameness *is* the ADR-009 claim, so the two modules ask the
same questions of two different stacks and neither is allowed to answer them its own way.

What is asked only here is what is peculiar to ASGI: that a sync ``def`` route reaches the
ambient principal across the AnyIO worker-thread hop just as an ``async def`` route does, that
a non-HTTP scope passes the middleware untouched, and that the route-scoped dependency form
works as an alternative to the middleware.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

pytest.importorskip("fastapi")

from examples.fastapi_app.policy import POLICY_TEXT, build_grants
from examples.fastapi_app.service import search_orders
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.types import Receive, Scope, Send

import sentrykit
from sentrykit.integrations.fastapi import (
    FastAPIProvider,
    SentrykitMiddleware,
    context_dependency,
    install_error_handlers,
)

PRINCIPAL_HEADER = "x-user"
"""The example's auth stub, repeated here for the throwaway app built at the bottom."""


@pytest.mark.integration
def test_the_shared_web_contract_holds_over_fastapi(
    fastapi_client: Any, web_contract_case: Callable[[Any], None]
) -> None:
    """Every row of the phase-3 behaviour table, answered by the ASGI stack."""
    web_contract_case(fastapi_client)


@pytest.mark.integration
def test_a_refusal_body_is_trimmed_to_the_configured_verbosity(
    fastapi_client: Any, refusal_verbosity_case: Callable[[Any], None]
) -> None:
    """A refusal is rendered from the exception, so its trimming needs its own proof."""
    refusal_verbosity_case(fastapi_client)


@pytest.mark.integration
def test_a_sync_route_reaches_the_ambient_principal(fastapi_client: Any) -> None:
    """``GET /orders`` is a ``def`` route, so it runs in an AnyIO worker thread.

    The worker gets a *copy* of the request's context, and that copy is what carries the
    principal. A provider that established from a sync dependency instead of the middleware
    would fail closed here, which is why the shape of this one route is worth an assertion.
    """
    reply = fastapi_client.get("/orders", user="alice")

    assert reply.status == 200
    assert reply.authz["principal"] == 'User::"alice"'


@pytest.mark.integration
def test_an_async_route_reaches_the_ambient_principal(fastapi_client: Any) -> None:
    """``POST /orders/export`` is ``async def`` and runs on the event loop itself."""
    reply = fastapi_client.post("/orders/export", json={"fmt": "csv"}, user="bob")

    assert reply.status == 200
    assert reply.authz["principal"] == 'User::"bob"'


@pytest.mark.integration
async def test_a_non_http_scope_reaches_the_inner_app_untouched() -> None:
    """A lifespan scope is not a request: nothing to identify, and nothing to release."""
    received: list[Scope] = []

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        received.append(scope)

    async def receive() -> dict[str, object]:
        return {"type": "lifespan.startup"}

    async def send(message: object) -> None:
        """Discard."""

    lifespan: Scope = {"type": "lifespan", "asgi": {"version": "3.0"}}
    middleware = SentrykitMiddleware(inner, provider=FastAPIProvider(grants=build_grants()))

    await middleware(lifespan, receive, send)

    assert received == [lifespan]
    assert received[0] is lifespan
    assert sentrykit.current_principal() is None


@pytest.mark.integration
def test_the_dependency_form_governs_the_route_it_is_declared_on() -> None:
    """The route-scoped alternative to the middleware, for a partly governed application.

    Worth its own app rather than a row in the shared table: the dependency's teardown unwinds
    *below* the exception handler, so a refusal here is rendered with the ambient context
    already released. That it still comes back as a 403 carrying the action is the evidence
    that the renderer reads the exception and not the context.
    """
    sentrykit.configure(verbosity="verbose")
    store = build_grants()
    provider = FastAPIProvider(
        identify=lambda request: request.headers.get(PRINCIPAL_HEADER), grants=store
    )
    sentrykit.install(POLICY_TEXT, grant_store=store, context_provider=provider)

    app = FastAPI()
    install_error_handlers(app, provider)

    @app.get("/orders", dependencies=[Depends(context_dependency(provider))])
    def list_orders() -> dict[str, object]:
        return search_orders()

    client = TestClient(app)

    allowed = client.get("/orders", headers={PRINCIPAL_HEADER: "alice"})
    refused = client.get("/orders")

    assert allowed.status_code == 200
    assert allowed.json()["region"] == "eu"
    assert refused.status_code == 403
    assert refused.json()["error"] == "NoContext"
