"""Nothing about request *N* survives into request *N+1*.

This is the worst failure sentrykit could have — request *N+1* authorized as request *N*'s
principal — and `dev-docs/notes/phase-3-research.md` §5 measured that it is reachable on both
frameworks if the provider stops releasing what it established. So it gets its own module, and
the assertions are written to *fail* when the release is deleted rather than to pass because
the test harness happened to isolate them.

The two frameworks need different proofs, and the difference is the whole reason this file is
longer than it looks:

* **Flask** runs a request on the caller's own thread and in the caller's own context, so an
  un-reset ``ContextVar`` really is still ambient when the next call starts. A sequence
  through one test client is a genuine leak test there.
* **FastAPI** does not: ``TestClient`` drives every request through its own portal task,
  starting from a fresh copy of the context, so a leaky middleware still looks clean through
  it. The behavioural sequence is kept anyway — it is what a reader expects to see — but the
  assertion with teeth drives the ASGI callable twice *inside one context* and asks what is
  ambient between the two calls.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("flask")

import anyio
from examples.fastapi_app.main import create_app as create_fastapi_app
from examples.fastapi_app.policy import build_grants as build_fastapi_grants
from examples.flask_app.main import create_app as create_flask_app
from examples.flask_app.policy import build_grants as build_flask_grants
from fastapi.testclient import TestClient
from flask import Request as FlaskRequest
from starlette.requests import Request as StarletteRequest
from starlette.types import Scope
from werkzeug.test import EnvironBuilder

import sentrykit
from sentrykit.integrations.fastapi import FastAPIProvider
from sentrykit.integrations.flask import FlaskProvider

PRINCIPAL_HEADER = "x-user"


def _http_scope(path: str, *, user: str | None = None) -> Scope:
    """Build a minimal ASGI ``http`` scope, verified against Starlette 1.6 by driving it.

    Args:
        path: The request path.
        user: The principal id to send in :data:`PRINCIPAL_HEADER`, or ``None`` to send none.

    Returns:
        The scope.
    """
    headers = [(b"host", b"testserver")]
    if user is not None:
        headers.append((b"x-user", user.encode()))
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }


async def _drive(app: Any, scope: Scope) -> tuple[int, dict[str, Any]]:
    """Call an ASGI application directly, in the caller's own task and context.

    The point of not using ``TestClient``: it would run the app in a portal task with a fresh
    copy of the context, which is exactly the isolation this test must not have.

    Args:
        app: The ASGI application.
        scope: The connection scope.

    Returns:
        ``(status, body)``.
    """
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(scope, receive, send)

    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, json.loads(payload)


# --- Flask ---------------------------------------------------------------------------------


@pytest.mark.integration
def test_flask_authorizes_each_request_as_its_own_caller() -> None:
    """Four requests on one client, and none of them is answered as the previous caller.

    Flask's test client serves the request in the caller's context, so a provider that stopped
    resetting in ``teardown_request`` would answer the second call as alice and this would go
    green-to-red immediately.
    """
    client = create_flask_app().test_client()

    alice = client.get("/orders", headers={PRINCIPAL_HEADER: "alice"})
    anonymous = client.get("/orders")
    bob = client.get("/orders", headers={PRINCIPAL_HEADER: "bob"})
    anonymous_again = client.get("/orders")

    assert alice.status_code == 200
    assert alice.get_json()["region"] == "eu"
    assert anonymous.status_code == 403
    assert anonymous.get_json()["error"] == "NoContext"
    assert bob.status_code == 403
    assert bob.get_json()["error"] == "AuthzDenied"
    assert anonymous_again.status_code == 403
    assert anonymous_again.get_json()["error"] == "NoContext"


@pytest.mark.integration
def test_flask_leaves_no_principal_behind_in_the_callers_own_context() -> None:
    """The direct form of the same claim, asserted where the leak would actually be visible."""
    client = create_flask_app().test_client()

    response = client.get("/orders", headers={PRINCIPAL_HEADER: "alice"})

    assert response.status_code == 200
    assert sentrykit.current_principal() is None
    assert sentrykit.last_envelope() is None


# --- FastAPI -------------------------------------------------------------------------------


@pytest.mark.integration
def test_fastapi_authorizes_each_request_as_its_own_caller() -> None:
    """The behavioural sequence, for symmetry with Flask — and it is *not* the teeth.

    ``TestClient`` runs every request through its own portal task, which starts from a fresh
    copy of the context, so this passes even against a middleware that never releases anything.
    It is kept because it is the sequence a reader expects to find, and because it would still
    catch a provider that established the *wrong* principal. The assertion that catches a
    missing release is the next one.
    """
    client = TestClient(create_fastapi_app())

    alice = client.get("/orders", headers={PRINCIPAL_HEADER: "alice"})
    anonymous = client.get("/orders")
    bob = client.get("/orders", headers={PRINCIPAL_HEADER: "bob"})
    anonymous_again = client.get("/orders")

    assert alice.status_code == 200
    assert alice.json()["region"] == "eu"
    assert anonymous.status_code == 403
    assert anonymous.json()["error"] == "NoContext"
    assert bob.status_code == 403
    assert bob.json()["error"] == "AuthzDenied"
    assert anonymous_again.status_code == 403
    assert anonymous_again.json()["error"] == "NoContext"


@pytest.mark.integration
def test_fastapi_leaves_no_principal_behind_between_two_calls_in_one_context() -> None:
    """Two requests, one task, one ``contextvars`` context — and nothing ambient between them.

    This is the assertion with teeth. Confirmed by construction: an otherwise identical
    middleware with the ``finally: provider.release(scope)`` removed leaves alice ambient at
    the ``between`` checkpoint, while every status code in this test stays exactly the same —
    because ``establish()`` clears the context for an unauthenticated caller, so the second
    call fails closed either way. Only the checkpoint distinguishes them.
    """
    app = create_fastapi_app()
    checkpoints: dict[str, object] = {}

    async def two_calls() -> tuple[tuple[int, dict[str, Any]], tuple[int, dict[str, Any]]]:
        first = await _drive(app, _http_scope("/orders", user="alice"))
        checkpoints["between"] = sentrykit.current_principal()
        second = await _drive(app, _http_scope("/orders"))
        checkpoints["after"] = sentrykit.current_principal()
        return first, second

    (first_status, first_body), (second_status, second_body) = anyio.run(two_calls)

    assert first_status == 200
    assert first_body["region"] == "eu"
    assert checkpoints["between"] is None
    assert second_status == 403
    assert second_body["error"] == "NoContext"
    assert checkpoints["after"] is None


# --- both, at the provider itself ----------------------------------------------------------


@pytest.mark.integration
def test_the_fastapi_provider_releases_what_it_established() -> None:
    provider = FastAPIProvider(
        identify=lambda request: request.headers.get(PRINCIPAL_HEADER),
        grants=build_fastapi_grants(),
    )
    request = StarletteRequest(_http_scope("/orders", user="alice"))

    scope = provider.establish(request)
    established = sentrykit.current_principal()
    provider.release(scope)

    assert established is not None
    assert established.id == "alice"
    assert sentrykit.current_principal() is None


@pytest.mark.integration
def test_the_flask_provider_releases_what_it_established() -> None:
    provider = FlaskProvider(
        identify=lambda request: request.headers.get(PRINCIPAL_HEADER),
        grants=build_flask_grants(),
    )
    builder = EnvironBuilder(path="/orders", headers={PRINCIPAL_HEADER: "alice"})
    request = FlaskRequest(builder.get_environ())

    scope = provider.establish(request)
    established = sentrykit.current_principal()
    provider.release(scope)

    assert established is not None
    assert established.id == "alice"
    assert sentrykit.current_principal() is None


@pytest.mark.integration
@pytest.mark.parametrize("provider_class", [FastAPIProvider, FlaskProvider])
def test_releasing_nothing_still_leaves_the_context_clean(provider_class: type) -> None:
    """``release(None)`` is what an unauthenticated request's teardown calls.

    It has to be safe — an unauthenticated request has no scope to hand back — and it has to
    leave the context *empty* rather than merely untouched, because "nothing was established"
    and "whatever the last request left behind" must mean the same thing to the next caller.
    So a principal is established here by hand first: a release that only reset a scope it was
    given would sail past this and leave that principal ambient.
    """
    provider = provider_class()
    sentrykit.establish(sentrykit.Principal(id="left-over"))

    provider.release(None)

    assert sentrykit.current_principal() is None
    assert sentrykit.last_envelope() is None
