"""Narrowing reaches the caller when the result cannot carry it — ADR-029.

The three narrowing fields (``narrowed``, ``narrowed_arguments``, ``guidance``) ride inside the
``_authz`` key, and that key can only be written into a ``MutableMapping``. A route returning a
JSON array, a tool returning a list, a handler returning a string — none of them can carry it,
and a web route returning an array is the commonest shape there is. So the benefit of having
those fields at all was conditional on the application's return type until the boundary gained
a channel of its own.

Every test here uses a **list-returning** protected callable on purpose. The mapping case is
covered by the shared web contract and by the documented-example checks; what is asserted here
is the half that was previously invisible.

The sync-route case is the one that matters most and is least obvious: a sync route runs in an
AnyIO worker thread holding a *context copy*, so a ``ContextVar`` write inside it is discarded
when the copy is dropped, and ``last_envelope()`` reads ``None`` in the middleware that has to
write the headers. Only a mutation to an object reached *through* the variable survives.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

# This module is the one place that exercises all four providers in a single file, so it needs
# both extras present and is skipped wherever either is missing -- the `web` environment has no
# `mcp`, the `agent` environment has no `fastapi`, and `default` has neither. Without these
# guards the module raises at *collection*, which pytest reports as an error rather than a
# skip, and an error during collection interrupts the whole run: three of the four environment
# gates were red from the moment this file landed, and each of them was red for a module that
# simply cannot run there.
pytest.importorskip("mcp")
pytest.importorskip("pydantic_ai")
pytest.importorskip("fastapi")
pytest.importorskip("flask")

import mcp
from fastapi import FastAPI
from fastapi.testclient import TestClient
from flask import Flask, jsonify
from mcp.server.mcpserver import MCPServer
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel

import sentrykit
from sentrykit import ArgumentConstraint, Entity, EntityRef, protect
from sentrykit.integrations.base import NARROWED_ARGUMENTS_HEADER, NARROWED_HEADER
from sentrykit.integrations.fastapi import FastAPIProvider
from sentrykit.integrations.fastapi import protect_app as protect_fastapi
from sentrykit.integrations.fastmcp import (
    NARROWED_ARGUMENTS_META_KEY,
    NARROWED_META_KEY,
    FastMCPProvider,
    protect_server,
)
from sentrykit.integrations.fastmcp import governed_tool as mcp_governed_tool
from sentrykit.integrations.flask import FlaskProvider
from sentrykit.integrations.flask import protect_app as protect_flask
from sentrykit.integrations.pydantic_ai import PydanticAIProvider
from sentrykit.integrations.pydantic_ai import governed_tool as agent_governed_tool
from sentrykit.stores.base import GrantSpec
from sentrykit.stores.memory import InMemoryGrantStore

pytestmark = pytest.mark.integration

ACTION = 'Action::"orders.search"'
RESOURCE = 'Tool::"orders"'
PRINCIPAL_HEADER = "x-sentrykit-principal"

POLICY = (
    '@id("support-may-search")\n'
    "permit (\n"
    '  principal in Role::"support",\n'
    '  action == Action::"orders.search",\n'
    '  resource == Tool::"orders"\n'
    ");"
)

ENTITIES = (Entity(EntityRef("Role", "support")), Entity(EntityRef("Tool", "orders")))


def _store() -> InMemoryGrantStore:
    """alice may search, in ``eu`` only, and her own default refills anything else."""
    store = InMemoryGrantStore()
    store.grant(GrantSpec(principal=EntityRef("User", "alice"), kind="role", subject="support"))
    store.grant(
        GrantSpec(
            principal=EntityRef("User", "alice"),
            kind="constraint",
            subject="region",
            constraint=ArgumentConstraint(allow=("eu",), default="eu", policy="alice-region"),
            action=ACTION,
        )
    )
    return store


@protect(action=ACTION, resource=RESOURCE)
def search_rows(customer_id: str = "", region: str = "unset") -> list[dict[str, object]]:
    """Returns a LIST, so nothing can be attached to it under ``_authz``."""
    return [{"customer_id": customer_id, "region": region}]


# --- web ------------------------------------------------------------------------------


def _fastapi_client() -> TestClient:
    store = _store()
    provider = FastAPIProvider(grants=store)
    sentrykit.install(POLICY, entities=list(ENTITIES), grant_store=store, context_provider=provider)
    app = FastAPI()

    @app.get("/async")
    async def by_coroutine() -> list[dict[str, object]]:
        return search_rows(customer_id="c-1", region="us")

    @app.get("/sync")
    def by_worker_thread() -> list[dict[str, object]]:
        return search_rows(customer_id="c-1", region="us")

    @app.get("/clean")
    def nothing_narrowed() -> list[dict[str, object]]:
        return search_rows(customer_id="c-1", region="eu")

    protect_fastapi(app, provider=provider)
    return TestClient(app)


@pytest.mark.parametrize("path", ["/async", "/sync"])
def test_a_list_returning_fastapi_route_reports_narrowing_in_its_headers(path: str) -> None:
    """Both route flavours, because only one of them ever worked.

    ``/sync`` is the load-bearing case: its decision is made inside a worker thread's context
    copy, where ``last_envelope()`` is invisible to the middleware.
    """
    response = _fastapi_client().get(path, headers={PRINCIPAL_HEADER: "alice"})

    assert response.status_code == 200
    # The narrowing happened -- `us` never reached the body.
    assert response.json() == [{"customer_id": "c-1", "region": "eu"}]
    # ...and the body could not say so, so the headers did.
    assert "_authz" not in str(response.json())
    assert response.headers[NARROWED_HEADER] == "true"
    assert response.headers[NARROWED_ARGUMENTS_HEADER] == "region"


def test_a_list_returning_fastapi_route_that_narrowed_nothing_sends_no_headers() -> None:
    response = _fastapi_client().get("/clean", headers={PRINCIPAL_HEADER: "alice"})

    assert response.status_code == 200
    assert NARROWED_HEADER not in response.headers
    assert NARROWED_ARGUMENTS_HEADER not in response.headers


def _flask_client() -> Any:
    store = _store()
    provider = FlaskProvider(grants=store)
    sentrykit.install(POLICY, entities=list(ENTITIES), grant_store=store, context_provider=provider)
    app = Flask(__name__)

    @app.get("/rows")
    def rows() -> Any:
        return jsonify(search_rows(customer_id="c-1", region="us"))

    @app.get("/clean")
    def clean() -> Any:
        return jsonify(search_rows(customer_id="c-1", region="eu"))

    protect_flask(app, provider=provider)
    return app.test_client()


def test_a_list_returning_flask_route_reports_narrowing_in_its_headers() -> None:
    response = _flask_client().get("/rows", headers={PRINCIPAL_HEADER: "alice"})

    assert response.status_code == 200
    assert response.get_json() == [{"customer_id": "c-1", "region": "eu"}]
    assert response.headers[NARROWED_HEADER] == "true"
    assert response.headers[NARROWED_ARGUMENTS_HEADER] == "region"


def test_a_list_returning_flask_route_that_narrowed_nothing_sends_no_headers() -> None:
    response = _flask_client().get("/clean", headers={PRINCIPAL_HEADER: "alice"})

    assert response.status_code == 200
    assert NARROWED_HEADER not in response.headers


# --- agents ---------------------------------------------------------------------------


def _mcp_server() -> MCPServer:
    store = _store()
    provider = FastMCPProvider(grants=store)
    sentrykit.install(POLICY, entities=list(ENTITIES), grant_store=store, context_provider=provider)
    server = MCPServer("orders")

    def as_rows(customer_id: str = "", region: str = "unset") -> list[dict[str, object]]:
        """Search orders, returning a list."""
        return [{"customer_id": customer_id, "region": region}]

    def as_mapping(customer_id: str = "", region: str = "unset") -> dict[str, object]:
        """Search orders, returning a mapping."""
        return {"customer_id": customer_id, "region": region}

    mcp_governed_tool(server, action=ACTION, resource=RESOURCE)(as_rows)
    mcp_governed_tool(server, action=ACTION, resource=RESOURCE)(as_mapping)
    protect_server(server, provider=provider)
    return server


def _call(tool: str) -> Any:
    async def run() -> Any:
        async with mcp.Client(_mcp_server()) as client:
            return await client.call_tool(
                tool,
                {"customer_id": "c-1", "region": "us"},
                meta={PRINCIPAL_HEADER: "alice"},
            )

    return asyncio.run(run())


def test_a_list_returning_mcp_tool_reports_narrowing_in_meta_and_in_content() -> None:
    """``_meta`` for the machine, an appended text block for the model.

    Appended, never substituted: the tool's own content block is still first and intact, so
    the data reaches the model exactly as the tool produced it.
    """
    result = _call("as_rows")

    meta = dict(result.meta or {})
    assert meta[NARROWED_META_KEY] is True
    assert meta[NARROWED_ARGUMENTS_META_KEY] == ["region"]

    blocks = [getattr(block, "text", "") for block in (result.content or [])]
    assert len(blocks) == 2
    assert "eu" in blocks[0]
    assert blocks[1].startswith("This result is valid and was served.")


def test_a_mapping_returning_mcp_tool_is_not_annotated_twice() -> None:
    """It already carries the whole envelope in band, where the model reads it."""
    result = _call("as_mapping")

    meta = dict(result.meta or {})
    assert NARROWED_META_KEY not in meta
    blocks = [getattr(block, "text", "") for block in (result.content or [])]
    assert len(blocks) == 1
    assert "_authz" in blocks[0]


def test_a_list_returning_pydantic_ai_tool_reports_narrowing_beside_its_result() -> None:
    """``ToolReturn`` is additive: the list still reaches the model as the tool return.

    The guidance arrives as a separate prompt part rather than replacing the data, which is
    the failure this whole channel exists to avoid, inverted.
    """
    store = _store()
    provider = PydanticAIProvider(grants=store)
    sentrykit.install(POLICY, entities=list(ENTITIES), grant_store=store, context_provider=provider)
    agent: Agent[dict[str, object], str] = Agent(TestModel(), deps_type=dict)

    @agent_governed_tool(agent, action=ACTION, resource=RESOURCE, provider=provider)
    def as_rows(customer_id: str = "", region: str = "unset") -> list[dict[str, object]]:
        """Search orders, returning a list."""
        return [{"customer_id": customer_id, "region": region}]

    result = asyncio.run(agent.run("search", deps={"principal": "alice"}))

    returns = [
        part
        for message in result.all_messages()
        for part in getattr(message, "parts", [])
        if type(part).__name__ == "ToolReturnPart"
    ]
    assert returns, "the tool was never called"
    assert returns[-1].metadata == {"narrowed": True, "narrowed_arguments": ["region"]}
    # The data, not a note about it.
    assert "region" in str(returns[-1].content)

    prompts = [
        str(getattr(part, "content", ""))
        for message in result.all_messages()
        for part in getattr(message, "parts", [])
        if type(part).__name__ == "UserPromptPart"
    ]
    assert any(text.startswith("This result is valid and was served.") for text in prompts)


# --- isolation ------------------------------------------------------------------------


def test_two_concurrent_requests_report_their_own_narrowing_and_not_each_others() -> None:
    """A recorder is per-request, and getting that wrong would report across callers.

    The failure this guards against is small but real: a shared recorder would tell a caller
    whose call was clean that something of theirs had been narrowed, and name another
    principal's argument while doing it. Each ASGI request is its own task with its own
    context, so each `establish` installs its own recorder -- asserted here rather than
    assumed, because the recorder is reached through a module-level `ContextVar` and that is
    exactly the shape that looks shared.
    """
    client = _fastapi_client()
    narrowed: list[Any] = []
    clean: list[Any] = []

    def hit(path: str, into: list[Any]) -> None:
        into.append(client.get(path, headers={PRINCIPAL_HEADER: "alice"}))

    import threading

    threads = [
        *(threading.Thread(target=hit, args=("/async", narrowed)) for _ in range(4)),
        *(threading.Thread(target=hit, args=("/clean", clean)) for _ in range(4)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(narrowed) == 4
    assert len(clean) == 4
    for response in narrowed:
        assert response.headers[NARROWED_HEADER] == "true"
        assert response.headers[NARROWED_ARGUMENTS_HEADER] == "region"
    for response in clean:
        assert NARROWED_HEADER not in response.headers


def test_a_second_request_on_one_client_does_not_inherit_the_first_narrowing() -> None:
    """The sequential form of the same question, which is what a pooled worker does."""
    client = _fastapi_client()

    first = client.get("/sync", headers={PRINCIPAL_HEADER: "alice"})
    second = client.get("/clean", headers={PRINCIPAL_HEADER: "alice"})

    assert first.headers[NARROWED_HEADER] == "true"
    assert NARROWED_HEADER not in second.headers
