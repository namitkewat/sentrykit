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

The page also *prints* things: the 22-row table each example drives through its own test
client before it starts serving, and the reviewed Cedar the argument ceiling is declared in.
Those are pinned by running the example and reading the block back out of the page, rather
than by transcribing either into this file — a transcription agrees with itself forever, and
what has to hold is that the page and the program say the same thing.
"""

from __future__ import annotations

import contextlib
import io
import logging
import re
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("flask")

from examples.fastapi_app import main as fastapi_main
from examples.fastapi_app import service as fastapi_service
from examples.fastapi_app.main import create_app as create_fastapi_app
from examples.fastapi_app.policy import POLICY_TEXT, build_grants
from examples.fastapi_app.service import summarize_orders
from examples.flask_app import main as flask_main
from examples.flask_app import service as flask_service
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from flask import Blueprint, Flask
from starlette.requests import Request

import sentrykit
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

PAGE = Path(__file__).resolve().parents[2] / "docs" / "web-frameworks.md"
"""The page these tests pin, read rather than transcribed."""


def fenced_block(page: Path, opens_with: str) -> str:
    """Return the one fenced block on ``page`` whose first line starts with ``opens_with``.

    Args:
        page: The markdown file to read.
        opens_with: How the block's first line begins.

    Returns:
        The block's contents, without the fences.

    Raises:
        AssertionError: If the page carries no such block, or more than one.
    """
    blocks = [
        block
        for block in re.findall(
            r"^```[a-z]*\n(.*?)^```", page.read_text(encoding="utf-8"), re.S | re.M
        )
        if block.lstrip().startswith(opens_with)
    ]
    assert len(blocks) == 1, f"{page.name} has {len(blocks)} blocks opening with {opens_with!r}"
    return blocks[0]


def printed_by(serve: Callable[[], object]) -> list[str]:
    """Run one example's self-drive and return the non-blank lines it printed.

    Args:
        serve: The example's ``serve`` entry point, which drives every flow and prints.

    Returns:
        The captured lines, blanks dropped so the page's own spacing is not the assertion.
    """
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        serve()
    return [line for line in captured.getvalue().splitlines() if line.strip()]


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
    seeded_desk: None,
) -> None:
    """`docs/web-frameworks.md` — Protected callables that are not routes; and the README.

    The permitted body is asserted whole because the page prints it whole, and the envelope is
    the half worth reading: `/orders/summary` mentions no authorization at all, and the
    decision named on the way back out is `orders.summarize` — the callable's action, decided
    against the principal the provider established a frame further out.
    """
    allowed = client.get("/orders/summary", headers={"x-user": "alice"})
    refused = client.get("/orders/summary", headers={"x-user": "bob"})

    assert allowed.status_code == 200
    assert allowed.json() == {
        "open_orders": 198,
        "regions": {"eu": 81, "uk": 54, "us": 63},
        "oldest_open": "ord-0319",
        "_authz": {
            "decision": "allow",
            "action": 'Action::"orders.summarize"',
            "resource": ORDERS,
            "principal": 'User::"alice"',
        },
    }
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

        open_orders: int

    app = FastAPI()
    protect_app(app, provider=provider)

    @app.get("/summary", response_model=Summary)
    def summary() -> dict[str, object]:
        """Return the protected callable's result, envelope and all."""
        return summarize_orders()

    with TestClient(app) as client:
        body = client.get("/summary", headers={"x-user": "alice"}).json()

    assert body == {"open_orders": 198}
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


# --- the 22-flow table each example prints before it serves ------------------------------------


@pytest.mark.integration
def test_the_flow_table_the_page_prints_is_the_table_the_fastapi_example_prints() -> None:
    """`docs/web-frameworks.md` — Runnable examples: every row of the printed table.

    Read off the page rather than transcribed, so this asserts the thing that actually matters:
    a reader who runs `pixi run -e web run-fastapi` sees what the page told them they would.
    Twenty-two rows covering the whole decision surface — statuses, the narrowing accounts, the
    two refusal shapes from the argument layer and the three from the gate — which is why one
    equality here stands in for a page-sized list of literals.
    """
    page = [line for line in fenced_block(PAGE, "#   who").splitlines() if line.strip()]

    printed = printed_by(fastapi_main.serve)

    assert len(page) == 24, "header, rule and 22 flows"
    assert printed[: len(page)] == page


@pytest.mark.integration
def test_the_flask_example_prints_the_same_table_but_for_one_cells_key_order() -> None:
    """The page prints one table and says both examples drive it. They do, bar one cell.

    Flow 3 is the exception, and it is a rendering difference rather than a decision one: each
    route builds its proposal dict in its own order and Flask's JSON provider sorts the keys it
    returns, so the two defaults come out `region` then `limit` on FastAPI and the other way
    round on Flask. The values are the assertion; the order is not, because nothing about the
    authorization outcome depends on it. Every other row is compared to the page verbatim, and
    flow 3 is allowed to match it too — the tolerance is for a difference the page can live
    with, not a requirement that there be one.
    """
    page = [line for line in fenced_block(PAGE, "#   who").splitlines() if line.strip()]

    printed = printed_by(flask_main.serve)[: len(page)]

    differing = {index for index, (a, b) in enumerate(zip(page, printed, strict=True)) if a != b}
    assert differing <= {4}, "only flow 3's defaulted clause may differ between the frameworks"
    assert "defaulted:" in printed[4]
    assert "limit=10" in printed[4]
    assert "region='eu'" in printed[4]


@pytest.mark.integration
@pytest.mark.parametrize(
    "serve",
    [fastapi_main.serve, flask_main.serve],
    ids=["fastapi", "flask"],
)
def test_each_web_run_logs_one_dropped_argument_warning_per_narrowed_value(
    serve: Callable[[], object], caplog: pytest.LogCaptureFixture
) -> None:
    """The page: "sentrykit logs `Argument dropped by policy` once per rejected value, so seven
    of those land on stderr ahead of the table".

    Seven is the count of *values* rejected across the 22 flows, not of flows that narrowed —
    the two happen to coincide here, and the page's claim is about the log line, so the log
    line is what is counted. A reader who runs either example and counts eight has found a
    rejection the table does not account for.
    """
    with caplog.at_level(logging.WARNING, logger="sentrykit"):
        printed_by(serve)

    dropped = [
        record for record in caplog.records if record.getMessage() == "Argument dropped by policy"
    ]
    assert len(dropped) == 7
    assert [record.name for record in dropped] == ["sentrykit.engine"] * 7


# --- the two `curl` recipes under "The bare `@protect`" ----------------------------------------


@pytest.mark.integration
def test_the_bare_protect_route_returns_exactly_the_body_the_page_prints(
    client: TestClient,
    seeded_desk: None,
) -> None:
    """`docs/web-frameworks.md` — The bare `@protect`, and a protected callable that is not a
    route: `curl localhost:8000/orders/status -H 'x-user: alice'`.

    The two derived ids are written out here rather than computed from the callable, which is
    the opposite of what the shared behaviour table does, and deliberately: that row asserts
    the id *is* the import path, and this one asserts the page prints the right path. A test
    that derived it would keep agreeing with itself after the module moved, which is precisely
    the fragility the page warns about two paragraphs later.
    """
    derived = "examples.fastapi_app.service.desk_status"

    body = client.get("/orders/status", headers={"x-user": "alice"}).json()

    assert body == {
        "desk": "orders",
        "open": True,
        "open_orders": 198,
        "pending_refunds": 4,
        "_authz": {
            "decision": "allow",
            "action": f'Action::"{derived}"',
            "resource": f'Resource::"{derived}"',
            "principal": 'User::"alice"',
        },
    }


# --- the reviewed Cedar both pages quote -------------------------------------------------------


@pytest.mark.integration
def test_the_argument_ceiling_the_pages_quote_is_the_reviewed_policy_text() -> None:
    """`docs/web-frameworks.md` — "The ceiling is reviewed text"; `docs/agents.md` quotes it too.

    A quoted policy that had drifted from the one the examples evaluate is the worst kind of
    documentation bug, because it reads as evidence. So the quote is checked against all four
    reviewed files rather than described — and against both pages, since a page that stopped
    quoting it would leave this passing against nothing.

    The files interleave explanatory comments between the `@id` and the `@constraints`
    annotation, which a quote of the *policy* has no business reproducing; comment lines are
    dropped before the comparison and nothing else is.
    """
    quoted = (
        '@id("support-may-search")\n'
        '@constraints("{\\"limit\\": {\\"maximum\\": 100}}")\n'
        "permit (\n"
        '  principal in Role::"support",\n'
        '  action == Action::"orders.search",\n'
        '  resource == Tool::"orders"\n'
        ");"
    )
    root = PAGE.parents[1]
    reviewed = sorted(root.glob("examples/*/policies/10-orders.cedar"))

    assert quoted in PAGE.read_text(encoding="utf-8")
    assert quoted in (root / "docs" / "agents.md").read_text(encoding="utf-8")
    assert len(reviewed) == 4, "one reviewed orders policy per example app"
    for policy in reviewed:
        without_comments = "\n".join(
            line
            for line in policy.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("//")
        )
        assert quoted in re.sub(r"\n{2,}", "\n\n", without_comments), policy.name


# --- the counts the page and the README both state ---------------------------------------------


@pytest.mark.integration
def test_the_two_apps_hold_the_flows_and_the_callables_the_page_counts() -> None:
    """The page — "Seven routes, seven protected callables"; the README — "22 requests".

    Both numbers are prose, which is exactly the kind of claim that rots quietly: adding a
    flow or a protected callable is a one-line change nobody would think to re-read the page
    for. Counted on both apps, because the page's whole point about them is that they are the
    same desk built twice.
    """
    protected = {
        framework: sorted(
            name
            for name, value in vars(module).items()
            if callable(value) and sentrykit.is_protected(value)
        )
        for framework, module in (("fastapi", fastapi_service), ("flask", flask_service))
    }

    assert len(fastapi_main.FLOWS) == 22
    assert len(flask_main.FLOWS) == 22
    assert protected["fastapi"] == protected["flask"]
    assert protected["fastapi"] == [
        "approve_refund",
        "desk_status",
        "export_orders",
        "issue_refund",
        "read_order",
        "search_orders",
        "summarize_orders",
    ]
