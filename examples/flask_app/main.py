"""A Flask orders-and-refunds desk, governed end to end by sentrykit.

Run it with ``pixi run -e web run-flask``. That starts the app through :func:`serve`, which
first drives every flow in the table below through Flask's own test client and prints one
line per flow, so the whole decision surface is visible before the first ``curl``. The
``curl`` recipes for each flow are in this directory's README.

The routes are the same URLs as ``examples/fastapi_app``, on purpose. The service layer is
identical, the policy directory is identical, the grants are identical — so a reader can diff
the two directories and find that only the boundary wiring differs:

* ``GET /orders`` — forwards only the query parameters the caller actually supplied.
* ``GET /orders/summary`` — an **unprotected** route calling a **protected** function. The
  gate is on the callable, not the URL.
* ``GET /orders/status`` — the callable protected by a bare ``@protect``, whose action id is
  its own import path.
* ``GET /orders/<order_id>`` — a multi-hop relationship, resolved by Cedar's entity graph.
* ``POST /orders/export`` — the body read by hand, refused three different ways: by role, by
  a ``forbid`` that reads the proposed argument, and by having nothing left to run with.
* ``POST /refunds`` — two policies that decide on the relationship *between* arguments.
* ``POST /refunds/<refund_id>/approve`` — the admin action.

The wiring order in :func:`create_app` is not arbitrary. ``install()`` runs before the app is
built so that :func:`~sentrykit.integrations.flask.protect_blueprint` has a governor to find,
and the provider is constructed *first* and passed to both, so the app and the engine share
one object rather than two that happen to agree.

Authentication is a stub: the ``x-user`` header names the principal. That is the seam a real
app replaces with its session, its bearer token, or its gateway's assertion.

The app is built by a **factory** and never at import: :func:`create_app` calls
``configure()`` and ``install()``, which mutate process-global state. A module-level
``app = create_app()`` would run that wiring for anyone who so much as imported the module —
including a test collector, and including a second example app in the same process.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Final

from flask import Blueprint, Flask, Request, request

from examples.flask_app.policy import POLICY_DIR, build_grants
from examples.flask_app.service import (
    approve_refund,
    desk_status,
    export_orders,
    issue_refund,
    read_order,
    search_orders,
    summarize_orders,
)
from sentrykit import configure, install
from sentrykit.integrations.flask import FlaskProvider, protect_blueprint
from sentrykit.stores.filesystem import FilesystemPolicySource


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

    Silent and side-effect-free beyond the wiring, because every test builds its own app with
    it. :func:`serve` is the one that prints.

    Returns:
        A Flask app whose ``orders`` blueprint is governed by sentrykit.
    """
    # ``verbose`` so the example is legible: the ``_authz`` envelope then carries the
    # processed arguments, the defaults that were injected and the rejections that were
    # dropped. A service would ship at the ``summary`` default.
    configure(verbosity="verbose")

    store = build_grants()
    provider = FlaskProvider(identify=_identify, grants=store)
    # Policy logic comes from reviewed ``.cedar`` files, not from a string in this process.
    # That is what puts the argument ceiling under review with the permit it hangs on, and it
    # is the same code path a deployment uses to load a bundle synced out of object storage.
    install(
        policy_source=FilesystemPolicySource(POLICY_DIR),
        grant_store=store,
        context_provider=provider,
    )

    app = Flask(__name__)
    # A blueprint rather than the whole app, to show the scoped form: only these routes get
    # the establish/release hooks, so an ungoverned surface can live beside them under one
    # app.
    orders = Blueprint("orders", __name__, url_prefix="")

    @orders.get("/orders")
    def list_orders() -> dict[str, object]:
        """Search orders, passing on only the parameters the caller actually supplied.

        The omission is the demonstration: an absent parameter is left out of the call
        entirely so policy can inject the caller's own default, rather than being passed as
        ``None`` and rejected. A route that substituted a value of its own first would leave
        nothing to inject.

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
        status = request.args.get("status")
        if status is not None:
            proposed["status"] = status
        return search_orders(**proposed)

    @orders.get("/orders/summary")
    def summary() -> dict[str, object]:
        """Summarize orders by calling a protected callable that is not itself a route.

        This handler is unprotected. The call inside it is not, and it is authorized against
        the same ambient principal — which is what "action layer, not routing layer" means.

        Returns:
            The summary, with the ``_authz`` envelope.
        """
        return summarize_orders()

    @orders.get("/orders/status")
    def status_route() -> dict[str, object]:
        """Report the desk status through the bare-``@protect`` callable.

        Its action id is the callable's import path, which is what
        ``policies/10-orders.cedar`` names.

        Returns:
            The desk status, with the ``_authz`` envelope.
        """
        return desk_status()

    @orders.get("/orders/<order_id>")
    def get_order(order_id: str) -> dict[str, object]:
        """Read one order, and let Cedar walk the relationship.

        This handler asks no questions about teams, divisions or projects. The chain from the
        caller to the order's project is resolved by the entity graph, which is why Alice
        succeeds and Bob is refused with no branch here.

        Returns:
            The order, with the ``_authz`` envelope.
        """
        return read_order(order_id)

    @orders.post("/orders/export")
    def export() -> dict[str, object]:
        """Export orders in the format the caller proposed.

        The body is read by hand rather than through a schema, so the proposed ``fmt``
        reaches policy exactly as the caller wrote it. Refusing ``fmt="pdf"`` is the policy's
        job, and doing it here as well would be the scattered ``if`` statement sentrykit
        exists to remove.

        Returns:
            The export result, with the ``_authz`` envelope.
        """
        body = request.get_json()
        proposed = {name: body[name] for name in ("fmt", "scope") if name in body}
        return export_orders(**proposed)

    @orders.post("/refunds")
    def refund() -> dict[str, object]:
        """Issue a refund, and let two policies judge the arguments together.

        Nothing in this handler compares ``amount`` to ``region``. Cedar receives the whole
        proposal and answers about all of it at once, so the cross-region rule and the desk
        limit are policy text rather than code here.

        Returns:
            The refund, with the ``_authz`` envelope.
        """
        body = request.get_json()
        names = ("order_id", "amount", "region")
        proposed = {name: body[name] for name in names if name in body}
        return issue_refund(**proposed)

    @orders.post("/refunds/<refund_id>/approve")
    def approve(refund_id: str) -> dict[str, object]:
        """Approve a refund — the admin action.

        The same request from two principals gets two answers, and neither this route nor
        the callable behind it knows who holds ``admin``.

        Returns:
            The approval, with the ``_authz`` envelope.
        """
        return approve_refund(refund_id)

    protect_blueprint(orders, provider=provider)
    app.register_blueprint(orders)
    return app


# --- the demonstration -------------------------------------------------------------------

_Flow = tuple[str, str, str, dict[str, object] | None]

FLOWS: Final[tuple[_Flow, ...]] = (
    # The bare @protect: the action id is the callable's import path.
    ("alice", "GET", "/orders/status", None),
    # A protected callable behind an unprotected route.
    ("alice", "GET", "/orders/summary", None),
    # Nothing proposed: both governed arguments come from Alice's defaults.
    ("alice", "GET", "/orders", None),
    # allow-set reject-and-refill: `cn` is refused, `eu` fills the gap, `limit=5` stands.
    ("alice", "GET", "/orders?region=cn&limit=5", None),
    # Several arguments decided at once: `limit` refilled, `region` defaulted, `status` free.
    ("alice", "GET", "/orders?limit=500&status=open", None),
    # The reviewed ceiling is Dana's only bound, and her own default is what she runs with.
    ("dana", "GET", "/orders?limit=500&status=open", None),
    # Multi-hop relationship: the permit names a project, not a person.
    ("alice", "GET", "/orders/o-1", None),
    # The same chain length, the other project.
    ("bob", "GET", "/orders/o-1", None),
    # Plainly allowed.
    ("bob", "POST", "/orders/export", {"fmt": "csv"}),
    # `fmt` omitted, so Bob's default is injected.
    ("bob", "POST", "/orders/export", {"scope": "open"}),
    # deny-set reject-and-refill, kept alive by a co-argument that survived.
    ("bob", "POST", "/orders/export", {"fmt": "xml", "scope": "open"}),
    # Nothing the caller sent survived: refilling refines a proposal, it does not rescue one.
    ("bob", "POST", "/orders/export", {"fmt": "xml"}),
    # A forbid reading the raw proposal, before the argument layer runs.
    ("bob", "POST", "/orders/export", {"fmt": "pdf"}),
    # The role gate.
    ("bob", "GET", "/orders", None),
    # Two arguments, each fine, and fine together.
    ("alice", "POST", "/refunds", {"order_id": "ord-0007", "amount": 100, "region": "uk"}),
    # Refused purely by the relationship between the two.
    ("alice", "POST", "/refunds", {"order_id": "ord-0007", "amount": 750, "region": "uk"}),
    # The gate said yes at 900; her own grant then rejected it and refilled with 50.
    ("alice", "POST", "/refunds", {"order_id": "ord-0007", "amount": 900, "region": "eu"}),
    # The desk limit. A `when` clause that comes out false is a default deny: nothing named.
    ("alice", "POST", "/refunds", {"order_id": "ord-0007", "amount": 5000, "region": "eu"}),
    # The same call, the admin branch of the same condition.
    ("dana", "POST", "/refunds", {"order_id": "ord-0007", "amount": 5000, "region": "eu"}),
    # A pattern rejection with no default to refill from.
    ("alice", "POST", "/refunds", {"order_id": "refund-me", "amount": 100, "region": "eu"}),
    # The admin action.
    ("dana", "POST", "/refunds/rf-1/approve", None),
    # The same call, the other principal.
    ("alice", "POST", "/refunds/rf-1/approve", None),
)
"""Every decision this example demonstrates, as one request each.

Ordered so a reader can follow it top to bottom: the decorator surfaces first, then the
argument layer, then the relationship cases, then the multi-argument rules.
"""


def _render_request(method: str, target: str, body: Mapping[str, object] | None) -> str:
    """Render one request the way a reader would type it.

    Args:
        method: The HTTP method.
        target: The path and query string.
        body: The JSON body, if any.

    Returns:
        A single-line rendering, with the body inlined so two refund flows are told apart.
    """
    rendered = f"{method:<4} {target}"
    if body is None:
        return rendered
    return f"{rendered} {json.dumps(body, separators=(',', ':'))}"


def _describe(payload: Mapping[str, object]) -> str:
    """Say what the policy did, in the vocabulary the library uses.

    Args:
        payload: The decoded response body.

    Returns:
        ``allowed``, ``denied: <reason>``, a ``narrowed``/``defaulted`` account of the
        argument layer, or the name of the error that refused the call.
    """
    envelope = payload.get("_authz")
    envelope = envelope if isinstance(envelope, dict) else {}
    error = payload.get("error")
    if isinstance(error, str):
        if error == "AuthzDenied":
            return f"denied: {envelope.get('reason') or payload.get('detail')}"
        # A refusal from the argument layer still renders an ``_authz`` block, but it is
        # built from the exception rather than from a decision: it names the argument and
        # the rule, and carries no action or resource, because the gate already said yes.
        return f"{error}: {payload.get('detail')}"

    rejected = envelope.get("rejected") or ()
    defaults = envelope.get("defaults_applied") or {}
    notes: list[str] = []
    for item in rejected:
        name = item["name"]
        origin = item.get("policy") or "no policy id"
        refill = (
            f", refilled with {defaults[name]!r}"
            if name in defaults
            else ", and nothing refilled it"
        )
        notes.append(f"{name}={item['value']!r} rejected ({item['rule']}, {origin}){refill}")
    injected = {
        name: value
        for name, value in defaults.items()
        if name not in {item["name"] for item in rejected}
    }
    parts: list[str] = []
    if notes:
        parts.append("narrowed: " + "; ".join(notes))
    if injected:
        rendered = " ".join(f"{name}={value!r}" for name, value in injected.items())
        parts.append(f"defaulted: {rendered}")
    return " | ".join(parts) if parts else "allowed"


def _print_table(rows: Sequence[tuple[str, str, str, str, str]]) -> None:
    """Print the collected flows as one aligned line each.

    Collected first and printed afterwards on purpose: sentrykit logs a warning through the
    ``sentrykit`` logger every time it drops an argument, and those land on stderr while the
    calls are running. Printing at the end keeps the table itself unbroken.

    Args:
        rows: One ``(index, principal, request, status, outcome)`` tuple per flow.
    """
    header = ("#", "who", "request", "code", "what the policy did")
    widths = [max(len(row[column]) for row in (*rows, header)) for column in range(4)]
    print()
    aligned_header = "  ".join(
        part.ljust(width) for part, width in zip(header, widths, strict=False)
    )
    print(f"{aligned_header}  {header[4]}")
    print("  ".join("-" * width for width in widths) + "  " + "-" * 20)
    for row in rows:
        aligned = "  ".join(part.ljust(width) for part, width in zip(row, widths, strict=False))
        print(f"{aligned}  {row[4]}")
    print()


def serve() -> Flask:
    """Build the app, run every flow through it, print what happened, and return it.

    The printing is the demonstration; the returned app is what Flask's CLI then serves, so
    ``pixi run -e web run-flask`` gives a reader the whole decision surface before they type
    their first ``curl``.

    Returns:
        The application.
    """
    app = create_app()
    client = app.test_client()
    rows: list[tuple[str, str, str, str, str]] = []
    for index, (who, method, target, body) in enumerate(FLOWS, start=1):
        # ``json=`` is passed only when there is a body: Flask's test client would otherwise
        # send a literal ``null`` on the GET flows.
        payload = {"json": body} if body is not None else {}
        response = client.open(target, method=method, headers={"x-user": who}, **payload)
        rows.append(
            (
                str(index),
                who,
                _render_request(method, target, body),
                str(response.status_code),
                _describe(response.get_json()),
            )
        )

    _print_table(rows)
    # Plain ASCII: this lands on a console whose encoding is not ours to choose.
    print(
        "Flow 6 is the one to read twice. Dana asked for limit=500. The ceiling declared in\n"
        "policies/10-orders.cedar is 100, and it is the only bound her grants leave in play.\n"
        "She ran with 25, her own default. The value that breached the ceiling was rejected\n"
        "and her default was put in the gap. Nothing was trimmed to 100.\n"
    )
    return app
