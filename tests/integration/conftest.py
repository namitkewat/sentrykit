"""The framework-independent half of the web integration suite.

One decorator and N providers means a FastAPI 403 and a Flask 403 are the *same* 403. A claim
like that is only tested if both frameworks are asked exactly the same questions, so the
questions live here — as plain functions over a :class:`WebCaller` — and each framework module
answers them with its own client. Keeping a second copy of every row would let the two drift,
and a drifted copy is how "identical on both frameworks" quietly stops being true.

The table covers the whole decision surface the example apps demonstrate: default injection,
reject-and-refill from a grant and from a reviewed ceiling, the three refusal shapes, rules
that read two proposed arguments at once, the relationship walk, and the two ids a bare
``@protect`` derives. A row belongs here whenever the behaviour is the *library's* rather than
the framework's, which is nearly all of it.

Nothing in this module imports a web framework. It is loaded in the ``default`` pixi
environment too, where FastAPI and Flask are absent and every test module that needs them has
already skipped itself at import time. The adapters below only ever call ``request``/``open``
on a client somebody else built, so they need no import to do it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from importlib import import_module
from typing import Any

import pytest

import sentrykit

PRINCIPAL_HEADER = "x-user"
"""The header both example apps read a principal id from. Their auth stub, and the seam a
real application replaces with its session or its gateway's assertion."""

_SERVICE_MODULE = {
    "fastapi": "examples.fastapi_app.service",
    "flask": "examples.flask_app.service",
}
"""Where each app's protected callables live, for the rows that read one rather than call it.

A bare ``@protect`` derives its action id from the callable's own import path, so the two apps
answer the *same* behaviour under two different ids. Naming the module is what lets one shared
row assert that without hard-coding either.
"""

_POLICY_MODULE = {
    "fastapi": "examples.fastapi_app.policy",
    "flask": "examples.flask_app.policy",
}
"""Where each app's grant data is built, for the rows that check a grant as well as its effect.

Imported lazily inside the checks: neither module imports a web framework, but this file is
loaded in the ``default`` environment too and a lazy import keeps that obviously true.
"""

Send = Callable[[str, str, str | None, Mapping[str, Any] | None], "Reply"]
"""``(method, path, user, json) -> Reply`` — the one thing a framework adapter supplies."""


@dataclass(frozen=True)
class Reply:
    """One HTTP response, reduced to what the contract talks about.

    Attributes:
        status: The HTTP status code.
        body: The decoded JSON body.
    """

    status: int
    body: Mapping[str, Any]

    @property
    def authz(self) -> Mapping[str, Any]:
        """The ``_authz`` envelope.

        Returns:
            The envelope.

        Raises:
            AssertionError: If the body carries none, which is a contract failure worth
                reporting as itself rather than as a ``KeyError`` further down the test.
        """
        assert "_authz" in self.body, f"no _authz envelope in {self.body!r}"
        envelope: Mapping[str, Any] = self.body["_authz"]
        return envelope

    @property
    def error(self) -> str | None:
        """The refusal's exception class name, or ``None`` on a success."""
        name: str | None = self.body.get("error")
        return name


class WebCaller:
    """One example app, addressed identically whichever framework is serving it.

    Args:
        framework: Which framework is behind it, for assertion messages.
        send: The adapter that actually performs a call.
    """

    def __init__(self, framework: str, send: Send) -> None:
        self.framework = framework
        self._send = send

    def get(self, path: str, *, user: str | None = None) -> Reply:
        """Issue a ``GET``, identifying the caller in :data:`PRINCIPAL_HEADER` when given."""
        return self._send("GET", path, user, None)

    def post(self, path: str, *, json: Mapping[str, Any], user: str | None = None) -> Reply:
        """Issue a ``POST`` with a JSON body."""
        return self._send("POST", path, user, json)


def _starlette_caller(client: Any) -> WebCaller:
    """Adapt a ``fastapi.testclient.TestClient`` to :class:`WebCaller`."""

    def send(method: str, path: str, user: str | None, payload: Mapping[str, Any] | None) -> Reply:
        headers = {PRINCIPAL_HEADER: user} if user is not None else {}
        extra: dict[str, Any] = {"json": payload} if payload is not None else {}
        response = client.request(method, path, headers=headers, **extra)
        return Reply(status=response.status_code, body=response.json())

    return WebCaller("fastapi", send)


def _flask_caller(client: Any) -> WebCaller:
    """Adapt a ``flask.testing.FlaskClient`` to :class:`WebCaller`."""

    def send(method: str, path: str, user: str | None, payload: Mapping[str, Any] | None) -> Reply:
        headers = {PRINCIPAL_HEADER: user} if user is not None else {}
        extra: dict[str, Any] = {"json": payload} if payload is not None else {}
        response = client.open(method=method, path=path, headers=headers, **extra)
        return Reply(status=response.status_code, body=response.get_json())

    return WebCaller("flask", send)


@pytest.fixture
def fastapi_client() -> Iterator[WebCaller]:
    """A caller over a freshly built FastAPI example app.

    Built per test rather than imported: ``create_app()`` calls ``configure()`` and
    ``install()``, and the root ``conftest`` tears both down between tests — so an app built
    once at import time would be answering to a governor that no longer exists.

    Entered as a context manager so the ASGI lifespan actually runs, which is also the
    cheapest proof that the middleware lets a non-HTTP scope past.

    Imports are inside the body on purpose: this module is loaded in the ``default``
    environment too, where FastAPI is not installed and this fixture is never requested.
    """
    from examples.fastapi_app.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as raw:
        yield _starlette_caller(raw)


@pytest.fixture
def flask_client() -> Iterator[WebCaller]:
    """A caller over a freshly built Flask example app.

    The client is deliberately *not* entered as a context manager: ``with app.test_client()``
    preserves the request context past the response, which would postpone the
    ``teardown_request`` that releases the ambient principal — the very hook this suite pins.
    """
    from examples.flask_app.main import create_app

    yield _flask_caller(create_app().test_client())


# --- the shared behaviour table ----------------------------------------------------------
#
# One function per row. Each is handed a caller and asserts the whole outcome of one request:
# status, result, and the ``_authz`` envelope. They run against both frameworks unchanged.


def check_defaults_are_injected_when_the_caller_supplies_no_arguments(client: WebCaller) -> None:
    """Neither parameter has a Python default, so a value can only have come from policy."""
    reply = client.get("/orders", user="alice")

    assert reply.status == 200
    assert reply.body["region"] == "eu"
    assert reply.body["limit"] == 10
    assert reply.authz["decision"] == "allow"
    assert set(reply.authz["defaults_applied"]) == {"region", "limit"}


def check_arguments_the_policy_permits_are_passed_through_untouched(client: WebCaller) -> None:
    """A default must never override a supplied value the principal is entitled to pass."""
    reply = client.get("/orders?region=uk&limit=5", user="alice")

    assert reply.status == 200
    assert reply.body["region"] == "uk"
    assert reply.body["limit"] == 5
    assert "rejected" not in reply.authz


def check_a_disallowed_argument_is_dropped_and_replaced_by_its_default(
    client: WebCaller,
) -> None:
    """The narrowing is reported rather than silent: the caller can see ``cn`` was refused."""
    reply = client.get("/orders?region=cn&limit=5", user="alice")

    assert reply.status == 200
    assert reply.body["region"] == "eu"
    assert reply.body["limit"] == 5
    rejections = reply.authz["rejected"]
    assert len(rejections) == 1
    assert rejections[0]["name"] == "region"
    assert rejections[0]["rule"] == "allow-set"
    assert rejections[0]["policy"] == "alice-region"
    assert rejections[0]["value"] == "cn"


def check_a_call_whose_every_argument_was_refused_is_itself_refused(client: WebCaller) -> None:
    """Completing this from defaults would answer a question the caller did not ask."""
    reply = client.get("/orders?region=cn", user="alice")

    assert reply.status == 400
    assert reply.error == "NoValidArguments"
    assert [item["name"] for item in reply.authz["rejected"]] == ["region"]


def check_a_principal_without_the_role_is_denied_the_route(client: WebCaller) -> None:
    """Bob is an auditor, and only support may search."""
    reply = client.get("/orders", user="bob")

    assert reply.status == 403
    assert reply.error == "AuthzDenied"
    assert reply.authz["action"] == 'Action::"orders.search"'


def check_an_unauthenticated_caller_is_denied(client: WebCaller) -> None:
    """No header means no principal, and no principal is a refusal rather than a free pass."""
    reply = client.get("/orders")

    assert reply.status == 403
    assert reply.error == "NoContext"


def check_a_principal_the_grant_store_never_heard_of_is_denied(client: WebCaller) -> None:
    """An id nobody granted anything to resolves to no principal, not to an empty one."""
    reply = client.get("/orders", user="mallory")

    assert reply.status == 403
    assert reply.error == "NoContext"


def check_the_export_route_allows_the_principal_whose_role_permits_it(client: WebCaller) -> None:
    reply = client.post("/orders/export", json={"fmt": "csv"}, user="bob")

    assert reply.status == 200
    assert reply.body["fmt"] == "csv"
    assert reply.authz["decision"] == "allow"


def check_the_export_route_denies_the_principal_whose_role_does_not(client: WebCaller) -> None:
    reply = client.post("/orders/export", json={"fmt": "csv"}, user="alice")

    assert reply.status == 403
    assert reply.error == "AuthzDenied"


def check_a_forbid_on_one_argument_value_beats_the_permit_that_allowed_the_action(
    client: WebCaller,
) -> None:
    """Bob may export, and still may not export a PDF.

    The demonstration that an exception is expressed as a ``forbid`` rather than by editing
    the permit — Cedar's forbid always wins. ``debug`` verbosity is set here and nowhere else,
    because the policy that decided a refusal is the one piece of the envelope that is
    withheld from callers below it.
    """
    sentrykit.configure(verbosity="debug")

    reply = client.post("/orders/export", json={"fmt": "pdf"}, user="bob")

    assert reply.status == 403
    assert reply.error == "AuthzDenied"
    assert reply.authz["determining_policies"] == ["no-pdf-exports"]


def check_a_protected_non_route_callable_is_governed_by_the_ambient_principal(
    client: WebCaller,
) -> None:
    """``/orders/summary`` is not protected; the function it calls three frames deeper is."""
    reply = client.get("/orders/summary", user="alice")

    assert reply.status == 200
    assert reply.body["summary"] == "3 open orders"
    assert reply.authz["action"] == 'Action::"orders.summarize"'
    assert reply.authz["decision"] == "allow"


def check_the_non_route_callable_refuses_a_principal_the_policy_denies(
    client: WebCaller,
) -> None:
    reply = client.get("/orders/summary", user="bob")

    assert reply.status == 403
    assert reply.error == "AuthzDenied"
    assert reply.authz["action"] == 'Action::"orders.summarize"'


def check_the_non_route_callable_refuses_an_unauthenticated_caller(client: WebCaller) -> None:
    reply = client.get("/orders/summary")

    assert reply.status == 403
    assert reply.error == "NoContext"


# --- the argument layer, in the shapes the examples demonstrate ---------------------------


def check_a_reviewed_ceiling_narrows_to_the_principals_own_default(client: WebCaller) -> None:
    """Dana proposes 500, the reviewed ceiling is 100, and she runs with 25 — her own default.

    The value asserted is 25 and the point is that it is **not** 100. A ceiling rejects a
    value the principal may not pass; it never hands back the bound that refused it. Her
    rejection names ``support-may-search``, the reviewed policy in ``policies/10-orders.cedar``
    that declared the ceiling, which is how a reader tells a ceiling refusal from a grant one.

    Alice is the contrast, on the identical request. Her grant caps ``limit`` at 50, grants
    filter before ceilings, and so the tighter bound is the one that reports: she runs with 10
    and her rejection names ``alice-limit``. Both halves live in one row because the claim is
    the *difference* between them.
    """
    ceiling = client.get("/orders?limit=500&status=open", user="dana")
    grant = client.get("/orders?limit=500&status=open", user="alice")

    assert ceiling.status == 200
    assert ceiling.body["limit"] == 25
    assert ceiling.authz["rejected"] == [
        {
            "name": "limit",
            "rule": "maximum",
            "reason": "Value is above the maximum of 100",
            "policy": "support-may-search",
            "value": 500,
        }
    ]

    assert grant.status == 200
    assert grant.body["limit"] == 10
    assert grant.authz["rejected"][0]["policy"] == "alice-limit"
    assert grant.authz["rejected"][0]["reason"] == "Value is above the maximum of 50"


def check_several_arguments_are_decided_in_one_call(client: WebCaller) -> None:
    """One argument rejected and refilled, one omitted and defaulted, one passed through.

    ``processed``, ``rejected`` and ``defaults_applied`` are all present on the one envelope,
    which is what makes it readable as an account of the whole call rather than of one
    argument. ``status`` is in ``processed`` and in neither of the others: it carries a Python
    default, nobody's policy has an opinion about it, and it arrives untouched.
    """
    reply = client.get("/orders?limit=500&status=open", user="alice")

    assert reply.status == 200
    assert reply.body == {
        "region": "eu",
        "limit": 10,
        "status": "open",
        "orders": ["order-0", "order-1", "order-2"],
        "_authz": reply.authz,
    }
    assert reply.authz["processed"] == {"status": "open", "region": "eu", "limit": 10}
    assert [item["name"] for item in reply.authz["rejected"]] == ["limit"]
    assert reply.authz["defaults_applied"] == {"region": "eu", "limit": 10}


def check_a_denied_format_is_rejected_and_refilled_beside_a_surviving_argument(
    client: WebCaller,
) -> None:
    """A deny-set refuses ``xml`` and bob's own default takes its place, so the call proceeds.

    ``scope`` is what keeps it alive: a rejected argument is refilled *alongside* whatever
    survived, and a proposal with nothing left in it is refused instead — the next row.
    """
    reply = client.post("/orders/export", json={"fmt": "xml", "scope": "open"}, user="bob")

    assert reply.status == 200
    assert reply.body["fmt"] == "csv"
    assert reply.body["scope"] == "open"
    assert reply.authz["rejected"] == [
        {
            "name": "fmt",
            "rule": "deny-set",
            "reason": "Value is explicitly denied",
            "policy": "bob-fmt",
            "value": "xml",
        }
    ]
    assert reply.authz["defaults_applied"] == {"fmt": "csv"}


def check_the_same_denied_format_alone_leaves_nothing_to_run_with(client: WebCaller) -> None:
    """``fmt="xml"`` with nothing beside it is refused, and bob's default does not rescue it.

    Reachable here because a web route forwards only what the caller actually sent, so an
    omitted ``scope`` stays omitted all the way to the decorator. The two agent boundaries
    behave differently on this exact call and deliberately so: both materialize the advertised
    schema's defaults before dispatch, so ``scope`` arrives as a proposed argument and
    survives. That is a property of the boundary, not a disagreement about the rule.

    The refusal is exception-derived, so it names no action and no resource, and carries an
    ``allowed`` block saying what bob may pass instead.
    """
    reply = client.post("/orders/export", json={"fmt": "xml"}, user="bob")

    assert reply.status == 400
    assert reply.error == "NoValidArguments"
    assert [item["name"] for item in reply.authz["rejected"]] == ["fmt"]
    assert reply.authz["allowed"]["fmt"]["deny"] == ["xml"]
    assert reply.authz["allowed"]["fmt"]["has_default"] is True
    assert "action" not in reply.authz


def check_a_pattern_rejection_with_no_default_refuses_the_call(client: WebCaller) -> None:
    """A malformed order id is refused rather than replaced by one nobody asked for.

    ``amount`` survived, so this is not the "nothing left to run with" refusal: it is the one
    argument that failed having no answer available. Which is the right answer rather than a
    shortcoming — no default order id could be correct, and inventing one would refund the
    wrong order.
    """
    payload = {"order_id": "refund-me", "amount": 100, "region": "eu"}

    reply = client.post("/refunds", json=payload, user="alice")

    assert reply.status == 400
    assert reply.error == "DefaultUnavailable"
    assert reply.body["detail"] == (
        "Argument 'order_id' is required and no policy default is configured."
    )
    assert reply.authz["rejected"] == [
        {"name": "order_id", "reason": "No policy default is configured."}
    ]
    assert "action" not in reply.authz


def check_the_gate_permits_a_value_the_argument_layer_then_rejects(client: WebCaller) -> None:
    """Two layers answer two different questions about one number, in one call.

    900 is under the reviewed desk limit of 1000, so the gate permits the call. It is above
    alice's own maximum of 750, so the argument layer rejects the value and refills with her
    default of 50 — not with 750, which is the bound that refused it.
    """
    payload = {"order_id": "ord-0007", "amount": 900, "region": "eu"}

    reply = client.post("/refunds", json=payload, user="alice")

    assert reply.status == 200
    assert reply.body["amount"] == 50
    assert reply.authz["decision"] == "allow"
    assert reply.authz["rejected"][0]["policy"] == "alice-amount"
    assert reply.authz["defaults_applied"] == {"amount": 50}


# --- decisions Cedar makes about more than one thing at once ------------------------------


def check_two_arguments_each_permitted_alone_are_refused_together(client: WebCaller) -> None:
    """A rule about the *pair*: neither value is out of bounds, and the combination is.

    ``no-large-cross-region-refunds`` forbids a refund over 200 booked outside ``eu``. Alice's
    grants permit ``region="uk"`` and ``amount=750`` both, and each is asserted to be allowed
    on its own here, because otherwise the refusal in the middle would prove nothing. No
    per-argument rule could express this; Cedar evaluates the whole request at once.
    """
    sentrykit.configure(verbosity="debug")
    order = {"order_id": "ord-0007"}

    refused = client.post("/refunds", json=order | {"amount": 750, "region": "uk"}, user="alice")
    small = client.post("/refunds", json=order | {"amount": 100, "region": "uk"}, user="alice")
    home = client.post("/refunds", json=order | {"amount": 750, "region": "eu"}, user="alice")

    assert refused.status == 403
    assert refused.error == "AuthzDenied"
    assert refused.authz["determining_policies"] == ["no-large-cross-region-refunds"]
    assert small.status == 200
    assert small.body["region"] == "uk"
    assert home.status == 200
    assert home.body["amount"] == 750


def check_an_argument_is_weighed_against_the_principal_who_proposed_it(
    client: WebCaller,
) -> None:
    """The same call, refused for alice and permitted for dana, by one ``forbid``.

    ``refunds-above-the-desk-limit-need-an-admin`` reads the proposed ``amount`` *and* the
    principal together, so the desk limit lifts for an admin without a second permit anywhere.
    A ``forbid`` that fires is determining, so alice's refusal names it at ``debug``.
    """
    sentrykit.configure(verbosity="debug")
    payload = {"order_id": "ord-0007", "amount": 5000, "region": "eu"}

    refused = client.post("/refunds", json=payload, user="alice")
    allowed = client.post("/refunds", json=payload, user="dana")

    assert refused.status == 403
    assert refused.authz["determining_policies"] == ["refunds-above-the-desk-limit-need-an-admin"]
    assert allowed.status == 200
    assert allowed.body["amount"] == 5000


# --- what the decorator and the entity graph settle ---------------------------------------


def check_the_bare_protect_is_authorized_under_its_derived_import_path(
    client: WebCaller,
) -> None:
    """``desk_status`` carries no ``action=``, so both ids come from the callable's own path.

    The expectation is read off the function rather than typed out, because the claim is that
    the id *is* the import path — a literal would go on agreeing with itself if the derivation
    changed. That is also the fragility the examples warn about: moving or renaming the
    function silently changes the id and the reviewed policy stops matching it.
    """
    service = import_module(f"{_SERVICE_MODULE[client.framework]}")
    path = f"{service.desk_status.__module__}.{service.desk_status.__qualname__}"

    reply = client.get("/orders/status", user="alice")

    assert reply.status == 200
    assert reply.body["desk"] == "orders"
    assert reply.authz["action"] == f'Action::"{path}"'
    assert reply.authz["resource"] == f'Resource::"{path}"'


def check_an_admin_reaches_a_support_permit_through_one_role_edge(client: WebCaller) -> None:
    """Dana holds ``admin`` and nothing else, and satisfies ``principal in Role::"support"``.

    ``Role::"admin"`` has ``Role::"support"`` as a parent in the entity graph, so "an admin is
    a superset of support" is one edge rather than a second grant on every admin. Her grant is
    read from the store here as well as exercised through the route: asserting only that she
    can search would pass just as happily against a store that had quietly given her both.
    """
    policy = import_module(f"{_POLICY_MODULE[client.framework]}")
    dana = policy.build_grants().get_principal("dana")

    reply = client.get("/orders", user="dana")

    assert dana is not None
    assert dana.roles == ("admin",)
    assert reply.status == 200
    assert reply.authz["decision"] == "allow"
    assert reply.authz["action"] == 'Action::"orders.search"'


def check_a_multi_hop_relationship_decides_a_read_no_policy_names_either_side_of(
    client: WebCaller,
) -> None:
    """Alice reads ``Order::"o-1"`` and bob does not, through edges no policy mentions.

    The permit names ``Project::"orders-eu"`` at both ends. Alice reaches it through her team
    and her division; the order hangs off it as a parent; Cedar walks both. Bob's chain is
    exactly as long and lands on ``Project::"orders-us"``, so the identical call with the
    identical argument is refused — and no route, no callable and no test resolves any of it.
    """
    allowed = client.get("/orders/o-1", user="alice")
    refused = client.get("/orders/o-1", user="bob")

    assert allowed.status == 200
    assert allowed.body["order_id"] == "o-1"
    assert allowed.authz["resource"] == 'Order::"o-1"'
    assert refused.status == 403
    assert refused.error == "AuthzDenied"
    assert refused.authz["resource"] == 'Order::"o-1"'


def check_the_admin_action_answers_two_principals_differently(client: WebCaller) -> None:
    """``approve_refund`` takes no argument policy has an opinion about, so only role decides.

    Alice's refusal is the shape that names nothing: no permit reaches her for
    ``refunds.approve``, the request falls through to Cedar's default deny, and
    ``determining_policies`` is empty even at ``debug``. There is no rule to point at, and
    reporting one would be inventing it.
    """
    sentrykit.configure(verbosity="debug")

    allowed = client.post("/refunds/rf-1/approve", json={}, user="dana")
    refused = client.post("/refunds/rf-1/approve", json={}, user="alice")

    assert allowed.status == 200
    assert allowed.body["approved"] is True
    assert refused.status == 403
    assert refused.authz["action"] == 'Action::"refunds.approve"'
    assert refused.authz["determining_policies"] == []


WEB_CONTRACT: tuple[Callable[[WebCaller], None], ...] = (
    check_defaults_are_injected_when_the_caller_supplies_no_arguments,
    check_arguments_the_policy_permits_are_passed_through_untouched,
    check_a_disallowed_argument_is_dropped_and_replaced_by_its_default,
    check_a_call_whose_every_argument_was_refused_is_itself_refused,
    check_a_principal_without_the_role_is_denied_the_route,
    check_an_unauthenticated_caller_is_denied,
    check_a_principal_the_grant_store_never_heard_of_is_denied,
    check_the_export_route_allows_the_principal_whose_role_permits_it,
    check_the_export_route_denies_the_principal_whose_role_does_not,
    check_a_forbid_on_one_argument_value_beats_the_permit_that_allowed_the_action,
    check_a_protected_non_route_callable_is_governed_by_the_ambient_principal,
    check_the_non_route_callable_refuses_a_principal_the_policy_denies,
    check_the_non_route_callable_refuses_an_unauthenticated_caller,
    check_a_reviewed_ceiling_narrows_to_the_principals_own_default,
    check_several_arguments_are_decided_in_one_call,
    check_a_denied_format_is_rejected_and_refilled_beside_a_surviving_argument,
    check_the_same_denied_format_alone_leaves_nothing_to_run_with,
    check_a_pattern_rejection_with_no_default_refuses_the_call,
    check_the_gate_permits_a_value_the_argument_layer_then_rejects,
    check_two_arguments_each_permitted_alone_are_refused_together,
    check_an_argument_is_weighed_against_the_principal_who_proposed_it,
    check_the_bare_protect_is_authorized_under_its_derived_import_path,
    check_an_admin_reaches_a_support_permit_through_one_role_edge,
    check_a_multi_hop_relationship_decides_a_read_no_policy_names_either_side_of,
    check_the_admin_action_answers_two_principals_differently,
)
"""Every row of the shared web behaviour table, in the order it is stated above."""


# --- verbosity trimming, seen through HTTP ------------------------------------------------
#
# The envelope's trimming rules are unit-tested; what these add is that a *provider* renders
# them faithfully, on the refusal path, where the envelope is rebuilt from the exception
# rather than read from ambient state.


def check_verbosity_off_tells_the_caller_nothing_beyond_the_status(client: WebCaller) -> None:
    """No envelope, no exception class, no action name — just the generic reason phrase."""
    sentrykit.configure(verbosity="off")

    reply = client.get("/orders", user="bob")

    assert reply.status == 403
    assert reply.body == {"detail": "Forbidden"}


def check_summary_verbosity_names_a_rejected_argument_without_its_value(
    client: WebCaller,
) -> None:
    sentrykit.configure(verbosity="summary")

    reply = client.get("/orders?region=cn&limit=5", user="alice")

    assert reply.status == 200
    rejection = reply.authz["rejected"][0]
    assert rejection["name"] == "region"
    assert rejection["reason"]
    assert "value" not in rejection


def check_summary_verbosity_withholds_the_set_a_caller_may_retry_with(
    client: WebCaller,
) -> None:
    """``allowed`` describes the principal's own entitlement, so it is a ``verbose`` field."""
    sentrykit.configure(verbosity="summary")

    reply = client.get("/orders?region=cn", user="alice")

    assert reply.status == 400
    assert "allowed" not in reply.authz


def check_verbose_verbosity_carries_the_offending_value(client: WebCaller) -> None:
    sentrykit.configure(verbosity="verbose")

    reply = client.get("/orders?region=cn&limit=5", user="alice")

    assert reply.status == 200
    assert reply.authz["rejected"][0]["value"] == "cn"


def check_verbose_verbosity_carries_the_set_a_caller_may_retry_with(client: WebCaller) -> None:
    sentrykit.configure(verbosity="verbose")

    reply = client.get("/orders?region=cn", user="alice")

    assert reply.status == 400
    assert reply.authz["allowed"]["region"]["allow"] == ["eu", "uk"]


def check_only_debug_verbosity_names_the_policies_behind_a_denial(client: WebCaller) -> None:
    """Policy ids describe the shape of the rule set, so they stop at ``debug``."""
    sentrykit.configure(verbosity="verbose")
    quiet = client.post("/orders/export", json={"fmt": "pdf"}, user="bob")

    sentrykit.configure(verbosity="debug")
    loud = client.post("/orders/export", json={"fmt": "pdf"}, user="bob")

    assert quiet.status == loud.status == 403
    assert "determining_policies" not in quiet.authz
    assert loud.authz["determining_policies"] == ["no-pdf-exports"]


REFUSAL_VERBOSITY: tuple[Callable[[WebCaller], None], ...] = (
    check_verbosity_off_tells_the_caller_nothing_beyond_the_status,
    check_summary_verbosity_names_a_rejected_argument_without_its_value,
    check_summary_verbosity_withholds_the_set_a_caller_may_retry_with,
    check_verbose_verbosity_carries_the_offending_value,
    check_verbose_verbosity_carries_the_set_a_caller_may_retry_with,
    check_only_debug_verbosity_names_the_policies_behind_a_denial,
)
"""What each verbosity does and does not disclose over HTTP."""


def _case_id(check: Callable[[WebCaller], None]) -> str:
    """Name a parametrized case after the behaviour its function describes."""
    return check.__name__.removeprefix("check_")


@pytest.fixture(params=WEB_CONTRACT, ids=_case_id)
def web_contract_case(request: pytest.FixtureRequest) -> Callable[[WebCaller], None]:
    """One row of :data:`WEB_CONTRACT`, to be run against a framework's caller."""
    case: Callable[[WebCaller], None] = request.param
    return case


@pytest.fixture(params=REFUSAL_VERBOSITY, ids=_case_id)
def refusal_verbosity_case(request: pytest.FixtureRequest) -> Callable[[WebCaller], None]:
    """One row of :data:`REFUSAL_VERBOSITY`, to be run against a framework's caller."""
    case: Callable[[WebCaller], None] = request.param
    return case
