"""The framework-independent half of the web integration suite.

One decorator and N providers means a FastAPI 403 and a Flask 403 are the *same* 403. A
claim like that is
only tested if both frameworks are asked exactly the same questions, so the questions live
here — as plain functions over a :class:`WebCaller` — and each framework module answers them
with its own client. Duplicating thirteen assertions twice would let the two copies drift, and
a drifted copy is how "identical on both frameworks" quietly stops being true.

Nothing in this module imports a web framework. It is loaded in the ``default`` pixi
environment too, where FastAPI and Flask are absent and every test module that needs them has
already skipped itself at import time. The adapters below only ever call ``request``/``open``
on a client somebody else built, so they need no import to do it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

import pytest

import sentrykit

PRINCIPAL_HEADER = "x-user"
"""The header both example apps read a principal id from. Their auth stub, and the seam a
real application replaces with its session or its gateway's assertion."""

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
