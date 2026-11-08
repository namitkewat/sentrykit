"""The exception hierarchy, tested as the contract it is rather than as raising incidentals.

A sentrykit error is the whole of what a boundary has to work with. Rendering a refusal reads
the exception and nothing else, because ambient state is not reliably there by the time a
framework's error handler runs — so what an error carries is public API, and a field that
quietly stopped being populated would surface as a thinner response rather than as a failure.

What is pinned here is the part of that contract no single raise site owns: the attribute
every error has because it is declared on the base class.
"""

from __future__ import annotations

import pytest

from sentrykit.errors import (
    ArgumentRejected,
    AuditUnavailable,
    AuthzDenied,
    ConfigurationError,
    DefaultUnavailable,
    NoContext,
    NoValidArguments,
    ReservedKey,
    SentrykitError,
    ValidationFailed,
)

SEARCH = 'Action::"orders.search"'
ORDERS = 'Tool::"orders"'

EVERY_ERROR = [
    ArgumentRejected("region", "not in the allowed set"),
    AuditUnavailable("jsonl", "no space left on device"),
    AuthzDenied(SEARCH, ORDERS, ["support-may-search"]),
    ConfigurationError("no grant store is configured"),
    DefaultUnavailable("customer_id"),
    NoContext(SEARCH),
    NoValidArguments({"region": {"allow": ["eu"]}}, [{"name": "region", "value": "us"}]),
    ReservedKey("__entity", "args.region"),
    ValidationFailed([{"loc": ("limit",), "msg": "input should be a valid integer"}]),
]
"""One instance of every error in the hierarchy, so a new one cannot miss the sweep below."""


# --- the unrecorded-refusal attribute --------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("error", EVERY_ERROR, ids=lambda error: type(error).__name__)
def test_an_error_carries_no_audit_failure_unless_one_is_attached(error: SentrykitError) -> None:
    """``None`` is the answer on the path every deployment spends its life on.

    The attribute is declared on the base class so that any refusal *can* report an audit
    sink that would not take it, which only works as a signal if its absence is the default:
    a handler that reads it must be able to treat "set" as the exceptional case without
    knowing which error it is holding.
    """
    assert error.audit_failure is None


@pytest.mark.unit
def test_the_base_class_is_where_the_audit_failure_is_declared() -> None:
    """Declared on the base, not improvised at a raise site, and that is the whole difference.

    Any refusal can be the one a sink would not take, so every refusal has to be able to say
    so — and a writer that merely set the attribute on whatever it was holding would be
    writing a field no reader could rely on, and no type checker would accept.
    """
    assert SentrykitError.audit_failure is None


@pytest.mark.unit
def test_a_refusal_can_carry_the_sink_failure_that_stopped_it_being_recorded() -> None:
    """A refusal nobody could write down travels with the reason it could not be written.

    The failure is attached rather than raised in the refusal's place, which is the whole
    point: the caller needs the precise refusal, and the operator needs to know it left no
    trace. Replacing one with the other loses whichever the reader was not asking for. It is
    per-refusal state, so the one next to it — and the class default every other refusal
    reads — are untouched by the attachment.
    """
    unavailable = AuditUnavailable("jsonl", "no space left on device")
    denied = AuthzDenied(SEARCH, ORDERS, ["support-may-search"])
    recorded = AuthzDenied(SEARCH, ORDERS, ["support-may-search"])

    denied.audit_failure = unavailable

    assert denied.audit_failure is unavailable
    assert denied.audit_failure.sink == "jsonl"
    assert recorded.audit_failure is None
    assert SentrykitError.audit_failure is None
