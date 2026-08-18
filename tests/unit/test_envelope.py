"""The ``_authz`` envelope: what each verbosity level is allowed to tell the caller."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from sentrykit.config import Verbosity
from sentrykit.constraints import RejectedArgument
from sentrykit.envelope import (
    ENVELOPE_KEY,
    AuthzEnvelope,
    attach_envelope,
    build_envelope,
    last_envelope,
    set_last_envelope,
)

REJECTION = RejectedArgument(
    name="region",
    rule="pattern",
    reason="Value does not match the permitted pattern.",
    policy="grant-orders-region",
    value="us-east-1",
)


def _envelope(verbosity: Verbosity, **overrides: Any) -> AuthzEnvelope | None:
    payload: dict[str, Any] = {
        "decision": "allow",
        "action": 'Action::"tool.search_orders"',
        "resource": 'Tool::"orders"',
        "principal": 'User::"casey"',
        "processed": {"customer_id": "c-1", "region": "eu-west"},
        "rejected": (REJECTION,),
        "defaults_applied": {"region": "eu-west"},
        "obligations": ("justify",),
        "determining_policies": ("support-may-search",),
        "trace": {"policy_set_hash": "abc123", "errors": []},
    }
    payload.update(overrides)
    return build_envelope(verbosity=verbosity, **payload)


@pytest.mark.unit
def test_verbosity_off_produces_no_envelope_at_all() -> None:
    assert _envelope("off") is None


@pytest.mark.unit
def test_summary_names_what_happened() -> None:
    envelope = _envelope("summary")

    assert envelope is not None
    assert envelope.decision == "allow"
    assert envelope.action == 'Action::"tool.search_orders"'
    assert envelope.resource == 'Tool::"orders"'
    assert [item.name for item in envelope.rejected] == ["region"]
    assert envelope.rejected[0].reason
    assert set(envelope.defaults_applied) == {"region"}
    assert envelope.obligations == ("justify",)


@pytest.mark.unit
def test_summary_carries_no_argument_values() -> None:
    envelope = _envelope("summary")

    assert envelope is not None
    assert envelope.processed == {}
    assert envelope.rejected[0].value is None
    assert "us-east-1" not in str(envelope.model_dump())
    assert "eu-west" not in str(envelope.model_dump())


@pytest.mark.unit
def test_summary_withholds_the_principal_the_policies_and_the_trace() -> None:
    envelope = _envelope("summary")

    assert envelope is not None
    assert envelope.principal is None
    assert envelope.determining_policies == ()
    assert envelope.trace is None


@pytest.mark.unit
def test_verbose_adds_the_processed_values() -> None:
    envelope = _envelope("verbose")

    assert envelope is not None
    assert envelope.processed == {"customer_id": "c-1", "region": "eu-west"}
    assert envelope.defaults_applied == {"region": "eu-west"}
    assert envelope.rejected[0].value == "us-east-1"
    assert envelope.principal == 'User::"casey"'


@pytest.mark.unit
def test_verbose_still_withholds_the_policies_and_the_trace() -> None:
    envelope = _envelope("verbose")

    assert envelope is not None
    assert envelope.determining_policies == ()
    assert envelope.trace is None


@pytest.mark.unit
def test_debug_adds_the_determining_policies_and_the_trace() -> None:
    envelope = _envelope("debug")

    assert envelope is not None
    assert envelope.determining_policies == ("support-may-search",)
    assert envelope.trace == {"policy_set_hash": "abc123", "errors": []}
    assert envelope.processed == {"customer_id": "c-1", "region": "eu-west"}


@pytest.mark.unit
def test_a_denial_envelope_explains_itself() -> None:
    envelope = _envelope("summary", decision="deny", reason="Principal is suspended.")

    assert envelope is not None
    assert envelope.decision == "deny"
    assert envelope.reason == "Principal is suspended."


@pytest.mark.unit
def test_a_clean_allow_renders_without_empty_sections() -> None:
    envelope = build_envelope(
        decision="allow",
        action='Action::"tool.ping"',
        resource=None,
        principal=None,
        processed={},
        rejected=(),
        defaults_applied={},
        verbosity="summary",
    )

    assert envelope is not None
    rendered = envelope.as_dict()

    assert rendered["decision"] == "allow"
    assert rendered["action"] == 'Action::"tool.ping"'
    assert "rejected" not in rendered
    assert "defaults_applied" not in rendered
    assert "trace" not in rendered
    assert "resource" not in rendered


@pytest.mark.unit
def test_an_envelope_is_immutable() -> None:
    envelope = _envelope("debug")

    assert envelope is not None
    with pytest.raises(ValidationError):
        envelope.decision = "deny"  # type: ignore[misc]


# --- attaching ------------------------------------------------------------------------


@pytest.mark.unit
def test_no_decision_has_been_made_yet() -> None:
    assert last_envelope() is None


@pytest.mark.unit
def test_a_mapping_result_carries_the_envelope_home() -> None:
    envelope = _envelope("summary")
    result: dict[str, object] = {"orders": []}

    returned = attach_envelope(result, envelope)

    assert returned is result
    attached = result[ENVELOPE_KEY]
    payload = attached.as_dict() if isinstance(attached, AuthzEnvelope) else attached
    assert isinstance(payload, dict)
    assert payload["decision"] == "allow"


@pytest.mark.unit
def test_a_non_mapping_result_is_returned_untouched() -> None:
    envelope = _envelope("summary")
    result = ["order-1", "order-2"]

    returned = attach_envelope(result, envelope)

    assert returned is result
    assert returned == ["order-1", "order-2"]


@pytest.mark.unit
def test_the_envelope_is_reachable_even_when_the_result_could_not_carry_it() -> None:
    envelope = _envelope("summary")

    attach_envelope(["order-1"], envelope)

    assert last_envelope() == envelope


@pytest.mark.unit
def test_attaching_nothing_leaves_the_result_clean() -> None:
    result: dict[str, object] = {"orders": []}

    returned = attach_envelope(result, None)

    assert returned == {"orders": []}
    assert ENVELOPE_KEY not in result
    assert last_envelope() is None


@pytest.mark.unit
def test_the_last_envelope_can_be_recorded_directly() -> None:
    envelope = _envelope("debug")

    set_last_envelope(envelope)

    assert last_envelope() == envelope
