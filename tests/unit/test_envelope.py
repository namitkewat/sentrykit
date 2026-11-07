"""The ``_authz`` envelope: what each verbosity level is allowed to tell the caller."""

from __future__ import annotations

from contextvars import copy_context
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
    current_recorder,
    last_envelope,
    narrowing_guidance,
    record_decisions,
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


# --- the outcome half: narrowed / narrowed_arguments / guidance ------------------------
#
# These three say what the decision *did*, where `rejected` says only what it would not
# accept. They exist because an envelope reporting only the exceptions reads as a failure
# report, and a reader acting on it withholds a result it is already holding.


@pytest.mark.unit
def test_a_clean_allow_says_nothing_about_narrowing() -> None:
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
    assert envelope.narrowed is False
    assert envelope.guidance is None
    # Dropped rather than rendered as ``false``: emitting the key on every ordinary
    # response would train a reader to skip it.
    assert "narrowed" not in envelope.as_dict()


@pytest.mark.unit
@pytest.mark.parametrize("verbosity", ["summary", "verbose", "debug"])
def test_the_outcome_fields_survive_every_verbosity_that_reports_at_all(
    verbosity: Verbosity,
) -> None:
    """They carry no values and no policy ids, so verbosity has nothing to trim."""
    envelope = _envelope(verbosity, narrowed_arguments=("region",))

    assert envelope is not None
    rendered = envelope.as_dict()
    assert rendered["narrowed"] is True
    assert rendered["narrowed_arguments"] == ["region"]
    assert "This result is valid and was served." in str(rendered["guidance"])


@pytest.mark.unit
def test_verbosity_off_still_reports_nothing_at_all() -> None:
    assert _envelope("off", narrowed_arguments=("region",)) is None


@pytest.mark.unit
def test_guidance_leaks_no_value_and_no_policy_id() -> None:
    """The reason it is safe below ``verbose``: there is nothing in it to withhold."""
    envelope = _envelope("summary", narrowed_arguments=("region",))

    assert envelope is not None
    guidance = str(envelope.guidance)
    assert REJECTION.value is not None
    assert str(REJECTION.value) not in guidance
    assert str(REJECTION.policy) not in guidance
    assert "eu-west" not in guidance


@pytest.mark.unit
def test_a_refilled_narrowing_vouches_for_the_result() -> None:
    assert narrowing_guidance(["region", "limit"]).startswith(
        "This result is valid and was served."
    )


@pytest.mark.unit
def test_a_narrowing_with_no_replacement_refuses_to_vouch_for_it() -> None:
    """The callable's own signature default landed in the slot and no constraint saw it.

    Claiming the result is "valid" there would be exactly the overclaim the envelope exists
    to prevent, so the wording says "served" and marks that part unverified.
    """
    guidance = narrowing_guidance(["limit"], unsupplied=["limit"])

    assert "This result was served" in guidance
    assert "valid" not in guidance
    assert "unverified" in guidance
    assert "no replacement" in guidance


@pytest.mark.unit
def test_a_mixed_narrowing_separates_what_policy_supplied_from_what_it_did_not() -> None:
    guidance = narrowing_guidance(["region", "limit"], unsupplied=["limit"])

    assert "unverified" in guidance
    assert "region did come from this principal's own entitlement." in guidance


# --- the recorder: the channel that survives a copied context -------------------------


@pytest.mark.unit
def test_no_recorder_outside_a_boundary() -> None:
    """A plain `with establish(...)` block installs none, and nothing requires one."""
    assert current_recorder() is None


@pytest.mark.unit
def test_a_recorder_accumulates_the_union_across_decisions() -> None:
    """A response-level report asks about the whole request, not the last decision."""
    recorder = record_decisions()
    try:
        recorder.record(_envelope("summary", narrowed_arguments=("region",)))  # type: ignore[arg-type]
        recorder.record(_envelope("summary", narrowed_arguments=("limit", "region")))  # type: ignore[arg-type]

        assert recorder.decisions == 2
        # First-seen order, de-duplicated: ``region`` is not repeated.
        assert recorder.narrowed_arguments == ("region", "limit")
        assert recorder.narrowed is True
    finally:
        recorder.close()


@pytest.mark.unit
def test_a_recorder_stays_quiet_when_nothing_narrowed() -> None:
    recorder = record_decisions()
    try:
        recorder.record(_envelope("summary"))  # type: ignore[arg-type]

        assert recorder.decisions == 1
        assert recorder.narrowed is False
        assert recorder.narrowed_arguments == ()
    finally:
        recorder.close()


@pytest.mark.unit
def test_set_last_envelope_feeds_the_installed_recorder() -> None:
    """The engine calls `set_last_envelope`; it must not also have to know about recorders."""
    recorder = record_decisions()
    try:
        set_last_envelope(_envelope("summary", narrowed_arguments=("region",)))

        assert recorder.narrowed_arguments == ("region",)
    finally:
        recorder.close()


@pytest.mark.unit
def test_a_none_envelope_records_nothing() -> None:
    """Verbosity ``off`` must produce no headers rather than empty ones."""
    recorder = record_decisions()
    try:
        set_last_envelope(None)

        assert recorder.decisions == 0
        assert recorder.narrowed is False
    finally:
        recorder.close()


@pytest.mark.unit
def test_closing_a_recorder_is_idempotent_and_uninstalls_it() -> None:
    recorder = record_decisions()
    recorder.close()
    recorder.close()

    assert current_recorder() is None


@pytest.mark.unit
def test_a_recorder_mutation_survives_a_copied_context() -> None:
    """The whole reason the recorder exists, asserted directly.

    A ``ContextVar`` write inside a copied context is discarded when the copy is dropped --
    which is what happens to every sync framework route, since it runs in a worker thread.
    A mutation to an object *reached through* the variable is not. See ADR-029.
    """
    recorder = record_decisions()
    try:
        narrowed = _envelope("summary", narrowed_arguments=("region",))

        def inside_a_copy() -> None:
            set_last_envelope(narrowed)
            # Visible here, because this context has its own copy of the value.
            assert last_envelope() is narrowed

        copy_context().run(inside_a_copy)

        # The value written to the ContextVar did NOT come back...
        assert last_envelope() is None
        # ...and the mutation to the recorder did.
        assert recorder.narrowed_arguments == ("region",)
    finally:
        recorder.close()


@pytest.mark.unit
def test_attaching_to_a_mapping_records_that_it_went_in_band() -> None:
    """What the agent adapters read to avoid saying the same thing twice."""
    recorder = record_decisions()
    try:
        envelope = _envelope("summary", narrowed_arguments=("region",))
        set_last_envelope(envelope)
        assert recorder.last_was_in_band is False

        attach_envelope({"region": "eu"}, envelope)

        assert recorder.last_was_in_band is True
    finally:
        recorder.close()


@pytest.mark.unit
def test_attaching_to_a_non_mapping_records_that_it_did_not() -> None:
    recorder = record_decisions()
    try:
        envelope = _envelope("summary", narrowed_arguments=("region",))
        set_last_envelope(envelope)

        attach_envelope([{"region": "eu"}], envelope)

        assert recorder.last_was_in_band is False
    finally:
        recorder.close()
