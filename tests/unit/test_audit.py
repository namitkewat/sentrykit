"""The audit record, the hash chain, and the one path from a decision to a sink.

Two failure modes get separate tests because they are caught by two different checks. A
*rewritten* record is caught by re-hashing its own content. A *deleted* record is not: every
remaining record still hashes correctly on its own, and only the link — one record's
``prev_hash`` against its predecessor's ``record_hash`` — notices the gap. A verifier that
only did the first would pass a log somebody had quietly pruned.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

import pytest

from sentrykit.audit import (
    GENESIS_HASH,
    AuditTrail,
    AuthzAuditRecord,
    DecisionFacts,
    PrincipalSnapshot,
    build_facts,
    canonical_json,
    verify_chain,
)
from sentrykit.cedar import CedarDecision, EntityRef
from sentrykit.constraints import ArgumentConstraint, ConstraintSet, RejectedArgument
from sentrykit.context import Invocation, Principal
from sentrykit.errors import AuditUnavailable
from sentrykit.masking import Masker
from sentrykit.stores.base import AuditWindow, NullAuditSink, PolicyBundle
from sentrykit.stores.memory import InMemoryAuditSink

RecordFactory = Callable[..., AuthzAuditRecord]
ChainBuilder = Callable[[Sequence[AuthzAuditRecord]], "tuple[AuthzAuditRecord, ...]"]

KEY = b"a-test-hmac-key"
MONDAY = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
TUESDAY = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
FRIDAY = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)

SEARCH = EntityRef("Action", "tool.search_orders")
ORDERS = EntityRef("Tool", "orders")

POLICY = """
@id("support-may-search")
@obligations("redact:secret, notify:secops")
permit (
  principal in Role::"support",
  action == Action::"tool.search_orders",
  resource == Tool::"orders"
);
"""

ALLOWED = CedarDecision(
    allowed=True,
    decision="allow",
    determining_policies=("support-may-search",),
    policy_set_hash="deadbeef",
)


def _invocation(**overrides: object) -> Invocation:
    fields: dict[str, object] = {
        "id": "inv-1",
        "principal": Principal(id="alice", roles=("support",)),
        "action": SEARCH,
        "resource": ORDERS,
        "proposed": {"customer_id": "c-1"},
        "environment": {"channel": "http", "now": MONDAY},
        "callable_name": "tests.search_orders",
    }
    fields.update(overrides)
    return Invocation(**fields)  # type: ignore[arg-type]


def _masker() -> Masker:
    return Masker(key=KEY)


# --- canonical encoding --------------------------------------------------------------------


@pytest.mark.unit
def test_the_canonical_encoding_does_not_depend_on_key_order() -> None:
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


@pytest.mark.unit
def test_the_canonical_encoding_is_utf8_bytes() -> None:
    encoded = canonical_json({"reason": "naïve"})

    assert isinstance(encoded, bytes)
    assert json.loads(encoded.decode("utf-8"))["reason"] == "naïve"


@pytest.mark.unit
def test_an_unrenderable_value_falls_back_rather_than_failing_the_decision() -> None:
    encoded = canonical_json({"value": object()})

    assert b"object" in encoded


# --- the record ----------------------------------------------------------------------------


@pytest.mark.unit
def test_a_principal_snapshot_captures_the_edges_the_decision_saw() -> None:
    principal = Principal(
        id="alice",
        roles=("support",),
        parents=(EntityRef("Team", "payments"),),
        attributes={"clearance": "high"},
        constraints={
            'Action::"tool.search_orders"': ConstraintSet(
                arguments={"customer_id": ArgumentConstraint(allow=("c-1",), default="c-1")}
            )
        },
    )

    snapshot = PrincipalSnapshot.of(principal)

    assert snapshot.uid == 'User::"alice"'
    assert snapshot.roles == ("support",)
    assert 'Team::"payments"' in snapshot.parents
    assert snapshot.attributes["clearance"] == "high"
    assert 'Action::"tool.search_orders"' in snapshot.constraints


@pytest.mark.unit
def test_the_hash_covers_the_content_and_the_link(make_record: RecordFactory) -> None:
    record = make_record().chained(prev_hash=GENESIS_HASH, sequence=0)

    assert record.record_hash == record.compute_hash()
    assert record.verify() is True
    assert "record_hash" not in record.payload()
    assert record.payload()["prev_hash"] == GENESIS_HASH


@pytest.mark.unit
def test_repointing_a_record_at_a_different_predecessor_changes_its_own_hash(
    make_record: RecordFactory,
) -> None:
    record = make_record()

    first = record.chained(prev_hash=GENESIS_HASH, sequence=0)
    second = record.chained(prev_hash="f" * 64, sequence=0)

    assert first.record_hash != second.record_hash


@pytest.mark.unit
def test_a_record_with_no_signature_defaults_hashes_a_payload_the_key_is_absent_from(
    make_record: RecordFactory,
) -> None:
    """``payload`` is the canonical pre-image, so every key it emits joins the integrity claim.

    Every record already in a deployed log hashed a payload with no ``signature_defaults`` key
    in it. A key that appeared even at its default would change every one of those digests and
    turn an intact log into a broken one on the next read. Omitting it when empty costs
    nothing, because a tuple that is *set* is in the payload — so it can be neither stripped
    off a record that reported one nor invented on a record that did not.
    """
    fixed = {"record_id": "rec-same", "invocation_id": "inv-same"}
    clean = make_record(**fixed).chained(prev_hash=GENESIS_HASH, sequence=0)
    filled = make_record(**fixed, signature_defaults=("limit",)).chained(
        prev_hash=GENESIS_HASH, sequence=0
    )

    assert "signature_defaults" not in clean.payload()
    assert filled.payload()["signature_defaults"] == ["limit"]
    assert clean.record_hash != filled.record_hash
    assert clean.verify()
    assert filled.verify()
    assert not filled.model_copy(update={"signature_defaults": ()}).verify()
    assert not clean.model_copy(update={"signature_defaults": ("limit",)}).verify()


@pytest.mark.unit
def test_editing_a_record_after_it_was_hashed_no_longer_verifies(
    make_record: RecordFactory,
) -> None:
    record = make_record(reason="denied by policy").chained(prev_hash=GENESIS_HASH, sequence=0)

    edited = record.model_copy(update={"reason": "allowed after all"})

    assert edited.verify() is False


# --- the chain -----------------------------------------------------------------------------


@pytest.mark.unit
def test_an_intact_chain_verifies(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    verdict = verify_chain(chained([make_record() for _ in range(4)]))

    assert verdict.ok is True
    assert verdict.broken_at is None


@pytest.mark.unit
def test_an_empty_chain_verifies() -> None:
    assert verify_chain(()).ok is True


@pytest.mark.unit
def test_a_window_over_a_longer_log_verifies_without_reaching_the_genesis_record(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    """``verify_chain`` verifies a *run*, so a report over a slice must not read as tampered."""
    records = chained([make_record() for _ in range(5)])

    assert verify_chain(records[2:]).ok is True


@pytest.mark.unit
def test_a_record_rewritten_after_hashing_is_caught(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    records = list(chained([make_record() for _ in range(4)]))
    records[2] = records[2].model_copy(update={"reason": "somebody rewrote this"})

    verdict = verify_chain(records)

    assert verdict.ok is False
    assert verdict.broken_at == 2
    assert verdict.reason


@pytest.mark.unit
def test_a_record_deleted_from_the_middle_is_caught(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    records = list(chained([make_record() for _ in range(4)]))
    del records[1]

    verdict = verify_chain(records)

    assert verdict.ok is False
    assert verdict.broken_at == 2


@pytest.mark.unit
def test_a_record_deleted_from_the_end_leaves_the_rest_intact(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    records = list(chained([make_record() for _ in range(4)]))

    assert verify_chain(records[:-1]).ok is True


# --- the window ----------------------------------------------------------------------------


@pytest.mark.unit
def test_an_empty_window_matches_everything(make_record: RecordFactory) -> None:
    assert AuditWindow().matches(make_record()) is True


@pytest.mark.unit
@pytest.mark.parametrize(
    ("window", "expected"),
    [
        (AuditWindow(start=MONDAY), True),
        (AuditWindow(start=FRIDAY), False),
        (AuditWindow(end=FRIDAY), True),
        (AuditWindow(end=MONDAY), False),
        (AuditWindow(principal='User::"alice"'), True),
        (AuditWindow(principal='User::"mallory"'), False),
        (AuditWindow(action="tool.search_orders"), True),
        (AuditWindow(action='Action::"tool.search_orders"'), True),
        (AuditWindow(action="tool.export_orders"), False),
        (AuditWindow(resource='Tool::"orders"'), True),
        (AuditWindow(decision="allow"), True),
        (AuditWindow(decision="deny"), False),
        (AuditWindow(kind="decision"), True),
        (AuditWindow(kind="mutation"), False),
    ],
)
def test_every_window_field_narrows(
    window: AuditWindow, expected: bool, make_record: RecordFactory
) -> None:
    assert window.matches(make_record(timestamp=TUESDAY)) is expected


# --- the trail -----------------------------------------------------------------------------


@pytest.mark.unit
def test_a_trail_with_no_sink_does_no_work() -> None:
    trail = AuditTrail(None)

    assert trail.enabled is False
    assert trail.sink is None
    assert (
        trail.record(
            build_facts(invocation=_invocation(), decision=ALLOWED, outcome="allowed", allowed=True)
        )
        is None
    )
    assert list(trail.query(AuditWindow())) == []


@pytest.mark.unit
def test_a_trail_writes_one_record_per_decision() -> None:
    sink = InMemoryAuditSink()
    trail = AuditTrail(sink, masker=_masker())

    written = trail.record(
        build_facts(invocation=_invocation(), decision=ALLOWED, outcome="allowed", allowed=True)
    )

    assert trail.enabled is True
    assert written is not None
    assert tuple(sink.records) == (written,)
    assert written.sequence == 0
    assert written.prev_hash == GENESIS_HASH
    assert written.invocation_id == "inv-1"
    assert written.action == 'Action::"tool.search_orders"'
    assert written.decision == "allow"
    assert written.outcome == "allowed"


@pytest.mark.unit
def test_successive_records_form_a_chain() -> None:
    sink = InMemoryAuditSink()
    trail = AuditTrail(sink, masker=_masker())

    for index in range(3):
        trail.record(
            build_facts(
                invocation=_invocation(id=f"inv-{index}"),
                decision=ALLOWED,
                outcome="allowed",
                allowed=True,
            )
        )

    assert [record.sequence for record in sink.records] == [0, 1, 2]
    assert verify_chain(sink.records).ok is True


@pytest.mark.unit
def test_the_record_pins_the_policy_set_it_was_decided_against() -> None:
    sink = InMemoryAuditSink()
    trail = AuditTrail(sink, masker=_masker())

    trail.record(
        build_facts(invocation=_invocation(), decision=ALLOWED, outcome="allowed", allowed=True)
    )

    assert sink.records[0].policy_set_hash == "deadbeef"
    assert sink.records[0].determining_policies == ("support-may-search",)


@pytest.mark.unit
def test_the_record_carries_the_provenance_of_its_determining_policies() -> None:
    bundle = PolicyBundle.from_text(POLICY, source="pack", origin="pack.cedar")
    sink = InMemoryAuditSink()
    trail = AuditTrail(sink, masker=_masker(), bundle=bundle)

    trail.record(
        build_facts(invocation=_invocation(), decision=ALLOWED, outcome="allowed", allowed=True)
    )

    provenance = sink.records[0].provenance
    assert len(provenance) == 1
    assert provenance[0]["source"] == "pack"
    assert provenance[0]["policy_id"] == "support-may-search"


@pytest.mark.unit
def test_a_refusal_is_recorded_as_carefully_as_an_allow() -> None:
    sink = InMemoryAuditSink()
    trail = AuditTrail(sink, masker=_masker())
    denied = CedarDecision(allowed=False, decision="deny", determining_policies=("suspended",))

    trail.record(
        build_facts(
            invocation=_invocation(),
            decision=denied,
            outcome="denied",
            allowed=False,
            reason="Denied by an explicit forbid policy",
        )
    )

    written = sink.records[0]
    assert written.decision == "deny"
    assert written.outcome == "denied"
    assert written.reason == "Denied by an explicit forbid policy"
    assert written.determining_policies == ("suspended",)


@pytest.mark.unit
def test_the_names_a_signature_filled_reach_the_sink_while_their_values_do_not() -> None:
    """Names only, so there is nothing here for the masker to do and nothing to leak.

    The value that landed in the slot is the application's own literal rather than anything
    the caller or the policy chose, and what an auditor needs is the name: it is the only
    thing on the record that says this call ran on a value nobody selected. ``processed``
    stays what it has always been, the set sentrykit decided to pass.
    """
    sink = InMemoryAuditSink()
    trail = AuditTrail(sink, masker=_masker())

    trail.record(
        build_facts(
            invocation=_invocation(),
            decision=ALLOWED,
            outcome="allowed",
            allowed=True,
            processed={"customer_id": "c-1"},
            signature_defaults=("limit",),
        )
    )

    assert sink.records[0].signature_defaults == ("limit",)
    assert "limit" not in sink.records[0].processed


@pytest.mark.unit
def test_an_engine_failure_carries_cedars_own_errors() -> None:
    sink = InMemoryAuditSink()
    trail = AuditTrail(sink, masker=_masker())
    failed = CedarDecision(
        allowed=False, decision="deny", errors=("record does not have the attribute `clearance`",)
    )

    facts = build_facts(
        invocation=_invocation(), decision=failed, outcome="engine-error", allowed=False
    )

    trail.record(facts)

    assert facts.engine_errors == failed.errors
    assert sink.records[0].engine_errors == failed.errors


@pytest.mark.unit
def test_a_mutation_is_recorded_into_the_same_chain() -> None:
    sink = InMemoryAuditSink()
    trail = AuditTrail(sink, masker=_masker())
    actor = Principal(id="admin", roles=("admin",))

    trail.record(
        build_facts(invocation=_invocation(), decision=ALLOWED, outcome="allowed", allowed=True)
    )
    written = trail.record_mutation(
        {"id": "g-1", "kind": "role", "subject": "support"},
        actor=actor,
        outcome="granted",
        reason="onboarding",
    )

    assert written is not None
    assert written.kind == "mutation"
    assert written.outcome == "granted"
    assert written.sequence == 1
    assert written.grant is not None
    assert written.grant["id"] == "g-1"
    assert verify_chain(sink.records).ok is True


@pytest.mark.unit
def test_the_trail_reads_records_back_from_its_sink() -> None:
    sink = InMemoryAuditSink()
    trail = AuditTrail(sink, masker=_masker())
    trail.record(
        build_facts(invocation=_invocation(), decision=ALLOWED, outcome="allowed", allowed=True)
    )

    assert [record.invocation_id for record in trail.query(AuditWindow())] == ["inv-1"]


@pytest.mark.unit
def test_a_sink_that_refuses_the_write_refuses_the_call_when_strict() -> None:
    class Refusing(NullAuditSink):
        name = "refusing"

        def write(self, record: AuthzAuditRecord) -> None:
            raise AuditUnavailable("refusing", "no space left on device")

    trail = AuditTrail(Refusing(), masker=_masker(), strict=True)

    with pytest.raises(AuditUnavailable):
        trail.record(
            build_facts(invocation=_invocation(), decision=ALLOWED, outcome="allowed", allowed=True)
        )


@pytest.mark.unit
def test_a_sink_that_refuses_the_write_is_survivable_when_not_strict() -> None:
    class Refusing(NullAuditSink):
        name = "refusing"

        def write(self, record: AuthzAuditRecord) -> None:
            raise AuditUnavailable("refusing", "no space left on device")

    trail = AuditTrail(Refusing(), masker=_masker(), strict=False)

    trail.record(
        build_facts(invocation=_invocation(), decision=ALLOWED, outcome="allowed", allowed=True)
    )


@pytest.mark.unit
def test_build_facts_fills_the_engine_errors_from_the_decision() -> None:
    failed = CedarDecision(allowed=False, decision="no-decision", errors=("boom",))

    facts = build_facts(
        invocation=_invocation(),
        decision=failed,
        outcome="engine-error",
        allowed=False,
        rejected=(RejectedArgument(name="limit", rule="maximum", reason="Too large"),),
    )

    assert isinstance(facts, DecisionFacts)
    assert facts.engine_errors == ("boom",)
    assert facts.rejected[0].name == "limit"
