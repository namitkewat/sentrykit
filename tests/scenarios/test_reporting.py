"""The yearly report, over a log whose every record is known.

The compliance report is a *query*, not a second system. What makes that claim testable is
that :func:`~sentrykit.cli.build_report` is pure — an iterable in, a value out, no sink and
no clock — so a seeded log has exactly one correct aggregate and this
module asserts it item by item, ordering included.

The seed spans everything the report has to keep apart: allows, four refusals across three
different outcomes, and both admin mutations. Aggregating by ``allow``/``deny`` would collapse
the refusals into one bucket and file the two mutations under "allowed", which is precisely the
collapse the outcome vocabulary exists to prevent — so the assertions below are what stop a
future simplification from reintroducing it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from sentrykit.audit import GENESIS_HASH, AuthzAuditRecord, PrincipalSnapshot, verify_chain
from sentrykit.cli import build_report, main, render_markdown
from sentrykit.context import Principal
from sentrykit.stores.base import AuditWindow
from sentrykit.stores.memory import InMemoryAuditSink

if TYPE_CHECKING:  # pragma: no cover - annotations only; pytest supplies the fixtures
    from conftest import AuditLog

CLI_DSN = "scenario://cli"
"""The shared sink, addressed the way an operator addresses a durable one."""

GENERATED_AT = datetime(2026, 6, 4, 9, 0, tzinfo=UTC)
"""A fixed report timestamp, so the rendered document is byte-comparable."""

WINDOW = AuditWindow(
    start=datetime(2026, 6, 1, tzinfo=UTC),
    end=datetime(2026, 6, 4, tzinfo=UTC),
)
"""The whole seeded period: no identity filter, so the chain verdict is meaningful."""


def _record(
    *,
    at: datetime,
    principal: str,
    action: str,
    outcome: str,
    decision: str,
    kind: str = "decision",
    determining: tuple[str, ...] = (),
    obligations: tuple[str, ...] = (),
    reason: str | None = None,
) -> AuthzAuditRecord:
    """Build one unchained record. Keyword-only, because every field here is a fact under test."""
    return AuthzAuditRecord(
        record_id=f"{principal}-{outcome}-{at.isoformat()}",
        timestamp=at,
        invocation_id=f"inv-{at.timestamp():.0f}",
        kind=kind,  # type: ignore[arg-type]
        principal=PrincipalSnapshot.of(Principal(id=principal)),
        action=action,
        resource='Resource::"orders"',
        decision=decision,  # type: ignore[arg-type]
        outcome=outcome,  # type: ignore[arg-type]
        reason=reason,
        determining_policies=determining,
        obligations=obligations,
    )


SEED = (
    _record(
        at=datetime(2026, 6, 1, 9, 0, tzinfo=UTC),
        principal="alice",
        action='Action::"orders.search"',
        outcome="allowed",
        decision="allow",
        determining=("rbac-required-role",),
    ),
    _record(
        at=datetime(2026, 6, 1, 10, 0, tzinfo=UTC),
        principal="alice",
        action='Action::"orders.search"',
        outcome="allowed",
        decision="allow",
        determining=("rbac-required-role",),
    ),
    _record(
        at=datetime(2026, 6, 1, 11, 0, tzinfo=UTC),
        principal="ivy",
        action='Action::"vault.open"',
        outcome="allowed",
        decision="allow",
        determining=("break-the-glass",),
        obligations=("notify:secops", "record:justification"),
    ),
    _record(
        at=datetime(2026, 6, 2, 9, 0, tzinfo=UTC),
        principal="bob",
        action='Action::"orders.search"',
        outcome="denied",
        decision="deny",
        reason="No policy permits this action",
    ),
    _record(
        at=datetime(2026, 6, 2, 10, 0, tzinfo=UTC),
        principal="sam",
        action='Action::"vault.open"',
        outcome="denied",
        decision="deny",
        determining=("emergency-resource-forbidden-without-flag",),
        reason="Denied by an explicit forbid policy",
    ),
    _record(
        at=datetime(2026, 6, 2, 11, 0, tzinfo=UTC),
        principal="casey",
        action='Action::"orders.search"',
        outcome="arguments-rejected",
        decision="deny",
        reason="customer_id is not in the allowed set",
    ),
    _record(
        at=datetime(2026, 6, 3, 9, 0, tzinfo=UTC),
        principal="casey",
        action='Action::"orders.export"',
        outcome="validation-failed",
        decision="deny",
        reason="fmt is not a valid format",
    ),
    _record(
        at=datetime(2026, 6, 3, 10, 0, tzinfo=UTC),
        principal="root",
        action='Action::"grant"',
        outcome="granted",
        decision="allow",
        kind="mutation",
    ),
    # Deliberately on the last day of the window, so `--to 2026-06-03` has to include it.
    _record(
        at=datetime(2026, 6, 3, 23, 30, tzinfo=UTC),
        principal="root",
        action='Action::"revoke"',
        outcome="revoked",
        decision="allow",
        kind="mutation",
    ),
)
"""Nine records: three allows, four refusals across three outcomes, and both mutations."""


def seed(sink: InMemoryAuditSink) -> None:
    """Write :data:`SEED` into ``sink``, chained the way the audit trail chains it.

    Chained rather than written raw, because the report verifies both the per-record hash and
    the links, and a seed that skipped it would assert a broken chain forever.

    Args:
        sink: The sink to fill.
    """
    previous = GENESIS_HASH
    for sequence, record in enumerate(SEED):
        chained = record.chained(prev_hash=previous, sequence=sequence)
        sink.write(chained)
        previous = chained.record_hash


@pytest.fixture
def seeded(sink: InMemoryAuditSink) -> InMemoryAuditSink:
    """A sink holding exactly :data:`SEED`."""
    seed(sink)
    return sink


# --- the aggregate -------------------------------------------------------------------------


@pytest.mark.scenario
def test_the_report_counts_decisions_and_mutations_apart(seeded: InMemoryAuditSink) -> None:
    report = build_report(
        seeded.query(WINDOW), window=WINDOW, sink="memory", generated_at=GENERATED_AT
    )

    assert report.total == 9
    assert report.decisions == 7
    assert report.mutations == 2
    # A grant is not a permitted call; it is a change to what will be permitted next.
    assert report.allowed == 3
    assert report.denied == 4


@pytest.mark.scenario
def test_the_report_aggregates_by_outcome_not_by_decision(seeded: InMemoryAuditSink) -> None:
    report = build_report(
        seeded.query(WINDOW), window=WINDOW, sink="memory", generated_at=GENERATED_AT
    )

    # Ordering is part of the contract — descending by count, ties broken by key — so this is
    # asserted as an ordered list of pairs rather than as a dict.
    assert list(report.by_outcome.items()) == [
        ("allowed", 3),
        ("denied", 2),
        ("arguments-rejected", 1),
        ("granted", 1),
        ("revoked", 1),
        ("validation-failed", 1),
    ]


@pytest.mark.scenario
def test_the_report_ranks_actions_principals_policies_and_obligations(
    seeded: InMemoryAuditSink,
) -> None:
    report = build_report(
        seeded.query(WINDOW), window=WINDOW, sink="memory", generated_at=GENERATED_AT
    )

    assert list(report.by_action.items()) == [
        ('Action::"orders.search"', 4),
        ('Action::"vault.open"', 2),
        ('Action::"grant"', 1),
        ('Action::"orders.export"', 1),
        ('Action::"revoke"', 1),
    ]
    assert list(report.by_principal.items()) == [
        ('User::"alice"', 2),
        ('User::"casey"', 2),
        ('User::"root"', 2),
        ('User::"bob"', 1),
        ('User::"ivy"', 1),
        ('User::"sam"', 1),
    ]
    assert list(report.by_policy.items()) == [
        ("rbac-required-role", 2),
        ("break-the-glass", 1),
        ("emergency-resource-forbidden-without-flag", 1),
    ]
    assert list(report.by_obligation.items()) == [
        ("notify:secops", 1),
        ("record:justification", 1),
    ]


@pytest.mark.scenario
def test_the_report_lists_refusals_newest_first_and_verifies_the_chain(
    seeded: InMemoryAuditSink,
) -> None:
    report = build_report(
        seeded.query(WINDOW), window=WINDOW, sink="memory", generated_at=GENERATED_AT
    )

    assert [record.outcome for record in report.refusals] == [
        "validation-failed",
        "arguments-rejected",
        "denied",
        "denied",
    ]
    assert report.chain == verify_chain(seeded.query(WINDOW))
    assert report.chain is not None
    assert report.chain.ok is True
    assert report.verified == 9


@pytest.mark.scenario
def test_a_window_filtered_by_identity_reports_no_chain_verdict(
    seeded: InMemoryAuditSink,
) -> None:
    narrowed = WINDOW.model_copy(update={"principal": 'User::"casey"'})

    report = build_report(seeded.query(narrowed), window=narrowed, sink="memory")

    assert report.total == 2
    # Not "the chain is broken" — the records are a slice of the log, not a run of it, and a
    # tamper-evidence line that cries wolf is worse than none.
    assert report.chain is None
    assert report.verified == 2


@pytest.mark.scenario
def test_top_caps_the_refusal_list_without_changing_the_counts(
    seeded: InMemoryAuditSink,
) -> None:
    report = build_report(
        seeded.query(WINDOW), window=WINDOW, sink="memory", generated_at=GENERATED_AT, top=2
    )

    assert report.denied == 4
    assert len(report.refusals) == 2


# --- the document --------------------------------------------------------------------------


@pytest.mark.scenario
def test_the_markdown_carries_the_specific_rows_an_auditor_reads(
    seeded: InMemoryAuditSink,
) -> None:
    report = build_report(
        seeded.query(WINDOW), window=WINDOW, sink="memory", generated_at=GENERATED_AT
    )

    document = render_markdown(report)

    assert document.endswith("\n")
    for row in (
        "# Audit report: 2026-06-01 to 2026-06-04",
        "| Records | 9 |",
        "| Decisions | 7 |",
        "| Mutations | 2 |",
        "| Allowed | 3 |",
        "| Denied | 4 |",
        "| allowed | 3 |",
        "| arguments-rejected | 1 |",
        "| validation-failed | 1 |",
        "| granted | 1 |",
        "| revoked | 1 |",
        "| rbac-required-role | 2 |",
        "| notify:secops | 1 |",
        "| record:justification | 1 |",
        "- Records whose own hash recomputes: 9 of 9.",
        "- Chain: intact across the window.",
    ):
        assert row in document, f"missing row: {row}"


@pytest.mark.scenario
def test_the_mutations_have_their_own_section(seeded: InMemoryAuditSink) -> None:
    report = build_report(
        seeded.query(WINDOW), window=WINDOW, sink="memory", generated_at=GENERATED_AT
    )

    document = render_markdown(report)
    mutations = document.split("## Mutations", 1)[1].split("##", 1)[0]

    assert "| granted | 1 |" in mutations
    assert "| revoked | 1 |" in mutations


# --- the command ---------------------------------------------------------------------------


@pytest.mark.scenario
def test_the_to_date_includes_the_day_it_names(shared_log: AuditLog, tmp_path: Path) -> None:
    seed(shared_log.sink)
    out = tmp_path / "report.md"

    code = main(
        [
            "audit-report",
            "--from",
            "2026-06-01",
            "--to",
            "2026-06-03",
            "--sink",
            CLI_DSN,
            "--out",
            str(out),
        ]
    )

    # The window's upper bound is exclusive, so a bare `--to` has to be nudged to the next day
    # or the last day's records — including the 23:30 revocation — silently vanish.
    assert code == 0
    document = out.read_text(encoding="utf-8")
    assert "| Records | 9 |" in document
    assert "| revoked | 1 |" in document


@pytest.mark.scenario
def test_a_to_date_before_the_last_day_excludes_it(shared_log: AuditLog, tmp_path: Path) -> None:
    seed(shared_log.sink)
    out = tmp_path / "report.md"

    code = main(
        [
            "audit-report",
            "--from",
            "2026-06-01",
            "--to",
            "2026-06-02",
            "--sink",
            CLI_DSN,
            "--out",
            str(out),
        ]
    )

    assert code == 0
    document = out.read_text(encoding="utf-8")
    # The two 2026-06-03 records are outside the window; the six from the first two days remain.
    assert "| Records | 6 |" in document
    assert "No grants were made or withdrawn in this window." in document
