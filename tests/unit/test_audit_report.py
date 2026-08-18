"""The audit report: the aggregate, the document, and the window that produces both.

ADR-006's claim is that "the yearly report is a query, not a feature". These tests hold that
claim to three specifics:

* **It aggregates by outcome, not by decision.** ``allow``/``deny`` collapses six materially
  different refusals and both admin mutations into two buckets. So the aggregates are
  asserted as whole dicts rather than by length — a mutation counted as an "allow" is exactly
  the regression that would still pass a length check.
* **The window's upper bound is inclusive of the day an operator names.**
  :class:`~sentrykit.stores.base.AuditWindow` is half-open, so ``--to 2026-12-31`` has to
  become ``end=2027-01-01`` or the last day silently vanishes from every report. A record is
  seeded *on* the last day and asserted to be counted.
* **Tamper evidence says what it can and no more.** The per-record hash check is always
  meaningful. The chain check is only meaningful over a contiguous run, so a window filtering
  by principal reports no verdict at all rather than an intact chain it never verified.

:func:`~sentrykit.cli.build_report` is pure — no sink, no clock — which is what lets these
tests assert an exact report over a hand-built log instead of a plausible one.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from sentrykit.audit import AuthzAuditRecord, PrincipalSnapshot
from sentrykit.cli import EXIT_FAILED, EXIT_OK, build_report, main, render_markdown
from sentrykit.stores.base import AuditWindow
from sentrykit.stores.jsonl import JsonlAuditSink

if TYPE_CHECKING:  # pragma: no cover - imported for annotations only
    from collections.abc import Callable, Sequence

pytestmark = pytest.mark.unit

JANUARY = AuditWindow(start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2026, 2, 1, tzinfo=UTC))
"""The window every aggregate test answers, so the header rows are predictable."""

GENERATED = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
"""A fixed report timestamp, passed in rather than read off a clock."""

SEARCH = 'Action::"tool.search_orders"'
EXPORT = 'Action::"tool.export_orders"'
GRANT = 'Action::"grant"'

MALLORY = PrincipalSnapshot(uid='User::"mallory"', type="User", id="mallory", roles=("guest",))
ROOT = PrincipalSnapshot(uid='User::"root"', type="User", id="root")


@pytest.fixture
def seeded(
    make_record: Callable[..., AuthzAuditRecord],
    chained: Callable[[Sequence[AuthzAuditRecord]], tuple[AuthzAuditRecord, ...]],
) -> tuple[AuthzAuditRecord, ...]:
    """Four records: two allows, one denial carrying an obligation, and one grant mutation."""
    return chained(
        [
            make_record(timestamp=datetime(2026, 1, 2, tzinfo=UTC), determining_policies=("p1",)),
            make_record(timestamp=datetime(2026, 1, 3, tzinfo=UTC), determining_policies=("p1",)),
            make_record(
                timestamp=datetime(2026, 1, 4, tzinfo=UTC),
                principal=MALLORY,
                action=EXPORT,
                decision="deny",
                outcome="denied",
                reason="No policy permits this",
                determining_policies=("p2",),
                obligations=("notify:secops",),
            ),
            make_record(
                timestamp=datetime(2026, 1, 5, tzinfo=UTC),
                principal=ROOT,
                action=GRANT,
                kind="mutation",
                outcome="granted",
                reason="shift",
                grant={"id": "g-1", "principal": 'User::"ana"', "subject": "oncall"},
            ),
        ]
    )


# --- the aggregate -----------------------------------------------------------------------


def test_the_totals_separate_decisions_from_mutations(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    report = build_report(seeded, window=JANUARY, sink="memory", generated_at=GENERATED)

    assert (report.total, report.decisions, report.mutations) == (4, 3, 1)
    assert (report.allowed, report.denied) == (2, 1)


def test_a_mutation_is_counted_as_a_mutation_and_never_as_an_allow(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    """The collapse ADR-006 exists to prevent, asserted directly."""
    report = build_report(seeded, window=JANUARY)

    assert report.by_outcome == {"allowed": 2, "denied": 1, "granted": 1}
    assert report.allowed == 2
    assert report.decisions + report.mutations == report.total


def test_the_aggregates_are_exact_and_ordered_by_descending_count(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    report = build_report(seeded, window=JANUARY)

    assert report.by_action == {SEARCH: 2, GRANT: 1, EXPORT: 1}
    assert report.by_principal == {'User::"alice"': 2, 'User::"mallory"': 1, 'User::"root"': 1}
    assert report.by_policy == {"p1": 2, "p2": 1}
    assert report.by_obligation == {"notify:secops": 1}


def test_ties_break_on_the_key_so_two_runs_produce_the_same_report(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    """A report a test cannot assert exactly is one nobody can diff between two periods."""
    first = build_report(seeded, window=JANUARY)
    second = build_report(reversed(seeded), window=JANUARY)

    assert list(first.by_action) == list(second.by_action)
    assert list(first.by_principal) == list(second.by_principal)


def test_refusals_come_back_newest_first(seeded: tuple[AuthzAuditRecord, ...]) -> None:
    report = build_report(seeded, window=JANUARY)

    assert [record.outcome for record in report.refusals] == ["denied"]
    assert report.refusals[0].principal.uid == 'User::"mallory"'


def test_refusals_are_capped_by_top(
    make_record: Callable[..., AuthzAuditRecord],
    chained: Callable[[Sequence[AuthzAuditRecord]], tuple[AuthzAuditRecord, ...]],
) -> None:
    records = chained(
        [
            make_record(
                timestamp=datetime(2026, 1, day, tzinfo=UTC), decision="deny", outcome="denied"
            )
            for day in range(1, 6)
        ]
    )

    report = build_report(records, window=JANUARY, top=2)

    assert report.denied == 5
    assert len(report.refusals) == 2
    # Newest first: days 5 and 4, in that order.
    assert [record.timestamp.day for record in report.refusals] == [5, 4]


def test_build_report_reads_no_clock_and_no_sink(seeded: tuple[AuthzAuditRecord, ...]) -> None:
    report = build_report(seeded, window=JANUARY, sink="memory", generated_at=GENERATED)

    assert report.generated_at == GENERATED
    assert report.sink == "memory"
    assert report.window is JANUARY


def test_an_empty_window_aggregates_to_nothing_rather_than_failing() -> None:
    report = build_report([], window=JANUARY)

    assert (report.total, report.by_outcome, report.refusals) == (0, {}, ())
    assert report.chain is not None
    assert report.chain.ok


# --- tamper evidence ---------------------------------------------------------------------


def test_every_intact_record_is_counted_as_verified(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    report = build_report(seeded, window=JANUARY)

    assert report.verified == 4
    assert report.chain is not None
    assert report.chain.ok


def test_an_edited_record_fails_both_its_own_hash_and_the_chain(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    tampered = (
        *seeded[:2],
        seeded[2].model_copy(update={"reason": "nothing to see here"}),
        seeded[3],
    )

    report = build_report(tampered, window=JANUARY)

    assert report.verified == 3
    assert report.chain is not None
    assert not report.chain.ok
    assert report.chain.broken_at == 2


def test_a_window_filtered_by_identity_reports_no_chain_verdict(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    """A ``broken_at`` over a filtered slice would mean "you filtered", not "somebody tampered"."""
    filtered = JANUARY.model_copy(update={"principal": 'User::"alice"'})

    report = build_report(seeded[:2], window=filtered)

    assert report.chain is None
    # The per-record check is still meaningful, filtered or not.
    assert report.verified == 2


@pytest.mark.parametrize(
    "narrowing",
    [
        {"principal": 'User::"alice"'},
        {"action": SEARCH},
        {"resource": 'Tool::"orders"'},
        {"decision": "allow"},
        {"kind": "decision"},
    ],
)
def test_every_identity_filter_suppresses_the_chain_verdict(
    seeded: tuple[AuthzAuditRecord, ...], narrowing: dict[str, Any]
) -> None:
    report = build_report(seeded, window=JANUARY.model_copy(update=narrowing))

    assert report.chain is None


def test_time_bounds_alone_leave_the_run_contiguous(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    report = build_report(seeded, window=JANUARY)

    assert report.chain is not None


# --- the document ------------------------------------------------------------------------


def test_the_summary_table_holds_the_exact_rows(seeded: tuple[AuthzAuditRecord, ...]) -> None:
    document = render_markdown(
        build_report(seeded, window=JANUARY, sink="memory", generated_at=GENERATED)
    )

    assert "# Audit report: 2026-01-01 to 2026-02-01" in document
    assert "| Records | 4 |" in document
    assert "| Decisions | 3 |" in document
    assert "| Mutations | 1 |" in document
    assert "| Allowed | 2 |" in document
    assert "| Denied | 1 |" in document


def test_the_header_names_the_window_the_sink_and_the_filters(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    document = render_markdown(
        build_report(seeded, window=JANUARY, sink="memory", generated_at=GENERATED)
    )

    assert (
        "- Window: 2026-01-01T00:00:00+00:00 to 2026-02-01T00:00:00+00:00 (end exclusive)"
        in document
    )
    assert "- Sink: memory" in document
    assert "- Generated: 2026-08-18T12:00:00+00:00" in document
    assert "- Filters: none" in document


def test_the_aggregate_tables_hold_the_exact_rows(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    document = render_markdown(build_report(seeded, window=JANUARY))

    assert "| allowed | 2 |" in document
    assert "| denied | 1 |" in document
    assert f"| {SEARCH} | 2 |" in document
    assert '| User::"alice" | 2 |' in document
    assert "| p1 | 2 |" in document
    assert "| notify:secops | 1 |" in document


def test_mutations_get_their_own_section(seeded: tuple[AuthzAuditRecord, ...]) -> None:
    document = render_markdown(build_report(seeded, window=JANUARY))
    section = document.split("## Mutations", 1)[1].split("##", 1)[0]

    assert "| Mutation | Count |" in section
    assert "| granted | 1 |" in section


def test_the_refusal_row_names_who_was_refused_and_why(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    document = render_markdown(build_report(seeded, window=JANUARY))

    assert (
        '| 2026-01-04T00:00:00+00:00 | User::"mallory" | Action::"tool.export_orders" | '
        "denied | No policy permits this |"
    ) in document


def test_a_capped_refusal_list_says_how_many_it_left_out(
    make_record: Callable[..., AuthzAuditRecord],
    chained: Callable[[Sequence[AuthzAuditRecord]], tuple[AuthzAuditRecord, ...]],
) -> None:
    records = chained(
        [
            make_record(
                timestamp=datetime(2026, 1, day, tzinfo=UTC), decision="deny", outcome="denied"
            )
            for day in range(1, 6)
        ]
    )

    document = render_markdown(build_report(records, window=JANUARY, top=2))

    assert "Showing the 2 most recent of 5 refusals." in document


def test_the_tamper_evidence_line_reports_an_intact_chain(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    document = render_markdown(build_report(seeded, window=JANUARY))

    assert "- Records whose own hash recomputes: 4 of 4." in document
    assert "- Chain: intact across the window." in document


def test_the_tamper_evidence_line_says_why_a_filtered_window_has_no_verdict(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    filtered = JANUARY.model_copy(update={"principal": 'User::"alice"'})

    document = render_markdown(build_report(seeded[:2], window=filtered))

    assert "- Chain: not verified." in document
    assert "non-contiguous slice" in document


def test_a_broken_chain_is_reported_loudly(seeded: tuple[AuthzAuditRecord, ...]) -> None:
    tampered = (*seeded[:2], seeded[2].model_copy(update={"reason": "edited"}), seeded[3])

    document = render_markdown(build_report(tampered, window=JANUARY))

    assert "- Chain: BROKEN at record 2." in document


def test_an_empty_window_still_renders_every_section() -> None:
    document = render_markdown(build_report([], window=JANUARY))

    assert "None recorded in this window." in document
    assert "No grants were made or withdrawn in this window." in document
    assert "No call was refused in this window." in document


def test_an_unbounded_window_gets_a_title_that_does_not_pretend_to_name_a_period() -> None:
    document = render_markdown(build_report([], window=AuditWindow()))

    assert document.startswith("# Audit report\n")
    assert "- Window: unbounded to unbounded (end exclusive)" in document


def test_the_document_ends_in_exactly_one_newline(
    seeded: tuple[AuthzAuditRecord, ...],
) -> None:
    document = render_markdown(build_report(seeded, window=JANUARY))

    assert document.endswith("\n")
    assert not document.endswith("\n\n")


# --- the command -------------------------------------------------------------------------


@pytest.fixture
def audit_log(
    tmp_path: Path,
    make_record: Callable[..., AuthzAuditRecord],
    chained: Callable[[Sequence[AuthzAuditRecord]], tuple[AuthzAuditRecord, ...]],
) -> Path:
    """A jsonl log holding one record per day from 29 to 31 December 2026."""
    path = tmp_path / "audit.jsonl"
    records = chained(
        [make_record(timestamp=datetime(2026, 12, day, 9, 0, tzinfo=UTC)) for day in (29, 30, 31)]
    )
    with JsonlAuditSink(path) as opened:
        for record in records:
            opened.write(record)
    return path


def report_argv(log: Path, *rest: str) -> list[str]:
    """Build an ``audit-report`` invocation over ``log``."""
    return [
        "audit-report",
        "--from",
        "2026-12-01",
        "--to",
        "2026-12-31",
        "--sink",
        f"jsonl://{log}",
        *rest,
    ]


def test_a_bare_to_date_includes_that_whole_day(
    audit_log: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Half-open bounds mean a naive ``--to`` would silently drop the last day's records."""
    code = main(report_argv(audit_log))

    document = capsys.readouterr().out
    assert code == EXIT_OK
    assert "| Records | 3 |" in document
    # The heading echoes what was typed; the header line states the bound that was actually
    # queried, marked exclusive. Both, because reading either one alone is how a reader ends
    # up unsure whether the last day was counted.
    assert "# Audit report: 2026-12-01 to 2026-12-31" in document
    assert "to 2027-01-01T00:00:00+00:00 (end exclusive)" in document


def test_a_to_carrying_a_time_is_used_exactly(
    audit_log: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        [
            "audit-report",
            "--from",
            "2026-12-01",
            "--to",
            "2026-12-31T00:00:00+00:00",
            "--sink",
            f"jsonl://{audit_log}",
        ]
    )

    document = capsys.readouterr().out
    assert code == EXIT_OK
    assert "| Records | 2 |" in document


def test_out_writes_the_document_and_creates_missing_parents(
    audit_log: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    destination = tmp_path / "reports" / "2026" / "audit.md"

    code = main(report_argv(audit_log, "--out", str(destination)))

    assert code == EXIT_OK
    assert destination.is_file()
    assert destination.read_text(encoding="utf-8").startswith("# Audit report: ")
    assert f"Wrote 3 record(s) to {destination}." in capsys.readouterr().out


def test_the_title_can_be_overridden(audit_log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(report_argv(audit_log, "--title", "Q4 access review"))

    document = capsys.readouterr().out
    assert code == EXIT_OK
    assert document.startswith("# Q4 access review\n")


def test_an_unfiltered_window_reports_the_chain_verdict(
    audit_log: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(report_argv(audit_log))

    assert "- Chain: intact across the window." in capsys.readouterr().out


def test_a_principal_filtered_window_reports_no_chain_verdict(
    audit_log: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(report_argv(audit_log, "--principal", 'User::"alice"'))

    document = capsys.readouterr().out
    assert '- Filters: principal=User::"alice"' in document
    assert "- Chain: not verified." in document


def test_filtering_by_a_principal_with_no_records_reports_an_empty_window(
    audit_log: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(report_argv(audit_log, "--principal", 'User::"nobody"'))

    assert "| Records | 0 |" in capsys.readouterr().out


def test_no_configured_sink_names_the_environment_variable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["audit-report", "--from", "2026-01-01", "--to", "2026-12-31"])

    assert code == EXIT_FAILED
    assert "SENTRYKIT_AUDIT_SINK" in capsys.readouterr().err


def test_the_sink_falls_back_to_the_configured_one(
    audit_log: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SENTRYKIT_AUDIT_SINK", f"jsonl://{audit_log}")

    code = main(["audit-report", "--from", "2026-12-01", "--to", "2026-12-31"])

    assert code == EXIT_OK
    assert "| Records | 3 |" in capsys.readouterr().out


def test_an_unparseable_bound_is_a_message_not_a_traceback(
    audit_log: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        [
            "audit-report",
            "--from",
            "last tuesday",
            "--to",
            "2026-12-31",
            "--sink",
            f"jsonl://{audit_log}",
        ]
    )

    assert code == EXIT_FAILED
    assert "--from is 'last tuesday'" in capsys.readouterr().err


def test_a_naive_bound_is_read_as_utc(
    tmp_path: Path,
    make_record: Callable[..., AuthzAuditRecord],
    chained: Callable[[Sequence[AuthzAuditRecord]], tuple[AuthzAuditRecord, ...]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Which records a report covers must not depend on the timezone of the host running it."""
    path = tmp_path / "naive.jsonl"
    boundary = datetime(2026, 6, 1, 0, 0, tzinfo=UTC)
    with JsonlAuditSink(path) as opened:
        for record in chained([make_record(timestamp=boundary)]):
            opened.write(record)

    code = main(
        [
            "audit-report",
            "--from",
            "2026-06-01T00:00:00",
            "--to",
            "2026-06-01T00:00:01",
            "--sink",
            f"jsonl://{path}",
        ]
    )

    assert code == EXIT_OK
    assert "| Records | 1 |" in capsys.readouterr().out


def test_the_report_survives_a_pipe_in_a_value(
    make_record: Callable[..., AuthzAuditRecord],
    chained: Callable[[Sequence[AuthzAuditRecord]], tuple[AuthzAuditRecord, ...]],
) -> None:
    """Markdown table cells are pipe-delimited; a value carrying one must not split the row."""
    records = chained(
        [make_record(decision="deny", outcome="denied", reason="rejected a|b as a value")]
    )

    document = render_markdown(build_report(records, window=JANUARY))

    assert "rejected a\\|b as a value" in document


def test_the_written_document_is_the_one_that_would_have_been_printed(
    audit_log: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(report_argv(audit_log, "--title", "Fixed"))
    printed = capsys.readouterr().out
    destination = tmp_path / "out" / "audit.md"

    main(report_argv(audit_log, "--title", "Fixed", "--out", str(destination)))

    written = destination.read_text(encoding="utf-8")
    # The generated-at line is the only thing that moves between two runs.
    assert _without_generated(written) == _without_generated(printed)


def _without_generated(document: str) -> str:
    """Drop the report timestamp, the one line that legitimately differs between two runs."""
    return "\n".join(line for line in document.splitlines() if not line.startswith("- Generated:"))


def test_the_json_shape_of_a_grant_is_not_what_this_module_asserts() -> None:
    """A guard against drift: the report reads records, and records render through pydantic."""
    record = AuthzAuditRecord(
        record_id="r",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        invocation_id="i",
        principal=ROOT,
        decision="allow",
        outcome="granted",
        kind="mutation",
        grant={"id": "g-1"},
    )

    assert json.loads(record.model_dump_json())["grant"] == {"id": "g-1"}
    assert build_report([record], window=JANUARY).mutations == 1


def test_the_window_carries_onto_the_report_unchanged() -> None:
    window = AuditWindow(
        start=datetime(2026, 1, 1, tzinfo=UTC),
        end=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=1),
        action=SEARCH,
    )

    report = build_report([], window=window)

    assert report.window == window
