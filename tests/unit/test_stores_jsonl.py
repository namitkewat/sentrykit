"""The append-only JSONL sink: byte-exact lines, a resumable chain, and tamper detection.

The line-ending test is the load-bearing one and it asserts on **raw bytes** deliberately.
This repo is developed on Windows, where ``open(path, "a", encoding="utf-8")`` writes
``\\r\\n``; a hash chain is computed over bytes, so left at the default the same record would
hash differently on Windows and Linux and an external verifier would disagree with the writer.
Asserting on ``read_text`` would not catch that, because Python's universal newlines would
translate the corruption away before the assertion saw it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentrykit.audit import GENESIS_HASH, AuditTrail, AuthzAuditRecord
from sentrykit.context import Principal
from sentrykit.errors import AuditUnavailable, ConfigurationError
from sentrykit.registry import parse_dsn
from sentrykit.stores.base import AuditSink, AuditWindow
from sentrykit.stores.jsonl import JsonlAuditSink

RecordFactory = Callable[..., AuthzAuditRecord]
ChainBuilder = Callable[[Sequence[AuthzAuditRecord]], "tuple[AuthzAuditRecord, ...]"]

MONDAY = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
TUESDAY = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
FRIDAY = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)

ADMIN = Principal(id="admin", roles=("admin",))


def _log(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


def _write_all(sink: JsonlAuditSink, records: Sequence[AuthzAuditRecord]) -> None:
    for record in records:
        sink.write(record)


# --- the bytes on disk ---------------------------------------------------------------------


@pytest.mark.unit
def test_the_log_is_written_with_newline_line_endings_on_every_platform(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    path = _log(tmp_path)
    with JsonlAuditSink(path) as sink:
        _write_all(sink, chained([make_record(), make_record(), make_record()]))

    raw = path.read_bytes()

    assert b"\r" not in raw
    assert raw.endswith(b"\n")
    assert raw.count(b"\n") == 3


@pytest.mark.unit
def test_every_line_is_one_json_object(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    path = _log(tmp_path)
    with JsonlAuditSink(path) as sink:
        _write_all(sink, chained([make_record(), make_record()]))

    lines = path.read_bytes().decode("utf-8").splitlines()

    assert len(lines) == 2
    assert [json.loads(line)["sequence"] for line in lines] == [0, 1]


@pytest.mark.unit
def test_the_sink_satisfies_the_audit_sink_contract(tmp_path: Path) -> None:
    with JsonlAuditSink(_log(tmp_path)) as sink:
        assert isinstance(sink, AuditSink)
        assert sink.name == "jsonl"
        assert sink.path == _log(tmp_path)


@pytest.mark.unit
def test_closing_twice_is_harmless(tmp_path: Path) -> None:
    sink = JsonlAuditSink(_log(tmp_path))

    sink.close()
    sink.close()


# --- reading back --------------------------------------------------------------------------


@pytest.mark.unit
def test_records_round_trip_through_query(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    written = chained([make_record(reason="first"), make_record(reason="second")])
    with JsonlAuditSink(_log(tmp_path)) as sink:
        _write_all(sink, written)
        read_back = tuple(sink.query(AuditWindow()))

    assert read_back == written


@pytest.mark.unit
def test_an_empty_log_reads_back_as_nothing(tmp_path: Path) -> None:
    with JsonlAuditSink(_log(tmp_path)) as sink:
        assert list(sink.query(AuditWindow())) == []


@pytest.mark.unit
def test_the_window_narrows_by_time_range(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    with JsonlAuditSink(_log(tmp_path)) as sink:
        _write_all(
            sink,
            chained(
                [
                    make_record(timestamp=MONDAY, reason="monday"),
                    make_record(timestamp=TUESDAY, reason="tuesday"),
                    make_record(timestamp=FRIDAY, reason="friday"),
                ]
            ),
        )

        found = list(sink.query(AuditWindow(start=TUESDAY, end=FRIDAY)))

    assert [record.reason for record in found] == ["tuesday"]


@pytest.mark.unit
def test_the_window_narrows_by_principal_and_decision(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    with JsonlAuditSink(_log(tmp_path)) as sink:
        _write_all(
            sink,
            chained(
                [
                    make_record(reason="allowed"),
                    make_record(decision="deny", outcome="denied", reason="refused"),
                ]
            ),
        )

        denials = list(sink.query(AuditWindow(decision="deny")))
        mine = list(sink.query(AuditWindow(principal='User::"alice"')))
        theirs = list(sink.query(AuditWindow(principal='User::"mallory"')))

    assert [record.reason for record in denials] == ["refused"]
    assert len(mine) == 2
    assert theirs == []


@pytest.mark.unit
def test_the_window_stops_at_its_limit(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    with JsonlAuditSink(_log(tmp_path)) as sink:
        _write_all(sink, chained([make_record() for _ in range(5)]))

        found = list(sink.query(AuditWindow(limit=2)))

    assert [record.sequence for record in found] == [0, 1]


# --- the chain across a reopen -------------------------------------------------------------


@pytest.mark.unit
def test_the_tail_of_an_empty_log_is_the_genesis_hash(tmp_path: Path) -> None:
    with JsonlAuditSink(_log(tmp_path)) as sink:
        assert sink.tail_hash() == GENESIS_HASH


@pytest.mark.unit
def test_the_tail_hash_survives_a_close_and_reopen(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    path = _log(tmp_path)
    written = chained([make_record(), make_record()])
    with JsonlAuditSink(path) as sink:
        _write_all(sink, written)
        while_open = sink.tail_hash()

    with JsonlAuditSink(path) as reopened:
        assert reopened.tail_hash() == while_open
        assert reopened.tail_hash() == written[-1].record_hash


@pytest.mark.unit
def test_a_trail_reopened_over_an_existing_log_continues_its_chain(tmp_path: Path) -> None:
    """A restarted process must append, not start a second chain in the same file."""
    path = _log(tmp_path)
    with JsonlAuditSink(path) as sink:
        trail = AuditTrail(sink)
        trail.record_mutation({"id": "g-1"}, actor=ADMIN, outcome="granted")
        trail.record_mutation({"id": "g-2"}, actor=ADMIN, outcome="granted")

    with JsonlAuditSink(path) as reopened:
        resumed = AuditTrail(reopened)
        resumed.record_mutation({"id": "g-3"}, actor=ADMIN, outcome="granted")

    with JsonlAuditSink(path) as verifier:
        verdict = verifier.verify()
        sequences = [record.sequence for record in verifier.query(AuditWindow())]

    assert verdict.ok, verdict.reason
    assert sequences == [0, 1, 2]


# --- tamper detection ----------------------------------------------------------------------


@pytest.mark.unit
def test_an_untouched_log_verifies(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    with JsonlAuditSink(_log(tmp_path)) as sink:
        _write_all(sink, chained([make_record() for _ in range(4)]))

        verdict = sink.verify()

    assert verdict.ok
    assert verdict.broken_at is None


@pytest.mark.unit
def test_editing_a_line_on_disk_is_reported_at_that_records_sequence(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    path = _log(tmp_path)
    with JsonlAuditSink(path) as sink:
        _write_all(sink, chained([make_record() for _ in range(4)]))

    lines = path.read_bytes().decode("utf-8").splitlines()
    edited = json.loads(lines[2])
    edited["reason"] = "somebody rewrote this after the fact"
    lines[2] = json.dumps(edited)
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))

    with JsonlAuditSink(path) as reopened:
        verdict = reopened.verify()

    assert verdict.ok is False
    assert verdict.broken_at == 2


@pytest.mark.unit
def test_deleting_a_line_from_the_middle_is_reported_at_the_orphaned_record(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    path = _log(tmp_path)
    with JsonlAuditSink(path) as sink:
        _write_all(sink, chained([make_record() for _ in range(4)]))

    lines = path.read_bytes().decode("utf-8").splitlines()
    del lines[1]
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))

    with JsonlAuditSink(path) as reopened:
        verdict = reopened.verify()

    assert verdict.ok is False
    assert verdict.broken_at == 2


# --- construction --------------------------------------------------------------------------


@pytest.mark.unit
def test_from_dsn_builds_the_sink_the_registry_would(tmp_path: Path) -> None:
    dsn = parse_dsn(f"jsonl://{_log(tmp_path).as_posix()}?fsync=true")

    sink = JsonlAuditSink.from_dsn(dsn)

    assert isinstance(sink, JsonlAuditSink)
    assert sink.name == "jsonl"
    sink.close()


@pytest.mark.unit
def test_a_dsn_with_a_mistyped_fsync_flag_is_refused(tmp_path: Path) -> None:
    dsn = parse_dsn(f"jsonl://{_log(tmp_path).as_posix()}?fsync=ture")

    with pytest.raises(ConfigurationError):
        JsonlAuditSink.from_dsn(dsn)


@pytest.mark.unit
def test_a_dsn_that_names_no_file_is_refused() -> None:
    with pytest.raises(ConfigurationError):
        JsonlAuditSink.from_dsn(parse_dsn("jsonl://"))


@pytest.mark.unit
def test_the_sink_creates_the_directory_it_was_pointed_at(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    nested = tmp_path / "logs" / "2026" / "audit.jsonl"

    with JsonlAuditSink(nested) as sink:
        _write_all(sink, chained([make_record()]))

    assert nested.is_file()


@pytest.mark.unit
def test_writing_to_a_closed_sink_is_an_audit_failure(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    sink = JsonlAuditSink(_log(tmp_path))
    sink.close()

    with pytest.raises(AuditUnavailable):
        sink.write(chained([make_record()])[0])


@pytest.mark.unit
def test_the_tail_sequence_tracks_the_last_record_written(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    with JsonlAuditSink(_log(tmp_path)) as sink:
        assert sink.tail_sequence() == -1
        _write_all(sink, chained([make_record(), make_record(), make_record()]))

        assert sink.tail_sequence() == 2


@pytest.mark.unit
def test_reopening_a_log_whose_last_line_is_unreadable_is_refused(tmp_path: Path) -> None:
    """A sink that could not recover ``prev_hash`` must not quietly start a second chain."""
    path = _log(tmp_path)
    path.write_bytes(b'{"not": "an audit record"}\n')

    with pytest.raises(ConfigurationError) as raised:
        JsonlAuditSink(path)

    assert "audit.jsonl" in str(raised.value)


@pytest.mark.unit
def test_verification_reports_a_line_it_cannot_read_at_all(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    path = _log(tmp_path)
    with JsonlAuditSink(path) as sink:
        _write_all(sink, chained([make_record() for _ in range(3)]))

    lines = path.read_bytes().decode("utf-8").splitlines()
    lines[1] = "{ this is not json"
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))

    with JsonlAuditSink(path) as reopened:
        verdict = reopened.verify()

    assert verdict.ok is False
    assert verdict.broken_at == 1
    assert verdict.reason is not None


@pytest.mark.unit
def test_querying_a_log_with_an_unreadable_line_is_an_audit_failure(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    path = _log(tmp_path)
    with JsonlAuditSink(path) as sink:
        _write_all(sink, chained([make_record() for _ in range(3)]))

    lines = path.read_bytes().decode("utf-8").splitlines()
    lines[1] = "{ this is not json"
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))

    with JsonlAuditSink(path) as reopened, pytest.raises(AuditUnavailable):
        list(reopened.query(AuditWindow()))


@pytest.mark.unit
def test_fsyncing_every_record_still_produces_the_same_bytes(
    tmp_path: Path,
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    records = chained([make_record(), make_record()])
    lazy, eager = tmp_path / "lazy.jsonl", tmp_path / "eager.jsonl"

    with JsonlAuditSink(lazy) as sink:
        _write_all(sink, records)
    with JsonlAuditSink(eager, fsync=True) as sink:
        _write_all(sink, records)

    assert lazy.read_bytes() == eager.read_bytes()
