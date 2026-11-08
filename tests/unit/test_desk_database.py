"""The example apps' seeded desk: the properties the printed tables depend on.

Three of these tests guard something a plausible refactor would quietly break.

The **threading** test is the one to leave alone. SQLite gives every connection to
``:memory:`` its own empty database and SQLAlchemy's default pool for a memory URL hands a
different connection to each thread, so dropping ``StaticPool`` or ``check_same_thread`` leaves
a desk that seeds correctly and then serves an empty table to a web server's request thread.
Nothing in a single-threaded test run notices. The test asserts the *behaviour* -- another
thread counts the same orders -- rather than the pool class, because what matters is that the
threads agree, not how.

The **determinism** test compares two independently seeded databases table by table, ids
included. The example apps print real query results, so a run that produced different rows
would invalidate every order id quoted in their output.

The **join** test cross-checks a total computed by SQL across four tables against the same
total computed in Python from the line items, so an order's money has to come out the same way
twice. An order carries no stored total to compare against on purpose: that is the column whose
absence makes the join necessary.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from examples.desk import (
    DB_URL_ENV,
    IN_MEMORY_URL,
    Base,
    Order,
    Refund,
    UnknownOrder,
    approve_refund,
    close_desk,
    desk_counts,
    engine,
    ensure_desk,
    export_job,
    find_orders,
    order_brief,
    order_detail,
    order_summary,
    record_refund,
    reset_desk,
    seed_desk,
    session_scope,
    start_export,
    ticket_thread,
)
from examples.desk.seed import ORDER_COUNT, PENDING_REFUND_COUNT, REGIONS
from sqlalchemy import Engine, create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

QUOTED_ORDER = "ord-0007"
"""An order id the example apps name in their own flow tables, so it has to exist."""

Snapshot = dict[str, list[tuple[object, ...]]]


def _int(result: Mapping[str, object], key: str) -> int:
    """Read a key the query surface promises is a whole number.

    The surface returns ``dict[str, object]``, so every value needs narrowing before it can be
    compared or summed. Doing it through these three helpers rather than with a cast means the
    narrowing *is* the assertion that the contract holds -- a key that came back as the wrong
    type fails here, named, instead of further down as a confusing comparison.

    Args:
        result: A result dict from the query surface.
        key: The key to read.

    Returns:
        The value, as an ``int``.
    """
    value = result[key]
    assert isinstance(value, int), f"{key} came back as {type(value).__name__}"
    return value


def _text(result: Mapping[str, object], key: str) -> str:
    """Read a key the query surface promises is a string.

    Args:
        result: A result dict from the query surface.
        key: The key to read.

    Returns:
        The value, as a ``str``.
    """
    value = result[key]
    assert isinstance(value, str), f"{key} came back as {type(value).__name__}"
    return value


def _rows(result: Mapping[str, object], key: str) -> list[Any]:
    """Read a key the query surface promises is a list.

    Args:
        result: A result dict from the query surface.
        key: The key to read.

    Returns:
        The value, as a ``list``.
    """
    value = result[key]
    assert isinstance(value, list), f"{key} came back as {type(value).__name__}"
    return value


@pytest.fixture(scope="module", autouse=True)
def seeded_desk() -> Iterator[None]:
    """Seed one in-memory desk for the whole module.

    Read-only cases share it, because a test that writes nothing cannot leave anything behind
    for the next one to trip over; the cases that *do* write take ``writable_desk`` below and
    put it back. Seeding is the slow part, so doing it once rather than a dozen times is what
    keeps this module quick.

    The environment variable is cleared and the engine closed first, so a developer who has
    pointed the desk at a file on disk does not find this suite writing to it.
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.delenv(DB_URL_ENV, raising=False)
        close_desk()
        ensure_desk()
        yield
        close_desk()


@pytest.fixture
def writable_desk() -> Iterator[None]:
    """Restore the seeded desk after a test that inserts or updates a row.

    Reseeding on teardown rather than on setup means a single reseed per writing test, and it
    is what lets every other test in the module assume the canonical data regardless of the
    order they run in.
    """
    yield
    reset_desk()


def _fresh_engine() -> Engine:
    """Create and seed an in-memory desk of its own, independent of the module's."""
    engine = create_engine(
        IN_MEMORY_URL,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        seed_desk(session)
        session.commit()
    return engine


def _snapshot(engine: Engine) -> Snapshot:
    """Read every table in primary-key order, as plain tuples that compare by value."""
    with Session(engine) as session:
        return {
            table.name: [
                tuple(row)
                for row in session.execute(select(table).order_by(*table.primary_key.columns))
            ]
            for table in Base.metadata.sorted_tables
        }


@pytest.fixture(scope="module")
def twin_desks() -> tuple[Snapshot, Snapshot]:
    """Two desks seeded from scratch, independently of each other and of the module's.

    Snapshotted once and shared, because seeding is the expensive part of this suite and the
    two questions asked of these desks -- that every table got rows, and that both runs
    produced the same ones -- are answered from the same pair of snapshots.

    Returns:
        A snapshot of each desk, table by table, in primary-key order.
    """
    return _snapshot(_fresh_engine()), _snapshot(_fresh_engine())


# --- the schema and the seed ---------------------------------------------------------------


@pytest.mark.unit
def test_every_table_is_created_and_has_rows_in_it(
    twin_desks: tuple[Snapshot, Snapshot],
) -> None:
    empty = [name for name, rows in twin_desks[0].items() if not rows]

    assert empty == []
    assert len(twin_desks[0]) == len(Base.metadata.sorted_tables)


@pytest.mark.unit
def test_the_desk_holds_the_whole_order_book() -> None:
    with session_scope() as session:
        orders = session.scalar(select(func.count()).select_from(Order))

    assert orders == ORDER_COUNT


@pytest.mark.unit
def test_ensuring_the_desk_again_leaves_exactly_the_rows_it_already_had() -> None:
    """The claim that makes it safe for every app and every query to call it."""
    before = _snapshot(engine())

    ensure_desk()
    ensure_desk()

    assert _snapshot(engine()) == before


@pytest.mark.unit
def test_two_independently_seeded_databases_hold_identical_rows(
    twin_desks: tuple[Snapshot, Snapshot],
) -> None:
    first, second = twin_desks

    assert first == second


@pytest.mark.unit
def test_the_order_ids_the_example_flows_quote_exist() -> None:
    assert order_detail(QUOTED_ORDER) is not None


@pytest.mark.unit
def test_every_region_the_policies_name_appears_in_the_order_book() -> None:
    summary = order_summary()
    regions = summary["regions"]

    assert isinstance(regions, dict)
    assert set(REGIONS) <= set(regions)


# --- one database, several sessions, several threads ---------------------------------------


@pytest.mark.unit
def test_two_sessions_see_the_same_in_memory_desk() -> None:
    with session_scope() as first:
        from_first = first.scalar(select(func.count()).select_from(Order))
    with session_scope() as second:
        from_second = second.scalar(select(func.count()).select_from(Order))

    assert from_first == from_second == ORDER_COUNT


@pytest.mark.unit
def test_another_thread_sees_the_same_in_memory_desk() -> None:
    """The shared-database property, asserted as behaviour rather than as configuration."""
    from_here = desk_counts()["open_orders"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        from_there = list(pool.map(lambda _: desk_counts()["open_orders"], range(8)))

    assert from_there == [from_here] * 8
    assert from_here


@pytest.mark.unit
def test_threads_reading_the_shared_desk_at_once_all_get_the_whole_answer() -> None:
    """Sharing one connection is not the same as being safe to use from two threads at once.

    ``check_same_thread=False`` only removes pysqlite's objection to the second thread; two
    overlapping reads on one connection still tread on each other, and the way it surfaces is
    a short result set or an exception thrown from inside the row loader rather than anything
    that looks like a locking problem. The reads below are wide enough to be interrupted
    mid-fetch, which an aggregate query is not.
    """
    expected = find_orders(region="eu", status="open", limit=500)
    assert len(expected) > 25

    def read() -> list[dict[str, object]]:
        return find_orders(region="eu", status="open", limit=500)

    with ThreadPoolExecutor(max_workers=4) as pool:
        answers = [future.result() for future in [pool.submit(read) for _ in range(12)]]

    assert all(answer == expected for answer in answers)


# --- find_orders: the governed arguments actually select rows ------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("region", REGIONS)
def test_find_orders_returns_only_the_region_it_was_asked_for(region: str) -> None:
    found = find_orders(region=region, status="open", limit=50)

    assert found
    assert {row["region"] for row in found} == {region}


@pytest.mark.unit
@pytest.mark.parametrize("status", ["open", "closed"])
def test_find_orders_returns_only_the_status_it_was_asked_for(status: str) -> None:
    found = find_orders(region="eu", status=status, limit=50)

    assert found
    assert {row["status"] for row in found} == {status}


@pytest.mark.unit
def test_find_orders_honours_the_limit_and_a_narrowed_one_is_a_smaller_answer() -> None:
    narrowed = find_orders(region="eu", status="open", limit=3)
    wider = find_orders(region="eu", status="open", limit=25)
    everything = find_orders(region="eu", status="open", limit=500)

    assert len(narrowed) == 3
    assert len(wider) == 25
    # The three have to be three different answers, or a narrowed `limit` demonstrates
    # nothing in the example apps: the widest one must not be exhausted at 25 either.
    assert len(everything) > len(wider) > len(narrowed)


@pytest.mark.unit
def test_find_orders_is_ordered_by_order_id() -> None:
    ids = [_text(row, "order_id") for row in find_orders(region="eu", status="open", limit=40)]

    assert ids == sorted(ids)


@pytest.mark.unit
def test_find_orders_returns_nothing_rather_than_everything_for_a_limit_below_zero() -> None:
    """SQLite reads ``LIMIT -1`` as no limit at all, which would invert the argument."""
    assert find_orders(region="eu", status="open", limit=-1) == []


@pytest.mark.unit
def test_the_four_table_join_reports_the_customer_the_lines_and_the_money() -> None:
    row = find_orders(region="eu", status="open", limit=1)[0]
    detail = order_detail(_text(row, "order_id"))

    assert detail is not None
    lines = _rows(detail, "items")
    assert _text(row, "customer") == _text(detail, "customer")
    assert _int(row, "items") == len(lines) >= 1
    # The same money, summed once by SQL across orders/customers/order_items/products and
    # once in Python from the lines. An order stores no total for either to read.
    assert _int(row, "total") == sum(_int(line, "quantity") * _int(line, "price") for line in lines)
    assert _int(row, "total") > 0


# --- reading one order --------------------------------------------------------------------


@pytest.mark.unit
def test_order_detail_returns_none_for_an_order_that_does_not_exist() -> None:
    assert order_detail("ord-9999") is None


@pytest.mark.unit
def test_order_detail_carries_the_customer_the_address_and_the_lines() -> None:
    detail = order_detail(QUOTED_ORDER)

    assert detail is not None
    lines = _rows(detail, "items")
    assert detail["order_id"] == QUOTED_ORDER
    assert detail["region"] in REGIONS
    assert _text(detail, "address")
    assert lines
    assert all({"sku", "name", "quantity", "price"} <= set(line) for line in lines)


@pytest.mark.unit
def test_a_brief_names_as_many_orders_as_it_was_allowed_and_counts_all_of_them() -> None:
    brief = order_brief(3)

    assert len(_rows(brief, "orders")) == 3
    # The total stays true while the list is narrowed, so the gap is visible in the answer.
    assert _int(brief, "open_orders") > 3
    assert str(_int(brief, "open_orders")) in _text(brief, "headline")


# --- the counts the desk reports ----------------------------------------------------------


@pytest.mark.unit
def test_desk_counts_reports_the_desk_its_staffing_and_its_two_queues() -> None:
    counts = desk_counts()

    assert counts["desk"] == "orders"
    assert counts["open"] is True
    assert counts["open_orders"] == order_summary()["open_orders"]
    assert counts["pending_refunds"] == PENDING_REFUND_COUNT


# --- refunds: a domain error, and an approval that happens once ---------------------------


@pytest.mark.unit
def test_recording_a_refund_against_an_unknown_order_raises_a_domain_error() -> None:
    with pytest.raises(UnknownOrder) as raised:
        record_refund(order_id="ord-9999", amount=500, region="eu")

    assert raised.value.order_id == "ord-9999"


@pytest.mark.unit
def test_approving_a_refund_that_does_not_exist_returns_nothing() -> None:
    assert approve_refund("rf-9999") is None


@pytest.mark.unit
@pytest.mark.usefixtures("writable_desk")
def test_a_refund_is_booked_pending_and_then_approved_exactly_once() -> None:
    """Both halves in one walk, because the gap between them is what the row is for."""
    booked = record_refund(order_id=QUOTED_ORDER, amount=1_200, region="uk")
    refund_id = str(booked["refund_id"])

    assert booked["status"] == "pending"
    assert booked["order_id"] == QUOTED_ORDER
    assert booked["amount"] == 1_200
    assert refund_id.startswith("rf-")
    with session_scope() as session:
        assert session.scalar(select(Refund.approved_by).where(Refund.id == refund_id)) is None

    first = approve_refund(refund_id)
    second = approve_refund(refund_id)

    assert first is not None and second is not None
    assert first["status"] == "approved"
    assert first["approved_by"]
    # A retried call, or a second principal arriving at the same row, must not overwrite who
    # signed it off.
    assert second == first


# --- exports: the handle survives the call that created it --------------------------------


@pytest.mark.unit
@pytest.mark.usefixtures("writable_desk")
def test_an_export_can_be_read_back_by_the_handle_it_returned() -> None:
    started = start_export(fmt="csv", scope="open", region="eu", requested_by="alice")

    read_back = export_job(_text(started, "job_id"))

    assert read_back is not None
    assert {key: read_back[key] for key in started} == started
    assert _text(read_back, "created_at")
    # The row remembers the narrowing it was created under, which is what makes a later call
    # presenting this id answerable rather than something to be taken on trust.
    assert read_back["region"] == "eu"
    assert read_back["scope"] == "open"
    assert _int(read_back, "rows") == len(find_orders(region="eu", status="open", limit=10_000))


@pytest.mark.unit
def test_reading_an_export_that_does_not_exist_returns_nothing() -> None:
    assert export_job("exp-9999") is None


# --- tickets ------------------------------------------------------------------------------


@pytest.mark.unit
def test_a_ticket_thread_comes_back_oldest_first_and_says_who_wrote_each_line() -> None:
    thread = ticket_thread("tkt-0001")

    assert thread is not None
    messages = _rows(thread, "messages")

    assert messages
    assert all({"author", "role", "body"} <= set(message) for message in messages)
    # The table exists so that text somebody outside the desk wrote is identifiable as such.
    assert "customer" in {_text(message, "role") for message in messages}


@pytest.mark.unit
def test_reading_a_ticket_that_does_not_exist_returns_nothing() -> None:
    assert ticket_thread("tkt-9999") is None
