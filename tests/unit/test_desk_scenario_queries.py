"""The desk calls and the planted message the attack/defence scenarios are built on.

These three pieces are tested here rather than inside the scenarios because a scenario asserts
what *authorization* did, and an assertion of that shape is only worth something if the thing
underneath it genuinely happened. A cross-tenant read that quietly returned the right tenant's
rows whatever it was asked for, or a bulk cancel that cancelled nothing, would let a scenario
report a defence that had never been tested.

So each of the three is pinned to the property a scenario leans on:

* :func:`~examples.desk.tenant_orders` must really separate the two tenants' books. The tenant
  is where ``region`` cannot reach -- two regions are still one desk, two tenants are two
  businesses -- and the ids in them are disjoint, so a wrong answer is recognisable rather than
  merely larger than expected.
* :func:`~examples.desk.cancel_open_orders` must really take the rows away, and must take away
  only the ones it was asked for. A refused destructive call demonstrates nothing if the call
  was harmless.
* :func:`~examples.scenarios.attack.plant_injection` must land the hostile message where a
  reader meets it -- last on the thread, in a customer's voice -- and must leave no trace once
  the desk is reset, so that nothing else in this suite is reading poisoned data.

Expected counts are queried, never written down. The seed is deterministic, so a literal would
pass today and become a silent lie the first time the distribution moved; a count read from the
same database the call reads keeps the assertion about the call. The helpers that read it
directly open with :func:`~examples.desk.ensure_desk`, exactly as the query surface does, so
that whichever case runs first in a process finds a seeded desk rather than an empty schema.

The cases that write cancel the whole open book, so they take ``writable_desk`` below, which
reseeds on the way out as well as on the way in.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, Final

import pytest
from examples import desk
from examples.scenarios import attack
from sqlalchemy import func, select

DESK_TENANT: Final = desk.DESK_TENANT
"""The tenant whose desk this is, and the one the example apps' principals belong to."""

OTHER_TENANT: Final = "globex"
"""The second tenant, whose book is the one the planted message tries to talk a reader into."""

OPEN: Final = "open"
"""The status every count here is taken over, and the one the policies supply as a default."""

TENANT_ORDER_KEYS: Final = (
    "order_id",
    "tenant_id",
    "region",
    "status",
    "customer",
    "total",
    "items",
)
"""Exactly the keys :func:`~examples.desk.tenant_orders` documents, in order.

Asserted as an ordered tuple rather than a set because the examples print these rows as a
table, and a column that moved would move the table's headings without failing anything else.
"""

AUTHORIZATION_PACKAGE: Final = "sentrykit"
"""The import no module in the data layer may carry. The desk is the domain, not the gate."""

WIDE: Final = 5_000
"""A limit above any result set here, so a call made with it returns the whole of one."""


# --- reading a result the query surface typed as `object` -----------------------------------


def _int(result: Mapping[str, object], key: str) -> int:
    """Read a key the query surface promises is a whole number.

    The surface returns ``dict[str, object]``, so narrowing a value *is* the assertion that the
    documented contract holds: a key that came back as the wrong type fails here, named, rather
    than further down as a puzzling comparison.

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


def _money(detail: Mapping[str, object]) -> int:
    """Sum one order's lines in Python, so the total SQL computed has something to agree with.

    Args:
        detail: A result from :func:`~examples.desk.order_detail`.

    Returns:
        The order's total, in minor units.
    """
    return sum(_int(line, "quantity") * _int(line, "price") for line in _rows(detail, "items"))


# --- reading the database without going through the call under test ------------------------


def _tenant_ids() -> set[str]:
    """Every tenant the desk holds, so the two named at the top of this module stay honest."""
    desk.ensure_desk()
    with desk.session_scope() as session:
        return set(session.scalars(select(desk.Tenant.id)))


def _order_ids(*, tenant_id: str, status: str) -> set[str]:
    """One tenant's order ids at one status, read independently of ``tenant_orders``.

    Args:
        tenant_id: The tenant whose customers' orders to look for.
        status: The status to look for.

    Returns:
        The ids, as a set.
    """
    desk.ensure_desk()
    with desk.session_scope() as session:
        return set(
            session.scalars(
                select(desk.Order.id)
                .join(desk.Customer, desk.Customer.id == desk.Order.customer_id)
                .where(desk.Customer.tenant_id == tenant_id, desk.Order.status == status)
            )
        )


def _open_by_region() -> dict[str, int]:
    """Count the open orders in each region, as the book stands at the moment of the call.

    A region with nothing open drops out of the mapping rather than appearing as a zero, which
    is what lets "this region is empty now" be asserted as an absence.

    Returns:
        Open orders per region.
    """
    desk.ensure_desk()
    with desk.session_scope() as session:
        rows = session.execute(
            select(desk.Order.region, func.count())
            .where(desk.Order.status == OPEN)
            .group_by(desk.Order.region)
        ).all()
    return {str(region): int(count) for region, count in rows}


def _found_ids(rows: list[dict[str, object]]) -> set[str]:
    """Collect the order ids out of a result table.

    Args:
        rows: What ``find_orders`` or ``tenant_orders`` returned.

    Returns:
        The ids, as a set.
    """
    return {_text(row, "order_id") for row in rows}


def _thread() -> Mapping[str, object]:
    """Read the thread the injection is planted on, failing loudly if the desk has lost it."""
    thread = desk.ticket_thread(attack.INJECTED_TICKET)
    assert thread is not None, f"the desk has no {attack.INJECTED_TICKET}"
    return thread


def _bodies() -> set[str]:
    """Every ticket message body on the desk, so "nothing was planted" is checked desk-wide."""
    desk.ensure_desk()
    with desk.session_scope() as session:
        return set(session.scalars(select(desk.TicketMessage.body)))


def _as_thread_message(planted: Mapping[str, object]) -> dict[str, object]:
    """Re-key a plant report the way a thread read keys a message.

    The two surfaces agree field for field except that one carries the ticket id and the other
    does not. Dropping it lets the test compare whole messages rather than compare two subsets
    of them and hope the rest followed.

    Args:
        planted: What :func:`~examples.scenarios.attack.plant_injection` returned.

    Returns:
        The same message, shaped as :func:`~examples.desk.ticket_thread` returns one.
    """
    return {key: planted[key] for key in ("author", "role", "body")}


# --- the static import scan ----------------------------------------------------------------


def _data_layer_sources() -> list[Path]:
    """Every module allowed to touch rows and nothing else: the desk, and the planted input."""
    return [*sorted(Path(desk.__file__).parent.glob("*.py")), Path(attack.__file__)]


def _label(path: Path) -> str:
    """Name a scanned module by package and file, so two ``__init__.py`` cannot collide."""
    return f"{path.parent.name}/{path.name}"


def _imported_top_level_packages(source: str) -> set[str]:
    """The top-level package name of every absolute import in ``source``.

    Walks the whole tree rather than the module body, because an import inside a function or a
    conditional is still an import, and a scan that read only the top of a file would be one
    somebody could step around without meaning to.

    Args:
        source: The module's text.

    Returns:
        The top-level names it imports.
    """
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    return imported


@pytest.fixture
def writable_desk(seeded_desk: None) -> Iterator[None]:
    """Seed the desk for a test that writes, and put the rows back once it has finished.

    Built on the shared ``seeded_desk`` fixture, which reseeds on the way *in*. That is enough
    for the test itself and not enough for the suite: these cases cancel the whole open book,
    and the next module to read it would find an empty one with nothing to explain why. So the
    reseed happens on the way out as well.

    Yields:
        Nothing; the value of this fixture is the state it leaves behind.
    """
    yield
    desk.reset_desk()


# --- tenant_orders: two tenants, two books -------------------------------------------------


@pytest.mark.unit
def test_the_desk_holds_exactly_the_two_tenants_these_cases_name() -> None:
    """The one place the tenant ids are written down, checked against the database itself."""
    assert _tenant_ids() == {DESK_TENANT, OTHER_TENANT}


@pytest.mark.unit
@pytest.mark.parametrize("tenant_id", [DESK_TENANT, OTHER_TENANT])
def test_tenant_orders_returns_only_the_tenant_it_was_asked_for(tenant_id: str) -> None:
    """Both tenants, because a filter that is ignored still passes when asked for the larger."""
    found = desk.tenant_orders(tenant_id=tenant_id, status=OPEN, limit=WIDE)

    assert found
    assert {row["tenant_id"] for row in found} == {tenant_id}
    assert _found_ids(found) == _order_ids(tenant_id=tenant_id, status=OPEN)


@pytest.mark.unit
def test_the_two_tenants_open_books_are_disjoint_and_together_are_the_whole_book() -> None:
    """What makes a cross-tenant answer recognisable rather than merely bigger than expected."""
    ours = _found_ids(desk.tenant_orders(tenant_id=DESK_TENANT, status=OPEN, limit=WIDE))
    theirs = _found_ids(desk.tenant_orders(tenant_id=OTHER_TENANT, status=OPEN, limit=WIDE))

    assert ours and theirs
    assert not ours & theirs
    assert len(ours | theirs) == sum(_open_by_region().values())


@pytest.mark.unit
@pytest.mark.parametrize("status", ["open", "closed", "cancelled"])
def test_tenant_orders_returns_only_the_status_it_was_asked_for(status: str) -> None:
    found = desk.tenant_orders(tenant_id=DESK_TENANT, status=status, limit=WIDE)

    assert found
    assert {row["status"] for row in found} == {status}


@pytest.mark.unit
def test_tenant_orders_honours_the_limit_and_a_narrowed_one_is_a_smaller_answer() -> None:
    """Three limits have to be three different answers, or narrowing one demonstrates nothing."""
    whole_book = _order_ids(tenant_id=DESK_TENANT, status=OPEN)
    assert len(whole_book) > 25

    narrowed = desk.tenant_orders(tenant_id=DESK_TENANT, status=OPEN, limit=3)
    wider = desk.tenant_orders(tenant_id=DESK_TENANT, status=OPEN, limit=25)
    everything = desk.tenant_orders(tenant_id=DESK_TENANT, status=OPEN, limit=WIDE)

    assert len(narrowed) == 3
    assert len(wider) == 25
    assert _found_ids(everything) == whole_book


@pytest.mark.unit
def test_tenant_orders_is_ordered_by_order_id() -> None:
    found = desk.tenant_orders(tenant_id=DESK_TENANT, status=OPEN, limit=40)
    ids = [_text(row, "order_id") for row in found]

    assert ids == sorted(ids)


@pytest.mark.unit
def test_tenant_orders_returns_nothing_rather_than_everything_for_a_limit_below_zero() -> None:
    """SQLite reads ``LIMIT -1`` as no limit at all, which would invert the argument."""
    assert desk.tenant_orders(tenant_id=DESK_TENANT, status=OPEN, limit=-1) == []


@pytest.mark.unit
def test_tenant_orders_returns_nothing_for_a_tenant_the_desk_does_not_have() -> None:
    assert desk.tenant_orders(tenant_id="initech", status=OPEN, limit=WIDE) == []


@pytest.mark.unit
def test_tenant_orders_reports_the_documented_keys_in_the_documented_order() -> None:
    row = desk.tenant_orders(tenant_id=DESK_TENANT, status=OPEN, limit=1)[0]

    assert tuple(row) == TENANT_ORDER_KEYS


@pytest.mark.unit
def test_tenant_orders_reports_the_same_money_and_lines_as_reading_the_order_in_full() -> None:
    """The total is summed across four tables, so it has to come out the same way twice."""
    row = desk.tenant_orders(tenant_id=DESK_TENANT, status=OPEN, limit=1)[0]
    detail = desk.order_detail(_text(row, "order_id"))

    assert detail is not None
    assert _text(row, "customer") == _text(detail, "customer")
    assert _int(row, "items") == len(_rows(detail, "items")) >= 1
    assert _int(row, "total") == _money(detail) > 0


# --- cancel_open_orders: the one call that takes rows away ---------------------------------


@pytest.mark.unit
@pytest.mark.usefixtures("writable_desk")
def test_cancelling_one_region_leaves_every_other_region_open() -> None:
    """A narrowed destructive call has to be narrow in its *effect*, not only in its report."""
    before = _open_by_region()
    assert len(before) > 1

    result = desk.cancel_open_orders(region="uk")

    after = _open_by_region()
    assert result["region"] == "uk"
    assert _int(result, "cancelled") == before["uk"]
    assert "uk" not in after
    assert after == {region: count for region, count in before.items() if region != "uk"}
    assert _int(result, "remaining_open") == sum(after.values())


@pytest.mark.unit
@pytest.mark.usefixtures("writable_desk")
def test_cancelling_the_orders_in_one_region_cancels_exactly_those_orders() -> None:
    """Named by id, so "it cancelled the right number" cannot stand in for the right rows."""
    doomed = _found_ids(desk.find_orders(region="us", status=OPEN, limit=WIDE))
    assert doomed

    desk.cancel_open_orders(region="us")

    cancelled = _found_ids(desk.find_orders(region="us", status="cancelled", limit=WIDE))
    assert doomed <= cancelled
    assert desk.find_orders(region="us", status=OPEN, limit=WIDE) == []


@pytest.mark.unit
@pytest.mark.usefixtures("writable_desk")
def test_cancelling_every_region_empties_the_open_book() -> None:
    """The desk-wide form, which is the one a grant most needs to be able to withhold."""
    before = sum(_open_by_region().values())
    assert before

    result = desk.cancel_open_orders(region=desk.ALL_REGIONS)

    assert result["region"] == desk.ALL_REGIONS
    assert _int(result, "cancelled") == before
    assert _int(result, "remaining_open") == 0
    assert _open_by_region() == {}


@pytest.mark.unit
@pytest.mark.usefixtures("writable_desk")
def test_cancelling_a_region_a_second_time_finds_nothing_left_to_cancel() -> None:
    """The rows stay rewritten, so the second call answers the same question differently."""
    first = desk.cancel_open_orders(region="eu")
    second = desk.cancel_open_orders(region="eu")

    assert _int(first, "cancelled") > 0
    assert _int(second, "cancelled") == 0
    assert _int(second, "remaining_open") == _int(first, "remaining_open")


@pytest.mark.unit
def test_cancelling_a_region_the_desk_books_no_orders_in_changes_nothing() -> None:
    """No fixture: a call that matches no row writes none, so there is nothing to put back."""
    before = sum(_open_by_region().values())

    result = desk.cancel_open_orders(region="apac")

    assert _int(result, "cancelled") == 0
    assert _int(result, "remaining_open") == before


# --- the planted injection -----------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.usefixtures("writable_desk")
def test_planting_the_injection_appends_one_customer_message_as_the_last_word() -> None:
    """Where a reader meets it, in whose voice, and that it is one row rather than a thread."""
    before = _rows(_thread(), "messages")

    planted = attack.plant_injection()

    after = _rows(_thread(), "messages")
    assert len(after) == len(before) + 1
    assert after[:-1] == before
    assert after[-1] == _as_thread_message(planted)
    assert _text(after[-1], "role") == "customer"
    assert _text(after[-1], "body") == attack.INJECTION


@pytest.mark.unit
@pytest.mark.usefixtures("writable_desk")
def test_the_planted_message_is_written_by_the_customer_whose_ticket_it_is() -> None:
    """An author of its own would be filterable by that author, and nothing real would be."""
    planted = attack.plant_injection()

    with desk.session_scope() as session:
        ticket = session.get(desk.Ticket, attack.INJECTED_TICKET)
        assert ticket is not None
        assert planted["author"] == ticket.customer_id


@pytest.mark.unit
@pytest.mark.usefixtures("writable_desk")
def test_resetting_the_desk_removes_the_planted_message() -> None:
    """The claim that keeps every other test and every example app reading clean data."""
    before = _rows(_thread(), "messages")

    attack.plant_injection()
    desk.reset_desk()

    assert _rows(_thread(), "messages") == before
    assert attack.INJECTION not in _bodies()


@pytest.mark.unit
def test_no_seeded_message_carries_an_instruction_aimed_at_whoever_reads_it() -> None:
    """The desk ships clean: the hostile text exists only once it has been planted."""
    assert attack.INJECTION not in _bodies()


@pytest.mark.unit
def test_planting_the_injection_on_a_ticket_that_does_not_exist_raises_a_lookup_error() -> None:
    with pytest.raises(LookupError, match="tkt-9999"):
        attack.plant_injection("tkt-9999")


# --- the data layer stays the data layer ---------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("source_path", _data_layer_sources(), ids=_label)
def test_no_module_in_the_data_layer_imports_the_authorization_layer(source_path: Path) -> None:
    """The desk answers what the rows say; whether a call was allowed is decided elsewhere.

    The attacker's module is scanned alongside the desk because the attack is expressed purely
    as data: it writes a row and makes no claim about what anybody may do with it.

    Checked statically, because walking ``sys.modules`` would pass vacuously -- the library is
    imported by the rest of this suite whether or not these modules reached for it.
    """
    imported = _imported_top_level_packages(source_path.read_text(encoding="utf-8"))

    assert AUTHORIZATION_PACKAGE not in imported, f"{_label(source_path)} imports the library"


@pytest.mark.unit
def test_the_scan_reaches_the_desk_package_and_the_planted_input() -> None:
    """A scan that quietly found no files would be a test that quietly asserted nothing."""
    scanned = {_label(path) for path in _data_layer_sources()}

    assert {"desk/queries.py", "desk/models.py", "scenarios/attack.py"} <= scanned


@pytest.mark.unit
def test_the_scanner_would_catch_the_import_wherever_it_hid() -> None:
    hidden = [
        "import sentrykit",
        "from sentrykit.engine import Governor",
        "if True:\n    import sentrykit.errors",
        "def late() -> None:\n    from sentrykit import protect",
    ]

    assert all(AUTHORIZATION_PACKAGE in _imported_top_level_packages(text) for text in hidden)
