"""The desk, as eight ordinary functions. The ungoverned arm of the comparison.

Run the suite with `pixi run -e default python -m examples.scenarios`; this module is the half
that does the work, and the half that an attacker is ultimately talking to.

Nothing here imports :mod:`sentrykit`. That absence is the measurement: these are the functions
an application would have written anyway, reached directly, with no gate in front of them and no
argument the caller proposed inspected by anybody. Whatever the suite records against this arm is
what the desk does when asked nicely, which is the only honest baseline for what the governed arm
changes.

## One body, two arms

:mod:`examples.scenarios.governed` builds its protected twins by applying
:func:`~sentrykit.decorator.protect` to *these function objects* at import time. The bodies are
written once, here. An A/B comparison between two implementations of the same idea measures the
implementations; this one measures the layer, because there is only one implementation underneath
it.

That is also why nothing in this module reads an ambient principal, a request, or a decision
envelope. A body that asked who was calling could not be the ungoverned arm of anything — it
would already be the governed one, in miniature and by hand.

## A row that is not there is not a refusal

The desk has already decided which misses are answers and which are failures: a read of an id it
does not hold comes back as ``None``, and a *write* against one raises. These bodies follow that
judgement rather than overruling it — a ``None`` is reported as ``found: False``, and the raise is
left to propagate. Keeping the two apart matters more here than anywhere else in the examples,
because the suite's whole question is whether a call was refused, and "there is no such ticket"
must not be able to answer it.

## What a body is free to compute

Two of these functions hand back more than the argument they were given selects:
:func:`fetch_export` resolves a handle into the rows behind it, and :func:`region_report` puts a
desk-wide aggregate beside one region's orders. Both are written that way on purpose, and both
stay that way in the governed arm, because the suite is as interested in what an authorization
layer does not reach as in what it does.
"""

from __future__ import annotations

from typing import Final

from examples import desk

# The desk is reached through the module rather than by importing its functions one by one: two
# of the queries below are named here before they exist anywhere else, and a `from ... import`
# would resolve at import time where an attribute resolves at call time.

REQUESTED_BY: Final = "desk"
"""The name an export is booked against.

Deliberately not a principal. A real application books an export against whoever asked for it,
read from the ambient context — and :mod:`examples.scenarios.governed` is where that would go,
because reading it here would mean this module knowing an authorization layer exists. Keeping the
name out of the body is what lets both arms share one body, and the cost is visible and small:
every export in either arm is booked to the desk itself.
"""

EXPORT_ROWS: Final = 1000
"""How many rows a fetched export handle hands back.

Larger than any one region's order book, so the handle is not quietly also a limit. The point of
:func:`fetch_export` is that presenting a handle returns everything behind it; a number small
enough to truncate the answer would hide that behind a coincidence.
"""

REPORT_LIMIT: Final = 10
"""How many of a region's open orders a report lists.

Fixed here rather than taken as an argument, because :func:`region_report` is about the *other*
number it returns — the desk-wide one — and a second governed argument would only draw attention
away from it.
"""


def search_orders(region: str, limit: int, status: str = "open") -> dict[str, object]:
    """Search one region's orders.

    The ordinary read, and the one every narrowing mechanism is easiest to see against: ``region``
    selects which rows, ``limit`` decides how many, and both are values a caller proposes.

    Args:
        region: Which region to search.
        limit: How many orders to return.
        status: Which orders to include. Keeps an ordinary Python default, so it is never absent
            and nothing can be filled in for it.

    Returns:
        The three arguments as the call ran with them, ``count``, and ``orders`` — the matching
        rows from the desk, lowest id first.
    """
    orders = desk.find_orders(region=region, status=status, limit=limit)
    return {
        "region": region,
        "limit": limit,
        "status": status,
        "count": len(orders),
        "orders": orders,
    }


def read_ticket(ticket_id: str) -> dict[str, object]:
    """Read one support ticket and everything said on it.

    Most of the text that comes back was typed by a customer, which is what makes this the suite's
    delivery route for an instruction aimed at a model rather than at the desk.

    Args:
        ticket_id: Which ticket to read.

    Returns:
        The thread beside ``found: True`` — subject, customer, status, and the messages oldest
        first, each saying whose words they are. A ticket the desk does not hold comes back as
        ``found: False`` and nothing else.
    """
    thread = desk.ticket_thread(ticket_id)
    if thread is None:
        return {"ticket_id": ticket_id, "found": False}
    return {"found": True, **thread}


def start_export(region: str, fmt: str = "csv") -> dict[str, object]:
    """Start an export of one region's open orders and hand back its handle.

    The handle is what the next two functions are about. ``region`` and ``scope`` are stored on the
    job, so it remembers the narrowing it was created under — and that memory lives in the desk,
    where an authorization layer cannot see it.

    Args:
        region: Which region to export.
        fmt: The export format.

    Returns:
        Whatever the desk recorded: the ``job_id``, the four stored fields, and ``rows``, the
        number of orders the export covers.
    """
    return desk.start_export(fmt=fmt, scope="open", region=region, requested_by=REQUESTED_BY)


def fetch_export(job_id: str) -> dict[str, object]:
    """Fetch an export by its handle, and the rows it covers.

    The laundering shape. A caller presents an opaque id and receives the orders behind it without
    ever naming a region, so the one argument on this call says nothing about what the answer will
    contain. The job's stored ``scope`` is read back as the status to filter on, which is how the
    answer ends up being exactly the set the export was created for.

    Args:
        job_id: The handle :func:`start_export` returned.

    Returns:
        The job as the desk stored it beside ``found: True``, plus ``count`` and ``orders`` — the
        rows the export covers. A handle the desk does not hold comes back as ``found: False`` and
        nothing else.
    """
    job = desk.export_job(job_id)
    if job is None:
        return {"job_id": job_id, "found": False}
    orders = desk.find_orders(
        region=str(job["region"]), status=str(job["scope"]), limit=EXPORT_ROWS
    )
    return {"found": True, **job, "count": len(orders), "orders": orders}


def fetch_export_rows(job_id: str, region: str) -> dict[str, object]:
    """Fetch an export by its handle, with the caller stating which region it believes it covers.

    The same read as :func:`fetch_export`, and the second shape exists for a plain reason: a handle
    hides the narrowing it was created under, so an argument constraint over this call has nothing
    to constrain. Whoever hosts the call has to re-express that narrowing as an argument policy can
    actually see, and then hold the answer to it — which is what ``region`` is. The desk still
    knows which region the job covers; the difference is that now the caller has to say it too, and
    a claim that does not match the job is answered with nothing.

    Args:
        job_id: The handle :func:`start_export` returned.
        region: The region the caller claims the handle covers.

    Returns:
        When the claim matches the job: the same payload as :func:`fetch_export`, plus
        ``mismatch: False``. When it does not: ``found: True`` with ``mismatch: True``, no rows,
        and no field of the job other than the region that was claimed — a caller learns that
        their claim was wrong, and nothing about what would have been right. A handle the desk does
        not hold comes back as ``found: False``.
    """
    job = desk.export_job(job_id)
    if job is None:
        return {"job_id": job_id, "found": False}
    if job["region"] != region:
        return {
            "job_id": job_id,
            "found": True,
            "region": region,
            "mismatch": True,
            "count": 0,
            "orders": [],
        }
    orders = desk.find_orders(
        region=str(job["region"]), status=str(job["scope"]), limit=EXPORT_ROWS
    )
    return {"found": True, **job, "mismatch": False, "count": len(orders), "orders": orders}


def list_tenant_orders(tenant_id: str, limit: int, status: str = "open") -> dict[str, object]:
    """List one tenant's orders.

    The cross-tenant read. Nothing in this signature distinguishes the caller's own tenant from
    anybody else's: ``tenant_id`` is a string, and the desk serves whichever one it is given.

    ``status`` is the caller's own business — no policy here has an opinion about it — so it keeps
    an ordinary Python default, which is the design rule the rest of these examples teach. It also
    does mechanical work in the demonstration: a call in which *every* proposed argument is
    rejected is refused outright rather than completed from defaults, so a proposal that is to be
    narrowed rather than refused needs something in it that survives. An argument nobody governs
    is the natural thing for that to be.

    Args:
        tenant_id: Whose orders to list.
        limit: How many orders to return.
        status: Which orders to include. Passed through untouched.

    Returns:
        The three arguments as the call ran with them, ``count``, and ``orders`` — the tenant's
        matching orders, lowest id first.
    """
    orders = desk.tenant_orders(tenant_id=tenant_id, status=status, limit=limit)
    return {
        "tenant_id": tenant_id,
        "limit": limit,
        "status": status,
        "count": len(orders),
        "orders": orders,
    }


def cancel_open_orders(region: str = "eu") -> dict[str, object]:
    """Cancel every open order in one region.

    The destructive call, and the only one in the suite whose damage cannot be read back out. Note
    what ``region`` carries: a Python default, and the value is the desk's home region — the
    largest book and the most expensive thing to lose. A caller who names no region at all is
    therefore proposing the worst available call, which is the ordinary way an omitted argument
    goes wrong.

    One value is wider still. The desk reads ``all`` as every region at once, so a single argument
    spells the difference between clearing one region's book and clearing the desk's.

    Args:
        region: Which region to clear out. ``all`` is the desk-wide form.

    Returns:
        Whatever the desk reported: the region, and how many orders it cancelled.
    """
    return desk.cancel_open_orders(region=region)


def region_report(region: str, status: str = "open") -> dict[str, object]:
    """Report one region's orders, beside the whole desk's order book.

    Read the two keys it returns. ``orders`` is the region the caller asked about, selected by the
    argument. ``book`` is :func:`examples.desk.order_summary`, which counts every region there is
    — so ``region`` can be settled correctly, by any mechanism, and the answer still carries a
    total the caller was never entitled to. The reason is structural: a layer that decides whether
    a call may happen, and with which arguments, decides nothing about what the body then chooses
    to compute. The body here chooses to compute a figure wider than its argument, and it is a
    function's own author who has to not do that.

    ``status`` keeps a Python default for the same two reasons it does on
    :func:`list_tenant_orders`: no policy here has an opinion about it, and a proposal in which
    every argument is rejected is refused rather than narrowed, so showing ``region`` being
    refilled needs one argument in the call that survives.

    Args:
        region: Which region to report on.
        status: Which orders to include. Passed through untouched.

    Returns:
        The two arguments as the call ran with them, ``count`` and ``orders`` — the region's
        matching orders, up to :data:`REPORT_LIMIT` of them — and ``book``, the desk-wide summary
        of the *open* book whatever ``status`` was: how many are open in total, how those split
        across every region, and the id of the one placed longest ago.
    """
    orders = desk.find_orders(region=region, status=status, limit=REPORT_LIMIT)
    return {
        "region": region,
        "status": status,
        "count": len(orders),
        "orders": orders,
        "book": desk.order_summary(),
    }
