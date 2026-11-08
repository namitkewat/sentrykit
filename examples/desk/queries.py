"""The desk's reads and writes, as plain functions over the seeded database.

These are the functions the example apps govern. Not one of them takes a principal, imports
anything from the authorization layer, or asks whether the call is allowed — a point worth
being deliberate about rather than incidental. The decision has already been taken by the time
one of these runs, and the arguments that arrive are the ones policy settled on. What this
module contributes is that a *narrowed* argument now selects a different set of rows: ask for
``region="us"`` without being entitled to it and the call comes back with the EU orders that
actually exist, not with a string saying ``region=eu``.

Being caller-blind shows up in two signatures. :func:`record_refund` and
:func:`approve_refund` write a row that wants a name on it and are not told whose, so they
name the desk's agent and admin *of record*, resolved from the roster. Which principal
actually made the call is recorded in the authorization audit trail, which is the one place it
cannot drift out of step with the decision that permitted it.

Every function opens its own short transaction and returns plain ``dict`` and ``list``
objects, never an ORM instance: a mapped object that outlives its session is a lazy load
waiting to fail inside a template or a JSON encoder. Anyone who wants the ORM can take
:func:`~examples.desk.database.session_scope` instead.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.orm import InstrumentedAttribute, Session

from examples.desk.database import ensure_desk, session_scope
from examples.desk.models import (
    Address,
    Customer,
    ExportJob,
    Order,
    OrderItem,
    Product,
    Refund,
    Shipment,
    Team,
    Tenant,
    Ticket,
    TicketMessage,
    User,
    UserTeam,
)
from examples.desk.seed import DESK_TENANT, stamp

ALL_SCOPE = "all"
"""The ``scope`` value that means "every status", as opposed to naming one."""

OPEN_STATUS = "open"
"""The status the examples' policies supply as a default, so the one the summaries report."""

ALL_REGIONS: Final = "all"
"""The ``region`` value that means "every region at once", as opposed to naming one.

It exists as a *value* rather than as a second function, because the desk-wide form of a
destructive call is the one that most needs saying in a grant: a principal who may cancel in
their own region and nowhere else is a different principal from one who may cancel everywhere,
and the difference is only expressible to the authorization layer if it is an argument. That it
happens to be spelled the same as :data:`ALL_SCOPE` is a coincidence of English -- the two
govern different arguments, so narrowing one says nothing about the other.
"""


class UnknownOrder(LookupError):
    """Raised when a call names an order the desk does not have.

    A *domain* error, deliberately unrelated to the authorization layer's exception
    hierarchy. The example apps need both kinds to be visible at once: a refusal that comes
    from policy, and a plain "no such row" that comes from the business and would have been
    raised whoever had called. An app that renders them identically has lost the distinction
    its users most need.

    ``LookupError`` is the base because that is what this is — a failed lookup — so a caller
    who does not know about this class still handles it sensibly.
    """

    def __init__(self, order_id: str) -> None:
        super().__init__(f"No such order: {order_id}")
        self.order_id = order_id
        """The id that was not found, so a handler can name it without parsing the message."""


def desk_counts() -> dict[str, object]:
    """Report what the desk is and how much work is on it.

    The desk's name is read from the tenant rather than written here, and "open" means
    *staffed* — at least one agent is on at least one of the desk's teams. Both are facts
    about data, so an operator changes them by changing rows.

    Returns:
        ``desk``, the desk's name; ``open``, whether anybody is on it; ``open_orders`` and
        ``pending_refunds``, the two queues worth seeing at a glance.
    """
    ensure_desk()
    with session_scope() as session:
        desk = session.scalar(select(Tenant.desk).where(Tenant.id == DESK_TENANT))
        staffed = session.scalar(
            select(func.count())
            .select_from(UserTeam)
            .join(Team, Team.id == UserTeam.team_id)
            .where(Team.tenant_id == DESK_TENANT)
        )
        open_orders = session.scalar(
            select(func.count()).select_from(Order).where(Order.status == OPEN_STATUS)
        )
        pending = session.scalar(
            select(func.count()).select_from(Refund).where(Refund.status == "pending")
        )
        return {
            "desk": desk or "orders",
            "open": bool(staffed),
            "open_orders": int(open_orders or 0),
            "pending_refunds": int(pending or 0),
        }


def order_summary() -> dict[str, object]:
    """Summarize the open order book.

    ``regions`` is keyed in sorted order, so the dict a caller prints is the same dict on
    every run even though nothing about SQL guarantees group ordering.

    Returns:
        ``open_orders``, the total; ``regions``, open orders per region; ``oldest_open``, the
        id of the open order placed longest ago, or ``None`` when there are none.
    """
    ensure_desk()
    with session_scope() as session:
        regions, oldest = _open_order_stats(session)
    return {
        "open_orders": sum(regions.values()),
        "regions": regions,
        "oldest_open": oldest,
    }


def order_brief(limit: int) -> dict[str, object]:
    """Summarize the open order book and name the first ``limit`` of them.

    The one function that reports the narrowing and the thing narrowed in the same breath: a
    caller held to three gets a three-line brief, while the ``open_orders`` count beside it
    stays the true total. The gap between what was asked for and what was served is therefore
    visible in the answer itself, not only in the audit record.

    Args:
        limit: How many order ids to name. Zero and below name none.

    Returns:
        ``open_orders``, the total; ``headline``, one line a caller can print as-is;
        ``orders``, the ids, lowest first.
    """
    ensure_desk()
    with session_scope() as session:
        regions, oldest = _open_order_stats(session)
        ids = list(
            session.scalars(
                select(Order.id)
                .where(Order.status == OPEN_STATUS)
                .order_by(Order.id)
                .limit(_row_limit(limit))
            )
        )
    total = sum(regions.values())
    tail = f"oldest {oldest}" if oldest else "none open"
    return {
        "open_orders": total,
        "headline": f"{total} open orders across {len(regions)} regions, {tail}",
        "orders": ids,
    }


def find_orders(*, region: str, status: str, limit: int) -> list[dict[str, object]]:
    """Find the orders in one region with one status.

    The read that makes a narrowed argument worth watching: ``region`` and ``status`` both
    select rows, and ``limit`` decides how many come back, so three different grants over the
    same call produce three different tables.

    Four tables at once, every one of them load-bearing. ``orders`` is filtered, ``customers``
    supplies the name, and the total is summed across ``order_items`` and ``products``
    together because the quantity and the price live in different places — which is the reason
    an order carries no stored total to read instead.

    Args:
        region: The region to look in. One of ``eu``, ``uk``, ``us``.
        status: The status to look for. One of ``open``, ``closed``, ``cancelled``.
        limit: The most rows to return. Zero and below return none.

    Returns:
        One dict per order, lowest id first so that two runs agree: ``order_id``, ``region``,
        ``status``, ``customer``, ``total`` in minor units, and ``items``, the number of
        lines.
    """
    ensure_desk()
    with session_scope() as session:
        rows = session.execute(
            select(
                Order.id,
                Order.region,
                Order.status,
                Customer.name,
                func.sum(OrderItem.quantity * Product.price),
                func.count(OrderItem.id),
            )
            .join(Customer, Customer.id == Order.customer_id)
            .join(OrderItem, OrderItem.order_id == Order.id)
            .join(Product, Product.sku == OrderItem.sku)
            .where(Order.region == region, Order.status == status)
            .group_by(Order.id, Order.region, Order.status, Customer.name)
            .order_by(Order.id)
            .limit(_row_limit(limit))
        ).all()
    return [
        {
            "order_id": order_id,
            "region": order_region,
            "status": order_status,
            "customer": customer,
            "total": int(total or 0),
            "items": int(items or 0),
        }
        for order_id, order_region, order_status, customer, total, items in rows
    ]


def tenant_orders(*, tenant_id: str, status: str, limit: int) -> list[dict[str, object]]:
    """Find the orders belonging to one tenant's customers.

    The read that makes a *cross-tenant* narrowing legible in a way ``region`` cannot. Every
    region is still the same desk's book, so a caller served the wrong one has merely seen
    further than intended; ``tenant_id`` selects somebody else's book entirely, and the two
    have no order in common. An answer that mixes them is therefore recognisable as wrong by
    anyone who can read the ``tenant_id`` column, without knowing anything about the data.

    The filter rides on ``customers`` rather than on ``orders``, because an order is a
    tenant's by virtue of whose customer placed it -- and because that join is one
    :func:`find_orders` already makes to put a name in the result, so the extra selectivity
    costs nothing.

    Args:
        tenant_id: The tenant whose customers' orders to return.
        status: The status to look for. One of ``open``, ``closed``, ``cancelled``.
        limit: The most rows to return. Zero and below return none.

    Returns:
        One dict per order, lowest id first so that two runs agree: ``order_id``,
        ``tenant_id``, ``region``, ``status``, ``customer``, ``total`` in minor units, and
        ``items``, the number of lines.
    """
    ensure_desk()
    with session_scope() as session:
        rows = session.execute(
            select(
                Order.id,
                Customer.tenant_id,
                Order.region,
                Order.status,
                Customer.name,
                func.sum(OrderItem.quantity * Product.price),
                func.count(OrderItem.id),
            )
            .join(Customer, Customer.id == Order.customer_id)
            .join(OrderItem, OrderItem.order_id == Order.id)
            .join(Product, Product.sku == OrderItem.sku)
            .where(Customer.tenant_id == tenant_id, Order.status == status)
            .group_by(Order.id, Customer.tenant_id, Order.region, Order.status, Customer.name)
            .order_by(Order.id)
            .limit(_row_limit(limit))
        ).all()
    return [
        {
            "order_id": order_id,
            "tenant_id": tenant,
            "region": order_region,
            "status": order_status,
            "customer": customer,
            "total": int(total or 0),
            "items": int(items or 0),
        }
        for order_id, tenant, order_region, order_status, customer, total, items in rows
    ]


def order_detail(order_id: str) -> dict[str, object] | None:
    """Read one order in full.

    Args:
        order_id: The order to read, formatted ``ord-NNNN``.

    Returns:
        The order with its customer, its shipping address, its priced lines and its shipment,
        or ``None`` when there is no such order. Lines are ordered by sku. ``shipment`` is
        ``None`` for an order that has not been dispatched.
    """
    ensure_desk()
    with session_scope() as session:
        order = session.get(Order, order_id)
        if order is None:
            return None
        customer = session.get(Customer, order.customer_id)
        address = session.get(Address, order.address_id)
        lines = session.execute(
            select(OrderItem.sku, Product.name, OrderItem.quantity, Product.price)
            .join(Product, Product.sku == OrderItem.sku)
            .where(OrderItem.order_id == order.id)
            .order_by(OrderItem.sku)
        ).all()
        shipment = session.scalar(select(Shipment).where(Shipment.order_id == order.id))
        return {
            "order_id": order.id,
            "region": order.region,
            "status": order.status,
            "customer": customer.name if customer else None,
            "address": _one_line(address),
            "total": sum(int(quantity) * int(price) for _, _, quantity, price in lines),
            "items": [
                {"sku": sku, "name": name, "quantity": int(quantity), "price": int(price)}
                for sku, name, quantity, price in lines
            ],
            "shipment": _shipment(shipment),
        }


def start_export(*, fmt: str, scope: str, region: str, requested_by: str) -> dict[str, object]:
    """Record an export and hand back its handle.

    The handle is the interesting part. ``region`` and ``scope`` are stored on the row, so the
    job remembers the narrowing it was created under — which is what makes it possible to ask
    later whether a caller presenting this id is still inside it, rather than having to trust
    that they are.

    Args:
        fmt: The export format, as the caller ended up with it.
        scope: Which orders to cover. :data:`ALL_SCOPE` covers every status; any other value
            is read as the status to filter on, so ``scope="open"`` covers the open ones.
        region: Which region to cover.
        requested_by: The user the export is booked against.

    Returns:
        ``job_id`` and the four stored fields, plus ``rows``, the number of orders the export
        covers.
    """
    ensure_desk()
    with session_scope() as session:
        sequence = _next_sequence(session, ExportJob.id)
        covered = select(func.count()).select_from(Order).where(Order.region == region)
        if scope != ALL_SCOPE:
            covered = covered.where(Order.status == scope)
        rows = session.scalar(covered)
        job = ExportJob(
            id=f"exp-{sequence:04d}",
            fmt=fmt,
            scope=scope,
            region=region,
            rows=int(rows or 0),
            requested_by=requested_by,
            created_at=stamp(sequence),
        )
        session.add(job)
        return {
            "job_id": job.id,
            "fmt": job.fmt,
            "scope": job.scope,
            "region": job.region,
            "rows": job.rows,
            "requested_by": job.requested_by,
        }


def export_job(job_id: str) -> dict[str, object] | None:
    """Read an export back by its handle.

    Args:
        job_id: The id :func:`start_export` returned, formatted ``exp-NNNN``.

    Returns:
        The job as :func:`start_export` reported it, plus ``created_at`` as an ISO-8601
        string, or ``None`` when there is no such job.
    """
    ensure_desk()
    with session_scope() as session:
        job = session.get(ExportJob, job_id)
        if job is None:
            return None
        return {
            "job_id": job.id,
            "fmt": job.fmt,
            "scope": job.scope,
            "region": job.region,
            "rows": job.rows,
            "requested_by": job.requested_by,
            "created_at": _iso(job.created_at),
        }


def record_refund(*, order_id: str, amount: int, region: str) -> dict[str, object]:
    """Book a refund against an order, pending approval.

    Written ``pending`` rather than settled, because creating a refund and approving one are
    two calls under two different policies — and a row that waits between them is what lets an
    example show the second decision at all.

    Args:
        order_id: The order to refund, formatted ``ord-NNNN``.
        amount: How much to refund, in minor units.
        region: Where the refund is booked.

    Returns:
        ``refund_id``, ``order_id``, ``amount``, ``region`` and ``status``.

    Raises:
        UnknownOrder: When no order has that id. Checked here rather than left to a foreign
            key, so that the caller gets a named domain error instead of a database one.
    """
    ensure_desk()
    with session_scope() as session:
        if session.get(Order, order_id) is None:
            raise UnknownOrder(order_id)
        sequence = _next_sequence(session, Refund.id)
        refund = Refund(
            id=f"rf-{sequence:04d}",
            order_id=order_id,
            amount=amount,
            region=region,
            status="pending",
            reason="requested at the desk",
            requested_by=_of_record(session, "support"),
            approved_by=None,
            created_at=stamp(sequence),
        )
        session.add(refund)
        return {
            "refund_id": refund.id,
            "order_id": refund.order_id,
            "amount": refund.amount,
            "region": refund.region,
            "status": refund.status,
        }


def approve_refund(refund_id: str) -> dict[str, object] | None:
    """Approve a pending refund.

    Approves once. A refund that is already approved is returned as it stands, with the
    approver it was settled by — so a retried call, or a second principal arriving at the same
    row, cannot quietly overwrite who signed it off.

    Args:
        refund_id: The refund to approve, formatted ``rf-NNNN``.

    Returns:
        ``refund_id``, ``order_id``, ``amount``, ``region``, ``status`` and ``approved_by``,
        or ``None`` when there is no such refund.
    """
    ensure_desk()
    with session_scope() as session:
        refund = session.get(Refund, refund_id)
        if refund is None:
            return None
        if refund.status == "pending":
            refund.status = "approved"
            refund.approved_by = _of_record(session, "admin")
        return {
            "refund_id": refund.id,
            "order_id": refund.order_id,
            "amount": refund.amount,
            "region": refund.region,
            "status": refund.status,
            "approved_by": refund.approved_by,
        }


def ticket_thread(ticket_id: str) -> dict[str, object] | None:
    """Read one ticket and everything said on it.

    Most of the text that comes back was written by somebody outside the desk, which is why
    each message says whose words they are. A caller that passes a thread to a language model
    is passing it text a stranger chose, and ``role`` is how it can tell which lines those
    are.

    Args:
        ticket_id: The ticket to read, formatted ``tkt-NNNN``.

    Returns:
        ``ticket_id``, ``subject``, ``customer``, ``status`` and ``messages`` -- oldest first,
        each with ``author``, ``role`` and ``body`` -- or ``None`` when there is no such
        ticket.
    """
    ensure_desk()
    with session_scope() as session:
        ticket = session.get(Ticket, ticket_id)
        if ticket is None:
            return None
        customer = session.get(Customer, ticket.customer_id)
        rows = session.execute(
            select(TicketMessage.author, TicketMessage.author_role, TicketMessage.body)
            .where(TicketMessage.ticket_id == ticket.id)
            .order_by(TicketMessage.created_at, TicketMessage.id)
        ).all()
        return {
            "ticket_id": ticket.id,
            "subject": ticket.subject,
            "customer": customer.name if customer else None,
            "status": ticket.status,
            "messages": [
                {"author": author, "role": role, "body": body} for author, role, body in rows
            ],
        }


def cancel_open_orders(*, region: str) -> dict[str, object]:
    """Cancel every open order in one region.

    The desk's one genuinely destructive call, and it is here so that the examples have a side
    effect worth refusing. Everything else on this surface either reads, or writes a row that
    can be read back and argued with afterwards; this rewrites rows that were somebody's live
    orders, in bulk, with no record of what they used to be. A wrong ``region`` here is not a
    caller seeing too much -- it is a caller having already done too much.

    Destructive, and not idempotent in what it reports: the orders it closed stay closed, so a
    second call finds nothing left open in that region and says ``cancelled: 0``. That is a
    different answer to the same question rather than a repeat of the first one, and nothing
    short of :func:`~examples.desk.reset_desk` puts the open book back.

    Args:
        region: The region to cancel in. :data:`ALL_REGIONS` is the desk-wide form and takes
            every region's open orders at once; any other value names one region.

    Returns:
        ``region``, as it arrived; ``cancelled``, how many orders this call rewrote; and
        ``remaining_open``, how many are still open across the whole book afterwards -- the
        whole book rather than the named region, because that is the number that says whether
        a narrowed call left the rest of the desk alone.
    """
    ensure_desk()
    with session_scope() as session:
        standing = select(Order).where(Order.status == OPEN_STATUS)
        if region != ALL_REGIONS:
            standing = standing.where(Order.region == region)
        affected = list(session.scalars(standing.order_by(Order.id)))
        for order in affected:
            order.status = "cancelled"
        # Flushed before the count below, so `remaining_open` describes the book this call
        # leaves behind rather than the one it walked in on.
        session.flush()
        remaining = session.scalar(
            select(func.count()).select_from(Order).where(Order.status == OPEN_STATUS)
        )
        return {
            "region": region,
            "cancelled": len(affected),
            "remaining_open": int(remaining or 0),
        }


def _open_order_stats(session: Session) -> tuple[dict[str, int], str | None]:
    """Count the open orders by region and find the one placed longest ago.

    Shared by :func:`order_summary` and :func:`order_brief` so that the headline and the
    summary can never disagree about how many orders are open.

    Args:
        session: The open session.

    Returns:
        Open orders per region, keyed in sorted order so a printed dict is stable, and the id
        of the oldest open order or ``None`` when there are none.
    """
    rows = session.execute(
        select(Order.region, func.count())
        .where(Order.status == OPEN_STATUS)
        .group_by(Order.region)
        .order_by(Order.region)
    ).all()
    oldest = session.scalar(
        select(Order.id).where(Order.status == OPEN_STATUS).order_by(Order.placed_at).limit(1)
    )
    return {str(region): int(count) for region, count in rows}, oldest


def _row_limit(limit: int) -> int:
    """Return a limit SQLite will honour as a limit.

    SQLite reads ``LIMIT -1`` as *no limit at all*, so a negative number arriving here would
    serve the whole table through the one argument that was meant to bound it. Anything below
    zero therefore becomes zero, which returns nothing.

    Args:
        limit: The limit as it arrived.

    Returns:
        The same number, or zero when it was negative.
    """
    return max(limit, 0)


def _next_sequence(session: Session, column: InstrumentedAttribute[str]) -> int:
    """Return one past the highest sequence number in an ``xx-NNNN`` id column.

    Takes the maximum as text, which is only correct because the numbers are zero-padded to a
    fixed width and therefore sort the same way as text and as integers.

    Args:
        session: The open session.
        column: The primary-key column to look in.

    Returns:
        The next sequence number, counting from one.
    """
    highest = session.scalar(select(func.max(column)))
    if not highest:
        return 1
    return int(highest.rsplit("-", 1)[-1]) + 1


def _of_record(session: Session, role: str) -> str:
    """Return the id of the desk's agent of record for a role.

    The roster answers "whose name goes on this" because this layer is not told who called
    it. Lowest id wins, so the answer does not move between runs.

    Args:
        session: The open session.
        role: The role to resolve, ``support`` or ``admin``.

    Returns:
        A user id, or the role name itself when the roster has nobody in it.
    """
    found = session.scalar(
        select(User.id)
        .where(User.role == role, User.tenant_id == DESK_TENANT)
        .order_by(User.id)
        .limit(1)
    )
    return found if found else role


def _one_line(address: Address | None) -> str | None:
    """Flatten an address onto one line, which is how every example prints it.

    Args:
        address: The address, or ``None``.

    Returns:
        The one-line form, or ``None``.
    """
    if address is None:
        return None
    return f"{address.line1}, {address.city} {address.postcode}, {address.country}"


def _shipment(shipment: Shipment | None) -> dict[str, object] | None:
    """Flatten a shipment, or report that there is not one.

    Args:
        shipment: The shipment, or ``None``.

    Returns:
        A dict of the fields a caller chasing a parcel needs, or ``None``.
    """
    if shipment is None:
        return None
    return {
        "shipment_id": shipment.id,
        "carrier": shipment.carrier,
        "tracking": shipment.tracking,
        "status": shipment.status,
        "shipped_at": _iso(shipment.shipped_at),
    }


def _iso(moment: datetime) -> str:
    """Render a stored timestamp as an ISO-8601 string in UTC.

    The columns are naive because SQLite has no timezone type; UTC is re-attached here, at the
    one boundary where the value stops being a database row and becomes something a caller
    reads.

    Args:
        moment: A naive datetime understood as UTC.

    Returns:
        The ISO-8601 form, with the offset.
    """
    return moment.replace(tzinfo=UTC).isoformat()
