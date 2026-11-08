"""The protected callables: ordinary functions that happen to be governed.

Not one of them takes a request, reads a header, or knows a web framework exists. The
principal reaches them through the ambient context the provider established at the boundary,
which is what lets the identical file sit behind FastAPI, behind Flask, behind an MCP tool
dispatch or behind a cron job.

Every body reads or writes :mod:`examples.desk`, a seeded order desk that knows nothing about
authorization. That is what makes narrowing legible rather than merely reported: a ``limit``
refilled with 10 brings back ten orders, and a caller refused ``region="cn"`` comes back with
the orders of the region policy gave them instead of a field saying ``eu``. A row the desk
does not hold leaves this layer as a ``LookupError``, uncaught — mapping a missing row to a
status code is a different job from refusing a call, and an app that renders the two
identically has lost the distinction its users most need.

Read the signatures for the one design rule worth copying: **``status`` and ``scope`` carry
Python defaults, and nothing else does.** A parameter whose value *policy* decides —
``region``, ``limit``, ``fmt``, ``amount`` — must stay omittable, because a Python default
would fill the hole before a policy default could reach it. A parameter that is the caller's
own business answers to Python and never troubles the policy layer at all.

``status`` and ``scope`` earn their keep a second way. A call whose *every* proposed argument
is rejected is refused rather than rebuilt from defaults, so proposing one of these alongside
a value that is about to be narrowed is what keeps the call alive.

Run the whole flow table with ``pixi run -e web run-fastapi``.
"""

from __future__ import annotations

from typing import Final

from examples import desk
from sentrykit import current_principal, protect

EXPORT_REGION: Final = "eu"
"""Which region an export covers.

The desk needs one and nothing can supply it. :func:`export_orders` takes no region
parameter — the reviewed policies and the grants are written against its signature — and the
caller's grants cannot answer either: an argument constraint governs the one action it names,
and nobody holds a ``region`` constraint on ``orders.export``, so borrowing the one from
``orders.search`` would apply a rule about searching to an export. The desk's home region is
therefore stated here, in one place, where a reader can see it is this example's decision and
not policy's.
"""

UNATTRIBUTED: Final = "unattributed"
"""What an export is booked against when no principal is ambient.

Out of reach through the gate, which is why it is named rather than guessed at: a call the
engine let through has a principal, so a body that finds none was never authorized and has no
business inventing a name for whoever ran it.
"""


@protect
def desk_status() -> dict[str, object]:
    """Report whether the desk is open.

    **The bare form.** With no ``action=`` and no ``resource=``, sentrykit derives both from
    the callable's import path: this one is authorized as
    ``Action::"examples.fastapi_app.service.desk_status"`` against a resource synthesized
    from the same path. ``policies/10-orders.cedar`` names that action verbatim, which is
    what the derived id looks like in a reviewed file.

    In the ``_authz`` envelope: ``action`` is the import path, and nothing else is
    interesting — no arguments means no argument layer.

    Returns:
        The desk's name, whether anybody is on it, and the two queues worth seeing at a
        glance: open orders, and refunds waiting for an approval.
    """
    return desk.desk_counts()


@protect(action='Action::"orders.summarize"', resource='Tool::"orders"')
def summarize_orders() -> dict[str, object]:
    """Summarize the open orders.

    Reached from a route that is **not** protected. The gate is on the call, not on the URL:
    this function is authorized against the same ambient principal whether a handler, a
    service layer three frames deeper, or a background job invokes it.

    In the ``_authz`` envelope: a plain allow, on a response served by a handler that
    mentions authorization nowhere.

    Returns:
        The open order book: how many orders are open, how they split across the regions, and
        the id of the one placed longest ago.
    """
    return desk.order_summary()


@protect(action='Action::"orders.search"', resource='Tool::"orders"')
def search_orders(region: str, limit: int, status: str = "open") -> dict[str, object]:
    """Search one region's orders.

    Where most of the argument layer is visible at once. ``region`` is governed by an
    allow-set, ``limit`` by a per-principal maximum *and* by the ceiling declared in
    ``policies/10-orders.cedar``, and both carry defaults; ``status`` is governed by nobody.

    Propose nothing and both governed arguments are filled from the caller's defaults.
    Propose a value the caller may not have and it is rejected, then their default fills the
    gap — the result is their default, which is not the bound the value breached. Dana asks
    for ``limit=500`` against a ceiling of 100 and runs with 25.

    The rows are what make that readable. ``region`` and ``status`` decide which orders exist
    for this caller and ``limit`` decides how many of them come back, so Dana's twenty-five
    rows and Alice's ten are two different answers to the identical request — and a caller
    refused ``cn`` is holding the orders of the region they were given instead.

    In the ``_authz`` envelope: ``rejected`` names the value that was refused and the rule
    and policy that refused it; ``defaults_applied`` names what was put in its place;
    ``processed`` is what this body actually received.

    Args:
        region: Which region to search. Constrained per principal.
        limit: How many orders to return. Bounded per principal and by the reviewed ceiling.
        status: Which orders to count. The caller's own business, so Python answers for it.

    Returns:
        The three effective arguments, ``count``, and ``orders`` — one entry per order with
        its region, status, customer, total in minor units and number of lines, lowest id
        first. The arguments are echoed so a caller can see what policy let through without
        reading the envelope; the rows are what policy let them see.
    """
    orders = desk.find_orders(region=region, status=status, limit=limit)
    return {
        "region": region,
        "limit": limit,
        "status": status,
        "count": len(orders),
        "orders": orders,
    }


@protect(action='Action::"orders.read"', resource='Order::"ord-0003"')
def read_order(order_id: str) -> dict[str, object]:
    """Read one order.

    The relationship case. ``project-members-may-read-project-orders`` names no role and no
    person: it says a member of ``Project::"orders-eu"`` may read an order in
    ``Project::"orders-eu"``, and Cedar walks both chains. Alice reaches the project through
    Team then Division; the order reaches it through one edge of its own. Bob's chain is the
    same length and ends somewhere else, so the same call is refused for him with no second
    policy written.

    Nothing in the row names that project, and nothing has to. The edge from
    ``Order::"ord-0003"`` to ``Project::"orders-eu"`` lives in the entity graph the policy
    walks, not in a column the desk would have to populate and keep true.

    In the ``_authz`` envelope: an allow for Alice and a deny for Bob, from one policy that
    mentions neither of them. Bob's deny **names nothing**: no permit reached him, so no
    policy was determining and ``determining_policies`` is empty even at ``debug``. A refusal
    by a ``forbid`` names that ``forbid``; a refusal because nothing permitted the call has
    nothing to name. His refusal on ``orders.search`` reads the same way.

    Args:
        order_id: Which order to read.

    Returns:
        The order with its customer, its one-line address, its priced lines and its shipment —
        a null shipment when it has not been dispatched yet.

        An id the desk does not hold comes back as ``found: False`` and nothing else. That
        is reported rather than raised, and the reason is about the *other* boundaries this
        same file sits behind: an exception out of a tool body becomes an error result, which
        is the shape a refusal has, so raising here would make "no such order" and "policy
        said no" arrive looking alike. The one distinction these examples exist to teach
        would be the casualty. A route that wants a 404 can read the flag.
    """
    order = desk.order_detail(order_id)
    if order is None:
        return {"order_id": order_id, "found": False}
    return {"found": True, **order}


@protect(action='Action::"orders.export"', resource='Tool::"orders"')
def export_orders(fmt: str, scope: str = "open") -> dict[str, object]:
    """Export orders in one format.

    Governed twice over, by two different mechanisms. Cedar sees the caller's **raw**
    proposal, so ``no-pdf-exports`` refuses ``fmt="pdf"`` at the gate before the argument
    layer runs at all. ``fmt="xml"`` clears the gate and is then rejected by Bob's own
    deny-set and refilled with ``csv``.

    Propose ``fmt="xml"`` **alone** and the call is refused instead: refilling refines a
    proposal, it does not rescue one, and nothing the caller sent survived.

    The desk books every export against a name, and this signature carries none — so the name
    comes from :func:`~sentrykit.current_principal`, the ambient principal the provider
    established at the boundary. That is the whole mechanism worth copying: a service layer
    can learn who is calling without taking a parameter for it, without being handed a
    request, and without importing a framework to ask.

    In the ``_authz`` envelope: a ``pdf`` attempt is ``decision: "deny"`` with the reason;
    an ``xml`` attempt beside a surviving ``scope`` is an allow carrying both a ``rejected``
    entry and a ``defaults_applied`` entry. An ``xml`` attempt on its own raises
    ``NoValidArguments``, whose body names the rejection and adds an ``allowed`` block
    saying what the caller may pass instead.

    Args:
        fmt: The export format. Governed by the caller's deny-set.
        scope: Which orders to include. The caller's own business.

    Returns:
        The job's handle and the four fields stored on it, plus ``rows``, the number of orders
        it covers. ``region`` is :data:`EXPORT_REGION` and ``requested_by`` is the ambient
        principal, so the stored row remembers both the narrowing it was created under and who
        it was created for.
    """
    principal = current_principal()
    return desk.start_export(
        fmt=fmt,
        scope=scope,
        region=EXPORT_REGION,
        requested_by=principal.id if principal is not None else UNATTRIBUTED,
    )


@protect(action='Action::"refunds.issue"', resource='Tool::"refunds"')
def issue_refund(order_id: str, amount: int, region: str) -> dict[str, object]:
    """Issue a refund against an order.

    An unconditional permit, and two ``forbid`` rules over it that read the proposal. A refund
    of 750 is fine and a ``uk`` refund is fine, and together they are forbidden — that rule
    decides purely on the **relationship between two arguments**. A refund of 5000 is refused
    for support and permitted for an admin — that rule decides on **an argument together with
    the principal**. Cedar evaluates the whole request at once, so sentrykit needs no extra
    syntax to express either one.

    The permit is unconditional on purpose. A permit whose ``when`` clause read
    ``context.args`` would come out false for a caller who has proposed nothing yet, and an
    agent asking which tools it may attempt proposes nothing. Permit broadly, forbid narrowly.

    The layers are separately visible here. At 900 the gate says yes — it is under the desk
    limit — and Alice's own grant then rejects the value and refills it with 50. The row the
    desk writes carries the 50, which is the part worth noticing: the side effect that really
    happened is the one policy settled on, not the one that was proposed.

    In the ``_authz`` envelope: both refusals are **named** denies at ``debug``, by
    ``no-large-cross-region-refunds`` and ``refunds-above-the-desk-limit-need-an-admin``
    respectively, because a ``forbid`` that fires is determining. An ``order_id`` that fails
    its pattern has no default to fall back on and raises ``DefaultUnavailable``, whose body
    names the argument rather than an action — the gate had already said yes.

    Args:
        order_id: The order being refunded. Governed by a pattern with no default.
        amount: How much to refund. Bounded per principal and by policy.
        region: Where the refund is booked. Governed by an allow-set.

    Returns:
        The refund as booked: a fresh id, the order, the amount, the region, and ``pending``.
        Approving it is a second call under a second policy, which is why the row waits.

    Raises:
        UnknownOrder: Raised by the desk when no order has that id, and left to propagate for
            the reason the module docstring gives. No flow reaches it: the one request that
            names an order the desk has not got fails its pattern first.
    """
    return desk.record_refund(order_id=order_id, amount=amount, region=region)


@protect(action='Action::"refunds.approve"', resource='Tool::"refunds"')
def approve_refund(refund_id: str) -> dict[str, object]:
    """Approve a pending refund.

    The admin action, and the cleanest before-and-after in the example: the same call, two
    principals, two answers. Policy says ``Role::"admin"`` may approve; the grant store says
    who holds ``admin``, and the reviewed file never changes when that answer does.

    In the ``_authz`` envelope: an allow for Dana, and a deny for Alice naming the action she
    was refused.

    Args:
        refund_id: Which refund to approve.

    Returns:
        The refund as it now stands, including ``approved_by`` — the desk's admin of record,
        resolved from its own roster, because the desk is never told who called. Which
        principal was permitted to make this call is in the audit trail instead, where it
        cannot drift out of step with the decision that permitted it.

        A refund id the desk does not hold comes back as ``found: False``, for the same
        reason :func:`read_order` reports a miss rather than raising one. Approving an
        already-approved refund changes nothing and answers the same way, so a repeated call
        is neither an error nor a second approval.
    """
    approved = desk.approve_refund(refund_id)
    if approved is None:
        return {"refund_id": refund_id, "found": False}
    return {"found": True, **approved}
