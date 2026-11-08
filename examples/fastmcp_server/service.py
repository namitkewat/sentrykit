"""The protected callables. Ordinary functions that happen to be governed.

None of them takes a request, reads a header, inspects ``_meta``, or knows that a model is on
the other end. The principal reaches them through the ambient context the provider established
at the MCP boundary, which is what lets the same functions be called from a tool dispatch, from
an HTTP route, or from a background job with no change.

Most of them are registered on the server through
:func:`~sentrykit.integrations.fastmcp.governed_tool`, which takes them exactly as they are —
already protected, still directly callable from anywhere else in the program — and adds the two
layers an MCP boundary needs: an omittable-argument shim, so the model can propose nothing and
let policy decide, and a translator that carries a refusal out of the tool body with its
envelope intact. A bare ``@server.tool()`` over ``@protect`` would lose that envelope.

:func:`summarize_orders` is the exception, and it is here on purpose: it is protected and it is
**never registered as a tool**. No model can propose it. It is reached only from inside
:func:`brief_orders`, and it is decided on its own terms all the same — a second decision, a
second audit record, from the same ambient principal.

## Every body queries a real database

The bodies read and write :mod:`examples.desk`, a seeded SQLite orders desk, and that is what
makes the argument layer legible rather than merely reported. A ``limit`` refilled with 10
comes back with ten real orders; a ``region`` the caller was not entitled to leaves them looking
at a different set of rows, with different customers and different totals. The number in the
envelope and the answer in the result agree because the answer was produced by the number.

The desk takes no principal, imports nothing from the authorization layer and never asks
whether a call is permitted — which is the separation an application should be able to keep.
By the time one of these bodies runs, the decision has been taken and the arguments it was
given are the ones policy settled on.

## A row that is not there is not a refusal

The desk has already decided which misses are answers and which are failures: a read of an id
it does not hold comes back as ``None``, and a *write* against one raises. These bodies follow
that judgement rather than overruling it — a ``None`` is reported as ``found: False`` and the
raise is left to propagate — and at this boundary that is worth being deliberate about. mcp
turns any exception out of a tool body into an error result, which is the same shape a refusal
has, so converting "there is no such order" into one would blur the single distinction a model
most needs: policy said no, versus nothing is there.

## Where a Python default belongs, and where it does not

``status`` and ``scope`` carry Python defaults. ``region``, ``limit``, ``fmt``, ``amount`` and
the identifiers do not, and that contrast is the lesson. A value **policy decides** must stay
omittable, because a Python default would fill the parameter in before sentrykit ever saw an
omission and the principal's own default would be unreachable. A value that is the caller's own
business — which slice of orders they want — is Python's to answer for, and giving it a default
costs nothing.

That distinction has a mechanical consequence too. Narrowing *refines* a proposal; it does not
rescue one: if every argument a caller proposed is rejected, the call is refused rather than
completed from defaults, so a refill needs at least one co-argument that survives. On this
boundary that is easy to arrange without noticing, because mcp materializes a schema default
before dispatch — ``status`` and ``scope`` arrive as proposed arguments whether or not the
caller named them, and they keep a narrowed call alive without being asked to. The tools whose
every parameter is policy-decidable are where a wholly-rejected proposal is still reachable.

Run the whole thing with `pixi run -e agent run-mcp`.
"""

from __future__ import annotations

from typing import Final

from examples import desk
from sentrykit import current_principal, protect

# The desk is reached through the module rather than by importing its functions, for one
# concrete reason: it exports ``approve_refund`` too, and a bare import of that name would be
# shadowed by the protected callable below — leaving the tool body calling itself.

BRIEF_LIMIT: Final = 3
"""How many order ids a briefing names.

Fixed here rather than taken as an argument, because :func:`brief_orders` has no parameter to
put it in and adding one would change what the model is told it may propose. Three keeps a
briefing down to a line, and the true total travels beside the ids, so the gap between the
whole order book and what was named is visible in the answer itself.
"""

EXPORT_REGION: Final = "eu"
"""Which region an export covers, since nothing in :func:`export_orders` carries one.

A stated constant rather than something inferred, and the distinction matters. The grants here
bound ``region`` on searches and on refunds, and an argument constraint governs the one action
it names; borrowing the search rule would apply a rule about searching to an export. So the
desk's home region is said once, here, where a reader can see that it is this example's
decision and not policy's.
"""

UNATTRIBUTED: Final = "unattributed"
"""What an export is booked against when no principal is ambient.

Named rather than guessed at, because it is out of reach through the gate: a call the engine
let through has a principal, so a body that finds none was never authorized and has no business
inventing a name for whoever ran it.
"""


# THE BARE FORM. No ``action=`` and no ``resource=``, so sentrykit derives both from the
# callable's import path: this is ``Action::"examples.fastmcp_server.service.desk_status"``,
# and the resource is the matching ``Resource::"…"``. The reviewed policy that permits it has
# to name that exact string, which is why an explicit ``action=`` is what you want as soon as
# the policy outlives the module layout — moving or renaming this function silently changes
# the id the policy is matching against.
#
# Watch in the envelope: ``action`` is the import path, and ``decision`` is ``allow`` for every
# principal, because the policy names no role.
@protect
def desk_status() -> dict[str, object]:
    """Report whether the desk is open. The one action nobody is gated on.

    Returns:
        The desk's name, whether anybody is staffing it, and the two queues worth seeing at a
        glance: open orders, and refunds waiting on an approval.
    """
    return desk.desk_counts()


# Protected, and NOT registered as a tool anywhere in this example. A model cannot propose it;
# only :func:`brief_orders` reaches it. It is still gated, still filtered, and still audited.
#
# Watch in the audit trail: calling ``brief_orders`` writes TWO records — the outer one first,
# before the body runs, then this one.
@protect(action='Action::"orders.summarize"', resource='Tool::"orders"')
def summarize_orders() -> dict[str, object]:
    """Summarize the desk's open orders.

    Returns:
        How many orders are open, how those split across regions, and the id of the one placed
        longest ago.
    """
    return desk.order_summary()


# The tool that calls the protected non-tool above. Two ``@protect`` decorators in one dispatch
# compose: two decisions, two audit records, and if the inner one is refused the ``AuthzDenied``
# propagates out through this function unchanged — the caller sees the inner refusal, not a
# rewritten one.
#
# Watch in the envelope: this reports ``Action::"orders.brief"``. The inner decision does not
# appear here at all; it appears in the audit trail as its own record.
@protect(action='Action::"orders.brief"', resource='Tool::"orders"')
def brief_orders() -> dict[str, object]:
    """Brief the desk, which means summarizing it — through a second gate.

    Returns:
        A briefing that wraps the summary the inner call was separately authorized to make.
        ``brief`` is that summary, carrying its own envelope; beside it are ``headline``, one
        line a caller can print as-is, the true ``open_orders`` total, and the first few open
        order ids.
    """
    return {"brief": summarize_orders(), **desk.order_brief(limit=BRIEF_LIMIT)}


# Default injection and per-principal argument filtering, both on one call.
#
# ``region`` and ``limit`` declare no Python defaults so a policy default is reachable; the
# model may propose neither and get alice's ``eu``/``10`` or dana's ``eu``/``25``. ``status``
# does declare one, because which slice of orders to look at is the caller's own business.
#
# Watch in the envelope: ``defaults_applied`` holds what the caller never chose, ``rejected``
# holds what was refused and why, and ``processed`` holds what sentrykit actually passed. A
# value that appears in both ``rejected`` and ``defaults_applied`` was rejected and refilled —
# the refill is the principal's own default, never the bound that refused it. Then watch the
# rows: they are the same three values asking the database a question.
@protect(action='Action::"orders.search"', resource='Tool::"orders"')
def search_orders(region: str, limit: int, status: str = "open") -> dict[str, object]:
    """Search orders in one region.

    Args:
        region: Which region to search. Constrained per principal.
        limit: How many orders to return. Bounded per principal, and by the reviewed ceiling.
        status: Which orders to look at. The caller's own choice; policy says nothing about it.

    Returns:
        The three arguments as policy settled on them, ``count``, and ``orders`` — the matching
        rows from the desk, lowest id first, each with its region, status, customer, total in
        minor units and number of lines. ``limit`` is therefore legible twice: as the number
        the call ran with, and as the number of rows it brought back. A narrowed limit is a
        shorter answer, not the same answer with a smaller number attached to it; a refilled
        ``region`` is a different set of customers.
    """
    orders = desk.find_orders(region=region, status=status, limit=limit)
    return {
        "region": region,
        "limit": limit,
        "status": status,
        "count": len(orders),
        "orders": orders,
    }


# The relationship tool. Nothing in this signature, in this body, or in the policy that
# authorizes it mentions a team or a division. Alice reaches it over four hops and Cedar walks
# every one of them; bob's chain is exactly as long and lands on the other project.
#
# Watch in the envelope: ``resource`` is ``Order::"ord-0003"`` for both principals and ``decision``
# differs. At ``debug`` verbosity, alice's ``determining_policies`` names
# ``project-members-may-read-project-orders`` — a policy that mentions neither of them.
@protect(action='Action::"orders.read"', resource='Order::"ord-0003"')
def read_order(order_id: str) -> dict[str, object]:
    """Read one order.

    Args:
        order_id: Which order to read.

    Returns:
        The order with its customer, its shipping address, its priced lines and its shipment,
        beside ``found: True``. ``shipment`` is ``null`` for an order not yet dispatched. An id
        the desk does not hold comes back as ``found: False`` and nothing else — a miss the
        desk itself answers rather than raises, reported here as what it is.
    """
    order = desk.order_detail(order_id)
    if order is None:
        return {"order_id": order_id, "found": False}
    return {"found": True, **order}


# A gate that reads the proposed argument, over an argument layer that also reads it. Cedar
# sees the RAW proposal, so ``fmt="pdf"`` trips the reviewed ``no-pdf-exports`` forbid before
# any filtering happens; ``fmt="xml"`` passes the gate and is then rejected by bob's own
# deny-set and refilled with ``csv``.
#
# Watch in the envelope: a ``pdf`` call is ``decision: deny`` with a reason and no ``processed``
# at all — the body never ran. An ``xml`` call is ``decision: allow`` with ``fmt`` in both
# ``rejected`` and ``defaults_applied``.
@protect(action='Action::"orders.export"', resource='Tool::"orders"')
def export_orders(fmt: str, scope: str = "open") -> dict[str, object]:
    """Export orders in one format.

    Two of the things the desk stores on the job are not in this signature, which is the part
    worth copying. ``requested_by`` is the human the agent is acting for, learned from
    :func:`~sentrykit.current_principal` — the ambient principal the provider established at
    the boundary. The model can neither read that name nor write it, because it is not an
    argument, so a tool body knows whose export it is booking without taking a parameter for
    it, without being handed a request, and without importing a framework to ask. ``region`` is
    :data:`EXPORT_REGION`, because no argument carries one.

    Args:
        fmt: The export format. Decided by policy, so it declares no Python default.
        scope: Which orders to export. The caller's own choice.

    Returns:
        The job's handle and the four fields stored on it, plus ``rows`` — how many orders the
        export covers. The stored ``scope`` and ``region`` are what make the handle worth
        having: the job remembers the narrowing it was created under, so a caller presenting
        the id later can be held to it rather than trusted about it.
    """
    principal = current_principal()
    return desk.start_export(
        fmt=fmt,
        scope=scope,
        region=EXPORT_REGION,
        requested_by=principal.id if principal is not None else UNATTRIBUTED,
    )


# Three arguments, one unconditional permit, and two reviewed ``forbid`` rules that read the
# proposal. ``no-large-cross-region-refunds`` decides on the relationship BETWEEN two arguments:
# neither ``region`` nor ``amount`` is out of bounds alone, and the combination is refused.
# ``refunds-above-the-desk-limit-need-an-admin`` decides on an argument TOGETHER WITH the
# principal: over 1000 is refused unless the caller is an admin. Both are Cedar evaluating the
# whole request from ``context.args`` — sentrykit needs no extra syntax for either shape, and no
# ``if`` statement in this body approximates one.
#
# The permit is unconditional on purpose. A permit whose ``when`` clause read ``context.args``
# would come out false for a caller that has proposed nothing — which is exactly what a
# ``tools/list`` probe is — and this tool would disappear from every manifest.
#
# Watch in the envelope: both refusals are ``forbid``s, so both are NAMED in
# ``determining_policies`` at ``debug``. A refusal that names nothing is the other shape
# entirely: bob on ``orders.read`` or ``orders.search``, where no permit reaches him and the
# request falls through to Cedar's default deny.
@protect(action='Action::"refunds.issue"', resource='Tool::"refunds"')
def issue_refund(order_id: str, amount: int, region: str) -> dict[str, object]:
    """Issue a refund against one order.

    A **write**: each permitted call books a new row and the desk allocates its id, so two
    calls are two refunds and a re-run is not idempotent.

    Args:
        order_id: The order to refund. Alice's grant constrains its shape and gives it no
            default, so a malformed one is refused rather than replaced.
        amount: How much. Bounded per principal, and separately by the reviewed desk limit.
        region: Where the refund is booked.

    Returns:
        The refund as the desk booked it: a freshly allocated ``refund_id``, the three
        arguments as policy settled on them, and ``status`` — ``pending``, because booking a
        refund and approving one are two calls under two different policies. The row carries
        the *processed* amount, which is the part worth noticing: the side effect that really
        happened is the one policy settled on, not the one that was proposed.

    Raises:
        UnknownOrder: When the desk holds no order with that id. Refunding an order that is
            not there is a failed call rather than an answer, which is why the desk raises
            where a read returns nothing, and this body leaves the raise alone: deciding how a
            domain error is rendered is the host's job, not the authorization layer's.
    """
    return desk.record_refund(order_id=order_id, amount=amount, region=region)


# The admin action, and the cheapest possible demonstration that a gate is about the principal
# and not about the arguments: the same one-argument call, allowed for dana and refused for
# alice, with no argument constraint involved on either side.
#
# Watch in the envelope: identical ``action`` and ``resource``, different ``decision``.
@protect(action='Action::"refunds.approve"', resource='Tool::"refunds"')
def approve_refund(refund_id: str) -> dict[str, object]:
    """Approve a pending refund.

    Args:
        refund_id: The refund to approve.

    Returns:
        The settled refund beside ``found: True``, including ``approved_by``. That name is the
        desk's admin of record and not the caller: the desk is never told who called it, and
        which principal was authorized to approve this is in the audit trail, where it cannot
        drift out of step with the decision that permitted it. An id the desk does not hold
        comes back as ``found: False``. Approving an already-approved refund changes nothing
        and keeps the approver it was settled by.
    """
    approval = desk.approve_refund(refund_id)
    if approval is None:
        return {"refund_id": refund_id, "found": False}
    return {"found": True, **approval}
