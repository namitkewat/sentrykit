"""The protected callables. Ordinary functions that happen to be governed.

Run the example with `pixi run -e agent run-agent`; this module is the half that does the work
once the decision has been made.

Not one of these takes a ``RunContext``, reads ``deps``, or knows an LLM exists. The principal
reaches them through the ambient context the provider established for the dispatch, which is
what lets the same functions be called from an agent tool, from an HTTP route, or from a
nightly job with no change.

## The work is a real query

Each body reads or writes :mod:`examples.desk`, a seeded SQLite orders desk. That is what turns
the argument layer from something reported into something visible: a ``limit`` refilled with 10
comes back with ten real orders, and a ``region`` refilled with the caller's own default comes
back with different customers and different totals. The envelope says what policy decided; the
result is what that decision selected.

The desk takes no principal, imports nothing from the authorization layer, and never asks
whether a call is permitted — the separation an application should be able to keep. By the time
one of these bodies runs the decision has been taken, and the arguments that arrived are the
ones policy settled on.

## A row that is not there is not a refusal

The desk has already decided which misses are answers and which are failures: a read of an id
it does not hold comes back as ``None``, and a *write* against one raises. These bodies follow
that judgement rather than overruling it — a ``None`` is reported as ``found: False``, and the
raise is left to propagate. At an agent boundary that is worth being deliberate about, because
an exception out of a tool body reaches the model as a failed call, which is also the shape a
refusal has: converting "there is no such order" into one would blur the single distinction a
model most needs, between policy saying no and nothing being there.

## Python defaults, and when not to write one

``status`` and ``scope`` carry Python defaults; nothing else does, and that contrast is the
lesson. ``region``, ``limit``, ``fmt`` and ``amount`` are values *policy* decides, so they have
to stay omittable for a policy default to be reachable at all — a parameter Python has already
answered for is never absent, and an argument that is never absent can never be filled in from
a grant. ``status`` and ``scope`` are the caller's own business, nobody's policy has an opinion
about them, so Python answers for them.

They also do a mechanical job in the demonstration: a call whose every proposed argument is
rejected is refused outright, so the flows that show a refill propose one of these alongside
the argument being narrowed.
"""

from __future__ import annotations

from typing import Final

from examples import desk
from sentrykit import current_principal, protect

# The desk is reached through the module rather than by importing its functions one by one.
# One of them is called ``approve_refund``, and a bare import of that name would be shadowed by
# the protected callable below — which would leave that tool's body calling itself.

BRIEF_LIMIT: Final = 3
"""How many order ids a briefing names.

Fixed here rather than taken as an argument, because :func:`brief_orders` has no parameter to
put it in and adding one would change what the model is told it may propose. Three keeps a
briefing to one line, and the true total travels beside the ids, so the distance between the
whole order book and what was named is visible in the answer.
"""

EXPORT_REGION: Final = "eu"
"""Which region an export covers, since nothing in :func:`export_orders` carries one.

A stated constant rather than something inferred, and the difference is the point: the grants
in this example bound ``region`` on searches and on refunds, and an argument constraint governs
the one action it names. Borrowing the search rule would apply a rule about searching to an
export, so the desk's home region is said once, here, where a reader can see that it is this
example's decision and not policy's.
"""

UNATTRIBUTED: Final = "unattributed"
"""What an export is booked against when no principal is ambient.

Named rather than guessed at, because it is out of reach through the gate: a call the engine
let through has a principal, so a body that finds none was never authorized and has no business
inventing a name for whoever ran it.
"""


@protect
def desk_status() -> dict[str, object]:
    """Report whether the desk is open. Available to anyone the application recognises.

    The **bare** form of the decorator: no ``action=``, no ``resource=``. sentrykit derives
    ``Action::"examples.pydantic_ai_agent.service.desk_status"`` from the callable's import
    path and synthesises a matching ``Resource``, which is why the policy naming it reads like
    a Python path. Convenient to start with, and fragile in exactly one way: moving or renaming
    this function silently changes the action id and the policy stops matching. Pass an
    explicit ``action=`` as soon as the policy is expected to outlive the module layout.

    Returns:
        The desk's name, whether anybody is staffing it, and the two queues worth seeing at a
        glance — open orders, and refunds waiting on an approval. The engine annotates the
        mapping with ``_authz`` in place.
    """
    return desk.desk_counts()


@protect(action='Action::"orders.summarize"', resource='Tool::"orders"')
def summarize_orders() -> dict[str, object]:
    """Summarize the desk's open orders.

    Deliberately **not registered as a tool**. No model is ever offered it and no model can
    propose it — and it is still protected, because the gate is on the *call*, not on the tool
    registration. :func:`brief_orders` reaches it from inside a tool body and it is decided
    there on its own merits.

    Returns:
        How many orders are open, how those split across regions, and the id of the one placed
        longest ago, which the engine annotates with ``_authz`` in place.
    """
    return desk.order_summary()


@protect(action='Action::"orders.brief"', resource='Tool::"orders"')
def brief_orders() -> dict[str, object]:
    """Brief the caller on the desk, by calling a second protected callable.

    Nested ``@protect`` composes, and the composition is worth watching:

    * **two decisions run**, one for ``orders.brief`` and one for ``orders.summarize``, each
      against the same ambient principal — the inner call inherits nobody's authority from the
      outer one;
    * **two audit records** reach whatever sink is wired, and the outer record is written
      *before* this body runs, so a refusal inside the body cannot erase the fact that the
      outer call was permitted;
    * an inner refusal **propagates unchanged** to whoever called the outer function. It is not
      caught, re-wrapped, or downgraded into a partial answer.

    Returns:
        A briefing, which the engine annotates with ``_authz`` in place: ``headline``, one line
        a caller can print as-is, the true ``open_orders`` total, and the first few open order
        ids. The nested summary carries its own ``_authz`` under ``brief``.
    """
    return {"brief": summarize_orders(), **desk.order_brief(limit=BRIEF_LIMIT)}


@protect(action='Action::"orders.search"', resource='Tool::"orders"')
def search_orders(region: str, limit: int, status: str = "open") -> dict[str, object]:
    """Search orders in one region.

    Args:
        region: Which region to search. Constrained per principal.
        limit: How many orders to return. Bounded per principal, and bounded again by the
            reviewed ceiling on ``support-may-search``.
        status: Which orders to include. Nobody's policy has an opinion about it, so it keeps
            an ordinary Python default and is passed through untouched.

    Returns:
        The three arguments as policy settled on them, ``count``, and ``orders`` — the matching
        rows from the desk, lowest id first, each with its region, status, customer, total in
        minor units and number of lines. The engine annotates the mapping with ``_authz`` in
        place.

        ``limit`` is legible twice over here: as the number the call ran with, and as the
        number of rows it brought back. A narrowed limit is a shorter answer rather than the
        same answer with a smaller number attached to it, and a refilled ``region`` is a
        different set of customers — which is what makes a narrowed result something a model
        can act on instead of merely report.
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

    The relationship case. Nothing about the principal appears in the policy that permits
    this: alice reaches ``Project::"orders-eu"`` through her team and division, the order
    reaches it as a parent, and Cedar resolves both walks. bob's chain is the same length and
    ends somewhere else, so the identical call is refused for him.

    Args:
        order_id: Which order to read.

    Returns:
        The order with its customer, its shipping address, its priced lines and its shipment,
        beside ``found: True``, annotated with ``_authz`` in place. ``shipment`` is ``None``
        for an order not yet dispatched. An id the desk does not hold comes back as
        ``found: False`` and nothing else — a miss the desk itself answers rather than raises,
        reported here as what it is.
    """
    order = desk.order_detail(order_id)
    if order is None:
        return {"order_id": order_id, "found": False}
    return {"found": True, **order}


@protect(action='Action::"orders.export"', resource='Tool::"orders"')
def export_orders(fmt: str, scope: str = "open") -> dict[str, object]:
    """Export orders in one format.

    The format the model proposed reaches Cedar as ``context.args.fmt`` *before* any
    per-principal filtering, so the reviewed ``no-pdf-exports`` policy sees what the model
    actually wrote. That gives ``fmt`` two very different fates worth comparing in the output:
    ``xml`` is a grant-level rejection and is refilled with ``csv``, while ``pdf`` is a denial
    from reviewed policy and there is nothing to refill.

    Two of the fields the desk stores on the job are not in this signature, and that is the
    part worth copying. ``requested_by`` is the human the agent is acting for, read from
    :func:`~sentrykit.current_principal` — the ambient principal the provider established for
    this dispatch. The model can neither see that name nor influence it, because it is not an
    argument, so a service layer learns who it is acting for without taking a parameter for it,
    without being handed a request, and without importing a framework to ask. ``region`` is
    :data:`EXPORT_REGION`, since no argument carries one.

    Args:
        fmt: The export format. Bounded per principal.
        scope: Which orders to include. The caller's own business, so it keeps a Python
            default.

    Returns:
        The job's handle and the four fields stored on it, plus ``rows`` — how many orders the
        export covers — annotated with ``_authz`` in place. The stored ``scope`` and ``region``
        are what make the handle worth having: the job remembers the narrowing it was created
        under, so whoever presents the id later can be held to it rather than trusted about it.
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

    Three arguments, decided by several mechanisms at once: ``order_id`` by a pattern with no
    default; ``amount`` by a bounded range in the grant store *and* by a reviewed ``forbid``
    that weighs it against the principal, so the desk limit lifts for an admin; ``region`` by
    an allow-set *and* by a second ``forbid`` that refuses a large refund outside the home
    region. That last one is a rule about the *pair* — each value is fine on its own — and it
    could not be written as a bound on either argument alone.

    A **write**: every permitted call books a new row and the desk allocates its id, so two
    calls are two refunds and a re-run is not idempotent.

    Args:
        order_id: The order being refunded. Must match the principal's pattern.
        amount: How much to refund, in whole currency units.
        region: Which region's desk is refunding.

    Returns:
        The refund as the desk booked it, annotated with ``_authz`` in place: a freshly
        allocated ``refund_id``, the three arguments as policy settled on them, and ``status``
        — ``pending``, because booking a refund and approving one are two calls under two
        different policies. The row carries the *processed* amount, which is the part worth
        noticing: the side effect that really happened is the one policy settled on, not the
        one the model proposed.

    Raises:
        UnknownOrder: When the desk holds no order with that id. Refunding an order that is not
            there is a failed call rather than an answer, which is why the desk raises where a
            read returns nothing, and this body leaves the raise alone: how a domain error is
            rendered is the host's decision, not the authorization layer's.
    """
    return desk.record_refund(order_id=order_id, amount=amount, region=region)


@protect(action='Action::"refunds.approve"', resource='Tool::"refunds"')
def approve_refund(refund_id: str) -> dict[str, object]:
    """Approve a pending refund. Admins only.

    Args:
        refund_id: Which refund to approve.

    Returns:
        The settled refund beside ``found: True``, annotated with ``_authz`` in place and
        including ``approved_by``. That name is the desk's admin of record rather than the
        caller: the desk is never told who called it, and which principal was authorized to
        approve this is in the audit trail, where it cannot drift out of step with the decision
        that permitted it. An id the desk does not hold comes back as ``found: False``.
        Approving an already-approved refund changes nothing and keeps the approver it was
        settled by.
    """
    approval = desk.approve_refund(refund_id)
    if approval is None:
        return {"refund_id": refund_id, "found": False}
    return {"found": True, **approval}
