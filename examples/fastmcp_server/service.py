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

from sentrykit import protect


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
        The desk's status.
    """
    return {"desk": "orders", "open": True, "queue": 3}


# Protected, and NOT registered as a tool anywhere in this example. A model cannot propose it;
# only :func:`brief_orders` reaches it. It is still gated, still filtered, and still audited.
#
# Watch in the audit trail: calling ``brief_orders`` writes TWO records — the outer one first,
# before the body runs, then this one.
@protect(action='Action::"orders.summarize"', resource='Tool::"orders"')
def summarize_orders() -> dict[str, object]:
    """Summarize the desk's open orders.

    Returns:
        The summary.
    """
    return {"open": 3, "closed": 11}


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
    """
    return {"brief": summarize_orders()}


# Default injection and per-principal argument filtering, both on one call.
#
# ``region`` and ``limit`` declare no Python defaults so a policy default is reachable; the
# model may propose neither and get alice's ``eu``/``10`` or dana's ``eu``/``25``. ``status``
# does declare one, because which slice of orders to look at is the caller's own business.
#
# Watch in the envelope: ``defaults_applied`` holds what the caller never chose, ``rejected``
# holds what was refused and why, and ``processed`` holds what sentrykit actually passed. A
# value that appears in both ``rejected`` and ``defaults_applied`` was rejected and refilled —
# the refill is the principal's own default, never the bound that refused it.
@protect(action='Action::"orders.search"', resource='Tool::"orders"')
def search_orders(region: str, limit: int, status: str = "open") -> dict[str, object]:
    """Search orders in one region.

    Args:
        region: Which region to search. Constrained per principal.
        limit: How many orders to return. Bounded per principal, and by the reviewed ceiling.
        status: Which orders to look at. The caller's own choice; policy says nothing about it.

    Returns:
        The search result, which the engine annotates with ``_authz`` in place.
    """
    return {
        "region": region,
        "limit": limit,
        "status": status,
        "orders": [f"order-{n}" for n in range(min(limit, 3))],
    }


# The relationship tool. Nothing in this signature, in this body, or in the policy that
# authorizes it mentions a team or a division. Alice reaches it over four hops and Cedar walks
# every one of them; bob's chain is exactly as long and lands on the other project.
#
# Watch in the envelope: ``resource`` is ``Order::"o-1"`` for both principals and ``decision``
# differs. At ``debug`` verbosity, alice's ``determining_policies`` names
# ``project-members-may-read-project-orders`` — a policy that mentions neither of them.
@protect(action='Action::"orders.read"', resource='Order::"o-1"')
def read_order(order_id: str) -> dict[str, object]:
    """Read one order.

    Args:
        order_id: Which order to read.

    Returns:
        The order.
    """
    return {"order_id": order_id, "total": "42.00", "currency": "EUR"}


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

    Args:
        fmt: The export format. Decided by policy, so it declares no Python default.
        scope: Which orders to export. The caller's own choice.

    Returns:
        The export result.
    """
    return {"fmt": fmt, "scope": scope, "exported": 42}


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

    Args:
        order_id: The order to refund. Alice's grant constrains its shape and gives it no
            default, so a malformed one is refused rather than replaced.
        amount: How much. Bounded per principal, and separately by the reviewed desk limit.
        region: Where the refund is booked.

    Returns:
        The refund.
    """
    return {"order_id": order_id, "amount": amount, "region": region, "refund_id": "rf-1"}


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
        The approval.
    """
    return {"refund_id": refund_id, "approved": True}
