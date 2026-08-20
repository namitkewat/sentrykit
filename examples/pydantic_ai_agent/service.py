"""The protected callables. Ordinary functions that happen to be governed.

Run the example with `pixi run -e agent run-agent`; this module is the half that does the work
once the decision has been made.

Not one of these takes a ``RunContext``, reads ``deps``, or knows an LLM exists. The principal
reaches them through the ambient context the provider established for the dispatch, which is
what lets the same functions be called from an agent tool, from an HTTP route, or from a
nightly job with no change.

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

from sentrykit import protect


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
        The desk state, which the engine annotates with ``_authz`` in place.
    """
    return {"desk": "orders", "open": True}


@protect(action='Action::"orders.summarize"', resource='Tool::"orders"')
def summarize_orders() -> dict[str, object]:
    """Summarize the desk's open orders.

    Deliberately **not registered as a tool**. No model is ever offered it and no model can
    propose it — and it is still protected, because the gate is on the *call*, not on the tool
    registration. :func:`brief_orders` reaches it from inside a tool body and it is decided
    there on its own merits.

    Returns:
        The summary, which the engine annotates with ``_authz`` in place.
    """
    return {"open": 3, "closed": 11}


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
        A summary of the desk, which the engine annotates with ``_authz`` in place. The nested
        result carries its own ``_authz`` under ``brief``.
    """
    return {"brief": summarize_orders()}


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
        The search result, which the engine annotates with ``_authz`` in place.
    """
    return {
        "region": region,
        "limit": limit,
        "status": status,
        "orders": [f"order-{n}" for n in range(min(limit, 3))],
    }


@protect(action='Action::"orders.read"', resource='Order::"o-1"')
def read_order(order_id: str) -> dict[str, object]:
    """Read one order.

    The relationship case. Nothing about the principal appears in the policy that permits
    this: alice reaches ``Project::"orders-eu"`` through her team and division, the order
    reaches it as a parent, and Cedar resolves both walks. bob's chain is the same length and
    ends somewhere else, so the identical call is refused for him.

    Args:
        order_id: Which order to read.

    Returns:
        The order, which the engine annotates with ``_authz`` in place.
    """
    return {"order_id": order_id, "project": "orders-eu", "total": 120}


@protect(action='Action::"orders.export"', resource='Tool::"orders"')
def export_orders(fmt: str, scope: str = "open") -> dict[str, object]:
    """Export orders in one format.

    The format the model proposed reaches Cedar as ``context.args.fmt`` *before* any
    per-principal filtering, so the reviewed ``no-pdf-exports`` policy sees what the model
    actually wrote. That gives ``fmt`` two very different fates worth comparing in the output:
    ``xml`` is a grant-level rejection and is refilled with ``csv``, while ``pdf`` is a denial
    from reviewed policy and there is nothing to refill.

    Args:
        fmt: The export format. Bounded per principal.
        scope: Which orders to include. The caller's own business, so it keeps a Python
            default.

    Returns:
        The export result, which the engine annotates with ``_authz`` in place.
    """
    return {"fmt": fmt, "scope": scope, "exported": 42}


@protect(action='Action::"refunds.issue"', resource='Tool::"refunds"')
def issue_refund(order_id: str, amount: int, region: str) -> dict[str, object]:
    """Issue a refund against an order.

    Three arguments, decided by several mechanisms at once: ``order_id`` by a pattern with no
    default; ``amount`` by a bounded range in the grant store *and* by a reviewed ``forbid``
    that weighs it against the principal, so the desk limit lifts for an admin; ``region`` by
    an allow-set *and* by a second ``forbid`` that refuses a large refund outside the home
    region. That last one is a rule about the *pair* — each value is fine on its own — and it
    could not be written as a bound on either argument alone.

    Args:
        order_id: The order being refunded. Must match the principal's pattern.
        amount: How much to refund, in whole currency units.
        region: Which region's desk is refunding.

    Returns:
        The refund, which the engine annotates with ``_authz`` in place.
    """
    return {"refund_id": "rf-1", "order_id": order_id, "amount": amount, "region": region}


@protect(action='Action::"refunds.approve"', resource='Tool::"refunds"')
def approve_refund(refund_id: str) -> dict[str, object]:
    """Approve a pending refund. Admins only.

    Args:
        refund_id: Which refund to approve.

    Returns:
        The approval, which the engine annotates with ``_authz`` in place.
    """
    return {"refund_id": refund_id, "approved": True}
