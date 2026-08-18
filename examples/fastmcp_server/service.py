"""The protected callables. Ordinary functions that happen to be governed.

None of them takes a request, reads a header, inspects ``_meta``, or knows that a model is on
the other end. The principal reaches them through the ambient context the provider established
at the MCP boundary, which is what lets the same three functions be called from a tool
dispatch, from an HTTP route, or from a background job with no change.

They are registered on the server through
:func:`~sentrykit.integrations.fastmcp.governed_tool`, which takes them exactly as they are —
already protected, still directly callable from anywhere else in the program — and adds the two
layers an MCP boundary needs: an omittable-argument shim, so the model can propose nothing and
let policy decide, and a translator that carries a refusal out of the tool body with its
envelope intact. A bare ``@server.tool()`` over ``@protect`` would lose that envelope.
"""

from __future__ import annotations

from sentrykit import protect


@protect(action='Action::"orders.search"', resource='Tool::"orders"')
def search_orders(region: str, limit: int) -> dict[str, object]:
    """Search orders in one region.

    Deliberately declares **no Python defaults**. A caller who omits ``region`` or ``limit``
    gets the value their *policy* grants them, not one this module picked — and a principal
    with no default configured for a required argument is refused rather than quietly given
    somebody else's idea of a sensible value. When a model calls this with no arguments at
    all, every value in the answer came from policy.

    Args:
        region: Which region to search. Constrained per principal.
        limit: How many orders to return. Capped per principal.

    Returns:
        The search result, which the engine annotates with ``_authz`` in place.
    """
    return {
        "region": region,
        "limit": limit,
        "orders": [f"order-{n}" for n in range(min(limit, 3))],
    }


@protect(action='Action::"orders.export"', resource='Tool::"orders"')
def export_orders(fmt: str) -> dict[str, object]:
    """Export orders in one format.

    The format reaches Cedar as ``context.args.fmt``, so the ``no-pdf-exports`` policy can
    refuse one *value* of an argument without the caller's role changing. This is the shape
    that matters most with a model on the other end: the model proposes ``fmt="pdf"`` in
    perfectly good faith, and the refusal is a policy fact rather than a prompt instruction.

    Args:
        fmt: The export format.

    Returns:
        The export result.
    """
    return {"fmt": fmt, "exported": 42}


@protect(action='Action::"orders.read"', resource='Order::"o-1"')
def read_order(order_id: str) -> dict[str, object]:
    """Read one order — the multi-hop tool.

    Nothing in this signature, in this body, or in the policy that authorizes it mentions a
    team or a division. Alice may call it because
    ``User::"alice" -> Team::"eu-support" -> Division::"emea" -> Project::"orders-eu"`` and
    ``Order::"o-1" -> Project::"orders-eu"``, and Cedar walks both halves of that on its own.
    Bob's chain is the same length and lands on the other project, so he is refused — and the
    tool is not even advertised to him.

    Args:
        order_id: Which order to read.

    Returns:
        The order.
    """
    return {"order_id": order_id, "total": "42.00", "currency": "EUR"}
