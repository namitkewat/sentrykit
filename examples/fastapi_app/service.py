"""The protected callables. Ordinary functions that happen to be governed.

None of them takes a request, reads a header, or knows a web framework exists. The principal
reaches them through the ambient context the provider established at the boundary, which is
what lets the same three functions be called from a route, from a background job, or from an
MCP tool with no change.
"""

from __future__ import annotations

from sentrykit import protect


@protect(action='Action::"orders.search"', resource='Tool::"orders"')
def search_orders(region: str, limit: int) -> dict[str, object]:
    """Search orders in one region.

    Deliberately declares **no Python defaults**. A caller who omits ``region`` or ``limit``
    gets the value their *policy* grants them, not one this module picked — and a principal
    with no default configured for a required argument is refused rather than quietly given
    somebody else's idea of a sensible value.

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
    refuse one value of an argument without the caller's role changing.

    Args:
        fmt: The export format.

    Returns:
        The export result.
    """
    return {"fmt": fmt, "exported": 42}


@protect(action='Action::"orders.summarize"', resource='Tool::"orders"')
def summarize_orders() -> dict[str, object]:
    """Summarize open orders.

    The protected **non-route** callable, invoked from inside a handler that is itself
    unguarded. It is the demonstration that governance follows the *call*, not the URL.

    Returns:
        The summary.
    """
    return {"summary": "3 open orders"}
