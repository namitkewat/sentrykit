"""The protected callables — ordinary functions that know nothing about Flask.

One decorator, N context providers — and this module is where that shows: there is no request
object here, no header, no framework import. The principal arrives ambiently, established by
:class:`~sentrykit.integrations.flask.FlaskProvider` at the boundary, so the same three
functions would work unchanged behind FastAPI, an MCP tool, or a cron job.

:func:`summarize_orders` is deliberately *not* a route. It is called from inside a plain
handler and is governed anyway, which is the property that makes this an action-layer library
rather than a routing concern.
"""

from __future__ import annotations

from sentrykit import protect


@protect(action='Action::"orders.search"', resource='Tool::"orders"')
def search_orders(region: str, limit: int) -> dict[str, object]:
    """Search orders in one region.

    Neither parameter has a Python default, on purpose: the only thing that can fill them when
    the caller omits them is a policy default from Alice's argument constraints. If default
    injection were not working, this call would fail on a missing argument rather than quietly
    running with a value nobody authorized.

    Args:
        region: The region to search. Constrained to the caller's allowed set.
        limit: How many orders to return. Constrained to the caller's maximum.

    Returns:
        The effective arguments and the matching orders, so the caller can see what policy
        actually let through.
    """
    return {
        "region": region,
        "limit": limit,
        "orders": [f"order-{n}" for n in range(min(limit, 3))],
    }


@protect(action='Action::"orders.export"', resource='Tool::"orders"')
def export_orders(fmt: str) -> dict[str, object]:
    """Export orders in one format.

    Gated by role *and* by argument: the ``no-pdf-exports`` forbid reads ``context.args.fmt``,
    so ``fmt="pdf"`` is refused before this body runs even for a caller who may otherwise
    export.

    Args:
        fmt: The export format.

    Returns:
        The format used and the number of rows exported.
    """
    return {"fmt": fmt, "exported": 42}


@protect(action='Action::"orders.summarize"', resource='Tool::"orders"')
def summarize_orders() -> dict[str, object]:
    """Summarize the open orders.

    The protected non-route callable, invoked from inside an unprotected handler. Its
    authorization comes entirely from the ambient context the provider established.

    Returns:
        A one-line summary.
    """
    return {"summary": "3 open orders"}
