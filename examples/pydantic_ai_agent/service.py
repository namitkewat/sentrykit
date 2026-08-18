"""The protected callables. Ordinary functions that happen to be governed.

Neither of them takes a ``RunContext``, reads ``deps``, or knows an LLM exists. The principal
reaches them through the ambient context the provider established for the dispatch, which is
what lets these same two functions be called from an agent tool, from a FastAPI route, or from
a nightly job with no change — and what lets the agent example reuse the FastAPI example's
policy verbatim.
"""

from __future__ import annotations

from sentrykit import protect


@protect(action='Action::"orders.search"', resource='Tool::"orders"')
def search_orders(region: str, limit: int) -> dict[str, object]:
    """Search orders in one region.

    Deliberately declares **no Python defaults**. A caller who omits ``region`` or ``limit``,
    or who proposes a value policy will not accept, gets the value their *policy* grants them
    — not one this module picked — and a principal with no default configured for a required
    argument is refused rather than quietly given somebody else's idea of a sensible value.

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

    The format the model proposed reaches Cedar as ``context.args.fmt``, so the
    ``no-pdf-exports`` policy can refuse one value of one argument without anybody's role
    changing — the model proposes, the policy decides.

    Args:
        fmt: The export format.

    Returns:
        The export result, which the engine annotates with ``_authz`` in place.
    """
    return {"fmt": fmt, "exported": 42}
