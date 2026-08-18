"""A minimal MCP tool server wired to sentrykit: the model proposes, the policy decides.

Run it with `pixi run -e agent run-mcp`. At a terminal it drives itself in-process and prints
the narrative below; with its stdin wired to a real MCP client it serves over stdio like any
other server.

Three tools cover the three things an agent boundary has to get right:

* `search_orders` — *default injection* and *argument filtering*. The model may call it with
  no arguments at all; the region and the limit it gets back came from alice's grants and from
  nowhere else. Propose `region="cn"` and the value is dropped and replaced, with the
  substitution recorded in the `_authz` envelope rather than hidden.
* `export_orders` — a `forbid` that reads the proposed argument. `fmt="pdf"` is refused for
  everyone, including the auditor who may otherwise export.
* `read_order` — **the showcase.** The policy that authorizes it,
  `project-members-may-read-project-orders`, names only `Project::"orders-eu"` at both ends.
  Alice reaches it over four hops —
  `User::"alice" -> Team::"eu-support" -> Division::"emea" -> Project::"orders-eu"` — and the
  order reaches it over its own edge. **Cedar resolves that chain; nothing here does.** No
  application code walks it, no model infers it, and `create_server(severed=True)` removes one
  edge, changes nothing else, and watches the access disappear.

## What the agent boundary adds

A web client already knows which URLs exist, so an HTTP provider has one job: establish
context. An MCP server has a second one — it tells the model what it may *attempt*. So
`tools/list` is filtered per principal: alice is shown `read_order`, bob is not.

That filtering is **never** the enforcement. `tools/call` runs the identical decision, so a
client that ignores the manifest and calls `read_order` by name is refused just the same. The
self-drive below asserts both halves together, because a filter that were *also* the
enforcement would be a hole the moment a client skipped `tools/list`.

## Identity

The caller names themselves in the request's `_meta`, under `x-sentrykit-principal`. That is
the one carrier every MCP transport has — stdio, in-memory and HTTP alike — which is why this
example is drivable with no socket. It is an authentication *stub*, exactly as the `x-user`
header is in the FastAPI example: a real deployment passes `identify=` and reaches for
`mcp.server.mcpserver.authenticated_principal`, which resolves the OAuth identity from the
ambient access token.

Nothing is configured at import time. `configure()` and `install()` are process-wide, and a
module that ran them merely because it was imported would reconfigure any host that imported
it — including the test suite.
"""

from __future__ import annotations

import sys
from typing import Any

import anyio
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

from examples.fastmcp_server.policy import POLICY_TEXT, build_grants
from examples.fastmcp_server.service import export_orders, read_order, search_orders
from sentrykit import configure, install
from sentrykit.integrations.fastmcp import FastMCPProvider, governed_tool, protect_server

PRINCIPAL_KEY = "x-sentrykit-principal"
"""The ``_meta`` key this example's callers name themselves in."""


def create_server(*, severed: bool = False) -> MCPServer:
    """Wire settings, grants, policy, the provider and the three tools into one server.

    Args:
        severed: Build the graph with ``Team::"eu-support"`` detached from its division, and
            nothing else changed. Alice can still search — that gate is a role — and can no
            longer read ``Order::"o-1"``.

    Returns:
        The server, with sentrykit's middleware installed.
    """
    # ``verbose`` so the ``_authz`` envelope actually carries processed values, applied
    # defaults and rejection reasons. A production service would leave this at ``summary``.
    configure(verbosity="verbose")

    store = build_grants(severed=severed)
    provider = FastMCPProvider(grants=store)
    install(POLICY_TEXT, grant_store=store, context_provider=provider)

    server = MCPServer("sentrykit-orders")
    # ``governed_tool`` and never a bare ``@server.tool()``: it advertises the arguments policy
    # can supply as omittable, so the model may propose none of them, and it lets a refusal out
    # of the tool body carrying its envelope instead of being flattened into an error string.
    # The callables are already ``@protect``-ed in service.py, so it registers them as they are.
    governed_tool(server)(search_orders)
    governed_tool(server)(export_orders)
    governed_tool(server)(read_order)

    protect_server(server, provider=provider)
    return server


def _structured(result: CallToolResult) -> dict[str, Any]:
    """Return a tool result's structured content, refusal or not.

    Args:
        result: What the client got back.

    Returns:
        The structured payload, or an empty mapping when the result carries none.
    """
    content = result.structured_content
    return dict(content) if isinstance(content, dict) else {}


async def _narrate(server: MCPServer, principal: str) -> None:
    """Drive one principal through every tool and print what policy did.

    Args:
        server: The server to drive, in-process.
        principal: Who to call as, carried in ``_meta``.
    """
    meta = {PRINCIPAL_KEY: principal}
    async with Client(server) as client:
        manifest = await client.list_tools(meta=meta)
        print(f"\n=== {principal} ===")
        print(f"  tools/list  -> {[tool.name for tool in manifest.tools]}")

        # No arguments at all: whatever comes back was decided by policy.
        search = await client.call_tool("search_orders", {}, meta=meta)
        print(f"  search()    -> {_structured(search)}")

        rejected = await client.call_tool("search_orders", {"region": "cn", "limit": 5}, meta=meta)
        print(f"  search(cn)  -> {_structured(rejected)}")

        # Called by name whether or not the manifest advertised it, which is the point.
        read = await client.call_tool("read_order", {"order_id": "o-1"}, meta=meta)
        print(f"  read(o-1)   -> {_structured(read)}")

        export = await client.call_tool("export_orders", {"fmt": "pdf"}, meta=meta)
        print(f"  export(pdf) -> {_structured(export)}")


async def demonstrate() -> None:
    """Drive the server in-process, as a client would, and print the whole story.

    No sockets and no model: :class:`mcp.Client` accepts an :class:`~mcp.server.mcpserver.
    MCPServer` directly and speaks to it over an in-memory transport, which is also how the
    integration tests run.
    """
    await _narrate(create_server(), "alice")
    await _narrate(create_server(), "bob")

    # One edge removed, nothing else changed. Alice keeps her team and her role; the policy
    # keeps its wording; the read stops being authorized and the tool stops being advertised.
    print('\n=== alice, with Team::"eu-support" detached from Division::"emea" ===')
    severed = create_server(severed=True)
    meta = {PRINCIPAL_KEY: "alice"}
    async with Client(severed) as client:
        manifest = await client.list_tools(meta=meta)
        print(f"  tools/list  -> {[tool.name for tool in manifest.tools]}")
        read = await client.call_tool("read_order", {"order_id": "o-1"}, meta=meta)
        print(f"  read(o-1)   -> {_structured(read)}")


def main() -> None:
    """Serve over stdio, or self-drive when a human ran this at a terminal.

    A stdio server speaks JSON-RPC on stdin, which nobody types by hand, so an interactive
    terminal gets the in-process narrative instead. Piped stdin — which is what an MCP client
    gives a server it spawned — gets a real server.
    """
    if sys.stdin is not None and sys.stdin.isatty():
        anyio.run(demonstrate)
        return
    create_server().run()


if __name__ == "__main__":
    main()
