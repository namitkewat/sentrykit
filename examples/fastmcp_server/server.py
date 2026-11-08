"""A governed MCP tool server: the model proposes, the policy decides.

Run it with `pixi run -e agent run-mcp`. At a terminal it drives itself in-process and prints
the whole flow table below; with its stdin wired to a real MCP client it serves over stdio like
any other server.

## What this file wires

`create_server()` is five lines of wiring and nothing else: settings, the grant store, the
reviewed policy *directory*, the context provider, and one `governed_tool` registration per
tool. The policy is not a string in this module — it is `policies/*.cedar`, loaded by a
`FilesystemPolicySource`, because policy logic belongs in files that get reviewed.

Seven tools, and one protected callable that is deliberately **not** a tool:

* `desk_status` — the bare `@protect`. Its action id is the callable's import path.
* `brief_orders` — calls `summarize_orders()`, which is protected and unregistered. Two
  decisions, two audit records, one dispatch.
* `search_orders` — default injection, per-principal filtering, and the reviewed argument
  ceiling that bounds everybody.
* `read_order` — the relationship. Four hops, resolved by Cedar, named by no policy.
* `export_orders` — a `forbid` that reads the proposed argument, over a deny-set that refills.
* `issue_refund` — an unconditional permit under two narrow `forbid`s: one reads an argument
  *together with* the principal, the other reads two arguments against each other.
* `approve_refund` — the admin gate, with no arguments involved at all.

## The tools query a real database

Every protected callable in `service.py` reads or writes a seeded SQLite orders desk, so a
narrowed argument selects different *rows* rather than putting a different number in a report:
a `limit` refilled with 10 comes back with ten real orders, and a `region` refilled from the
caller's own grant comes back with other customers and other totals. The self-drive resets that
desk before it starts, so the refund and export ids it prints are the same on every run.
`create_server()` resets nothing — a server that emptied its database on startup would be a
poor example of anything.

## What the agent boundary adds

A web client already knows which URLs exist, so an HTTP provider has one job: establish
context. An MCP server has a second one — it tells the model what it may *attempt*. So
`tools/list` is filtered per principal: alice is shown `read_order`, bob is not.

That filtering is **never** the enforcement. `tools/call` runs the identical decision, so a
client that ignores the manifest and calls `read_order` by name is refused just the same. The
self-drive below shows both halves together, because a filter that were *also* the enforcement
would be a hole the moment a client skipped `tools/list`.

## Identity

The caller names themselves in the request's `_meta`, under `x-sentrykit-principal`. That is
the one carrier every MCP transport has — stdio, in-memory and HTTP alike — which is why this
example is drivable with no socket. It is an authentication *stub*, exactly as the `x-user`
header is in a web example: a real deployment passes `identify=` and reaches for
`mcp.server.mcpserver.authenticated_principal`, which resolves the OAuth identity from the
ambient access token.

## The optional live model

The server is model-agnostic and stays that way: a server exposes governed tools, and a client
drives it. The last section of the self-drive is the client half — it takes the *filtered*
manifest, hands those schemas to the best model within reach, and dispatches whatever the model
proposed back through the same governed path. `examples.models` is what picks that model: a
frontier one over [OpenRouter](https://openrouter.ai) when an `OPENROUTER_API_KEY` is set — in
the environment, or in the untracked `.env` at the repository root — otherwise a local
[Ollama](https://ollama.com) daemon with a tool-capable model. When neither answers, the
deterministic drive above it is the whole demonstration, and every authorization outcome is
identical whichever tier answered, because the decision is made from the principal and the
proposed arguments and never from which model proposed them.

Nothing in `create_server()` probes for a model. Only the self-drive does, so importing this
module never touches a network.

Nothing is configured at import time either. `configure()` and `install()` are process-wide,
and a module that ran them merely because it was imported would reconfigure any host that
imported it — including a test suite.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

import anyio
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, ListToolsResult

from examples import desk, models
from examples.fastmcp_server.policy import POLICY_DIR, build_grants
from examples.fastmcp_server.service import (
    approve_refund,
    brief_orders,
    desk_status,
    export_orders,
    issue_refund,
    read_order,
    search_orders,
)
from sentrykit import configure, install
from sentrykit.integrations.fastmcp import FastMCPProvider, governed_tool, protect_server
from sentrykit.stores.filesystem import FilesystemPolicySource
from sentrykit.stores.memory import InMemoryAuditSink

PRINCIPAL_KEY = "x-sentrykit-principal"
"""The ``_meta`` key this example's callers name themselves in."""

PRINCIPALS = ("alice", "bob", "dana")
"""Everyone the self-drive acts as, in the order the manifests are printed."""


def create_server(
    *, severed: bool = False, audit_sink: InMemoryAuditSink | None = None
) -> MCPServer:
    """Wire settings, grants, the reviewed policy directory, the provider and the tools.

    Args:
        severed: Build the graph with ``Team::"eu-support"`` detached from its division, and
            nothing else changed. Alice can still search — that gate is a role — and can no
            longer read ``Order::"ord-0003"``.
        audit_sink: Where decision records go. ``None`` means no audit trail, which is the
            right default for a library: nothing should start writing files merely because it
            was imported.

    Returns:
        The server, with sentrykit's middleware installed.
    """
    # ``verbose`` so the ``_authz`` envelope actually carries processed values, applied
    # defaults and rejection reasons. A production service would leave this at ``summary``.
    configure(verbosity="verbose")

    store = build_grants(severed=severed)
    provider = FastMCPProvider(grants=store)
    # ``policy_source=`` rather than a policy string. The two are mutually exclusive, and this
    # is the shape a real deployment has: reviewed Cedar files on disk, grants in a store.
    install(
        policy_source=FilesystemPolicySource(POLICY_DIR),
        grant_store=store,
        context_provider=provider,
        audit_sink=audit_sink,
    )

    server = MCPServer("sentrykit-orders")
    # ``governed_tool`` and never a bare ``@server.tool()``: it advertises the arguments policy
    # can supply as omittable, so the model may propose none of them, and it lets a refusal out
    # of the tool body carrying its envelope instead of being flattened into an error string.
    # The callables are already ``@protect``-ed in service.py, so it registers them as they
    # are — and hands each one back unchanged, still directly callable from the rest of the
    # program.
    for tool in (
        desk_status,
        brief_orders,
        search_orders,
        read_order,
        export_orders,
        issue_refund,
        approve_refund,
    ):
        governed_tool(server)(tool)

    # ``summarize_orders`` is protected and is registered NOWHERE. It is reached only from
    # inside ``brief_orders``, and it is decided and audited on its own terms all the same.

    protect_server(server, provider=provider)
    return server


# --- reading a result ----------------------------------------------------------------------


def _structured(result: CallToolResult) -> dict[str, Any]:
    """Return a tool result's structured content, refusal or not.

    Args:
        result: What the client got back.

    Returns:
        The structured payload, or an empty mapping when the result carries none.
    """
    content = result.structured_content
    return dict(content) if isinstance(content, dict) else {}


def _outcome(result: CallToolResult) -> str:
    """Summarize one dispatch in a single line: what policy did, and why.

    Three refusal shapes reach here and they are not the same kind of refusal. ``AuthzDenied``
    is the *gate* refusing the call, so its ``_authz`` names the action and the resource that
    were denied. ``NoValidArguments`` and ``DefaultUnavailable`` come from the argument layer
    *after* the gate said yes, so their ``_authz`` is built from the refusal itself and names
    no action and no resource — there was no denied decision to name. What it does carry is
    which arguments were refused and what the principal may pass instead, which is what a
    caller needs in order to retry.

    Args:
        result: What the client got back.

    Returns:
        One of ``allowed``, ``allowed  narrowed: …``, ``allowed  defaulted: …``,
        ``denied: <reason>``, or ``<ErrorName>: <detail>``.
    """
    body = _structured(result)
    authz = body.get("_authz")
    envelope: dict[str, Any] = authz if isinstance(authz, dict) else {}

    if result.is_error:
        name = body.get("error", "Error")
        detail = envelope.get("reason") or body.get("detail") or ""
        return f"denied: {detail}" if name == "AuthzDenied" else f"{name}: {detail}"

    rejected = envelope.get("rejected") or []
    defaults = dict(envelope.get("defaults_applied") or {})
    notes: list[str] = []
    for item in rejected:
        name = item.get("name")
        rule, policy = item.get("rule"), item.get("policy", "-")
        if name in defaults:
            # Reject-and-refill: the proposal was refused and the principal's own default
            # filled the gap. The result is that default — not the bound that refused it.
            notes.append(
                f"narrowed: {name}={item.get('value')!r} rejected by {rule}/{policy}"
                f" -> refilled with {defaults.pop(name)!r}"
            )
        else:
            notes.append(f"dropped: {name}={item.get('value')!r} rejected by {rule}/{policy}")
    if defaults:
        omitted = ", ".join(f"{key}={value!r}" for key, value in defaults.items())
        notes.append(f"defaulted: {omitted}")
    return "allowed" + ("  " + "; ".join(notes) if notes else "")


# --- the flow table ------------------------------------------------------------------------

# One boundary fact worth knowing before reading the table. mcp validates a proposal against
# the advertised schema before dispatch and **materializes the schema's defaults**, so a
# parameter carrying a Python default — ``status``, ``scope`` — arrives at the decorator as a
# proposed argument even when the caller named none. Flows 5 and 11 pass it explicitly anyway,
# because a reader should be able to see what was proposed; and flow 12, which needs a call
# where *nothing* the caller sent survives, uses a tool whose every parameter is omittable.
# An omittable one is advertised as nullable, and the shim reads that ``null`` as *not
# proposed* and drops it — which is how an omission stays an omission across the boundary.

FLOWS: tuple[tuple[str, str, dict[str, Any], str], ...] = (
    ("alice", "desk_status", {}, "the bare @protect; the action id is the import path"),
    ("alice", "brief_orders", {}, "calls protected summarize_orders(): 2 decisions, 2 records"),
    ("alice", "search_orders", {}, "nothing proposed, so every value came from policy"),
    (
        "alice",
        "search_orders",
        {"region": "cn", "limit": 5},
        "allow-set reject-and-refill; limit=5 was within her bound and stands",
    ),
    (
        "alice",
        "search_orders",
        {"limit": 500, "status": "open"},
        "three arguments at once: one refilled, one defaulted, one untouched",
    ),
    (
        "dana",
        "search_orders",
        {"limit": 500, "status": "open"},
        "the reviewed ceiling is her only bound; she gets her own default of 25",
    ),
    (
        "alice",
        "read_order",
        {"order_id": "ord-0003"},
        "four hops; the permit names only the project",
    ),
    (
        "bob",
        "read_order",
        {"order_id": "ord-0003"},
        "same chain length, other project; no permit reaches him, so nothing is named",
    ),
    ("bob", "export_orders", {"fmt": "csv"}, "plainly allowed"),
    ("bob", "export_orders", {"scope": "open"}, "fmt omitted, so his default answers for it"),
    (
        "bob",
        "export_orders",
        {"fmt": "xml", "scope": "open"},
        "deny-set reject-and-refill; scope survived, so the call proceeds",
    ),
    (
        "alice",
        "issue_refund",
        {"order_id": "refund-me", "amount": 900},
        "narrowing refines a proposal, it does not rescue one: nothing she sent survived",
    ),
    ("bob", "export_orders", {"fmt": "pdf"}, "a forbid reading the raw proposal, before filtering"),
    ("bob", "search_orders", {}, "the role gate; nothing permitted it, so nothing is named"),
    (
        "alice",
        "issue_refund",
        {"order_id": "ord-0007", "amount": 100, "region": "uk"},
        "fine apart, fine together",
    ),
    (
        "alice",
        "issue_refund",
        {"order_id": "ord-0007", "amount": 750, "region": "uk"},
        "refused purely by the RELATIONSHIP between two arguments",
    ),
    (
        "alice",
        "issue_refund",
        {"order_id": "ord-0007", "amount": 900, "region": "eu"},
        "the gate said yes at 900; her own grant then rejected it and refilled with 50",
    ),
    (
        "alice",
        "issue_refund",
        {"order_id": "ord-0007", "amount": 5000, "region": "eu"},
        "the desk limit: an argument decided TOGETHER WITH the principal, by a named forbid",
    ),
    (
        "dana",
        "issue_refund",
        {"order_id": "ord-0007", "amount": 5000, "region": "eu"},
        "the same call, exempted from that forbid by its last clause: dana is an admin",
    ),
    (
        "alice",
        "issue_refund",
        {"order_id": "refund-me", "amount": 100, "region": "eu"},
        "pattern rejected with no default to refill from; the gate had already said yes",
    ),
    ("dana", "approve_refund", {"refund_id": "rf-0002"}, "the admin action"),
    ("alice", "approve_refund", {"refund_id": "rf-0002"}, "the same call, the other principal"),
)
"""Every flow the example demonstrates: principal, tool, proposal, and what it teaches."""


def _call_text(tool: str, arguments: dict[str, Any]) -> str:
    """Render one proposal the way a reader would write it.

    Args:
        tool: The tool name.
        arguments: What was proposed.

    Returns:
        ``tool(name=value, …)``.
    """
    return f"{tool}({', '.join(f'{k}={v!r}' for k, v in arguments.items())})"


async def _manifests(client: Client) -> None:
    """Print `tools/list` as each principal is answered it, and as nobody is answered it.

    Args:
        client: A connected client.
    """
    print("\n--- tools/list is answered per principal ---")
    for principal in (*PRINCIPALS, None):
        meta = {PRINCIPAL_KEY: principal} if principal else {}
        manifest = await client.list_tools(meta=meta)
        label = principal or "(anonymous)"
        print(f"  {label:<12} {[tool.name for tool in manifest.tools]}")
    # A tool is hidden from a principal exactly when the GATE would refuse it. `issue_refund`
    # is in alice's and dana's manifests and absent from bob's: the permit authorizing it is
    # unconditional, so a probe that proposes nothing still reaches it, and neither forbid
    # fires on a probe that proposed no `amount`. Bob has no permit for the action at all.
    #
    # Neither probe is a clean allow, though: `order_id` is required and has no default, so
    # both raise `DefaultUnavailable`. That is the ARGUMENT layer answering after the gate said
    # yes, and it deliberately hides nothing — every tool with a required argument would vanish
    # from every manifest if it did.
    print("  (a tool is hidden exactly when the GATE would refuse a no-argument probe of it)")


async def _flows(client: Client) -> None:
    """Run the whole flow table and print one aligned line per flow.

    Args:
        client: A connected client.
    """
    print("\n--- flows ---")
    print(f"  {'#':>2}  {'principal':<9}  {'call':<62}  outcome")
    for index, (principal, tool, arguments, lesson) in enumerate(FLOWS, start=1):
        result = await client.call_tool(tool, arguments, meta={PRINCIPAL_KEY: principal})
        print(
            f"  {index:>2}  {principal:<9}  {_call_text(tool, arguments):<62}  {_outcome(result)}"
        )
        print(f"      {'':<9}  {lesson}")


async def _severed_comparison() -> None:
    """Remove one entity edge, change nothing else, and print what alice lost.

    The relationship *was* the authorization, so the tool disappears from her manifest and the
    dispatch is refused — while the role gate she also holds is untouched.
    """
    print('\n--- the same policy, with Team::"eu-support" detached from Division::"emea" ---')
    meta = {PRINCIPAL_KEY: "alice"}
    async with Client(create_server(severed=True)) as client:
        manifest = await client.list_tools(meta=meta)
        print(f"  tools/list             {[tool.name for tool in manifest.tools]}")
        read = await client.call_tool("read_order", {"order_id": "ord-0003"}, meta=meta)
        print(f"  read_order(ord-0003)        {_outcome(read)}")
        search = await client.call_tool("search_orders", {}, meta=meta)
        print(f"  search_orders()        {_outcome(search)}   <- her role gate is untouched")


async def _nested_records(client: Client, sink: InMemoryAuditSink) -> None:
    """Dispatch `brief_orders` once and print exactly the records that dispatch wrote.

    Two protected callables in one dispatch means two decisions and two records. The outer one
    is written **before** the body runs, which is why it comes first — the gate refuses a side
    effect before it happens, so its record cannot wait for the call to finish. Had the inner
    decision been a refusal, its ``AuthzDenied`` would have travelled out through
    ``brief_orders`` unchanged; nothing rewrites it on the way.

    Args:
        client: A connected client.
        sink: The sink the server was wired with.
    """
    print("\n--- one dispatch of brief_orders, two audit records ---")
    # Marked, because a ``tools/list`` probe decides every tool too and so writes records of
    # its own. Only what this one dispatch appended is printed.
    mark = len(sink.records)
    await client.call_tool("brief_orders", {}, meta={PRINCIPAL_KEY: "alice"})
    for record in sink.records[mark:]:
        print(
            f"  seq {record.sequence:<3} {record.action:<28} {record.decision:<6}"
            f" {record.outcome:<10} callable={record.callable_name}"
        )
    print("  (summarize_orders is protected and registered as no tool; only brief_orders is)")


# --- the optional live-model section -------------------------------------------------------


def _declarations(manifest: ListToolsResult) -> list[dict[str, Any]]:
    """Convert a filtered MCP manifest into the tool-declaration form both live tiers read.

    The manifest is already per-principal, so the model is only ever offered tools this caller
    could actually invoke. That is a usability affordance and not the enforcement: whatever it
    proposes is dispatched through the same governed path and decided again.

    Args:
        manifest: What ``tools/list`` answered for this principal.

    Returns:
        ``tools=`` declarations in OpenAI's ``{"type": "function", …}`` shape, which the
        frontier tier and the local daemon both accept unchanged.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": (tool.description or tool.name).strip().splitlines()[0],
                "parameters": tool.input_schema,
            },
        }
        for tool in manifest.tools
    ]


async def _live_model(client: Client, choice: models.Choice, principal: str, ask: str) -> None:
    """Let a real model choose a tool, then dispatch its proposal through policy.

    Any failure here prints a line and returns. A model sometimes proposes a malformed call,
    an unknown tool, or nothing at all — and a proposal sentrykit refuses is exactly the point,
    so it is printed rather than hidden.

    Args:
        client: A connected client.
        choice: The tier and model to run on, as :func:`examples.models.choose` answered it.
        principal: Who to act as.
        ask: The user turn to send.
    """
    meta = {PRINCIPAL_KEY: principal}
    print(f"\n  [{principal}] {ask}")
    try:
        manifest = await client.list_tools(meta=meta)
        print(f"    offered   {[tool.name for tool in manifest.tools]}")
        message = models.chat(
            choice,
            [{"role": "user", "content": ask}],
            tools=_declarations(manifest),
        )
        if message is None:
            print("    the model stopped answering; skipping the rest of this section")
            return
        proposals = message.get("tool_calls") or []
        if not proposals:
            content = (message.get("content") or "").strip().replace("\n", " ")
            print(f"    the model proposed no tool call: {content[:120] or '(nothing)'}")
            return
        for proposal in proposals:
            function = proposal.get("function") or {}
            name = function.get("name")
            arguments = function.get("arguments") or {}
            if isinstance(arguments, str):
                # The one difference between the two live tiers that reaches this far: the
                # frontier tier answers with `arguments` as a JSON string and the local daemon
                # with an object. Both are the model's own proposal, and both go on from here
                # to the same governed dispatch.
                arguments = json.loads(arguments)
            print(f"    proposed  {_call_text(str(name), dict(arguments))}")
            result = await client.call_tool(str(name), dict(arguments), meta=meta)
            print(f"    policy    {_outcome(result)}")
    # Broad on purpose: a small local model can fail in more ways than are worth enumerating,
    # and a demonstration that aborted on a bad turn would teach less than one that says so.
    except Exception as error:
        print(
            f"    the turn failed and the demonstration continues: {type(error).__name__}: {error}"
        )


async def _model_section(client: Client) -> None:
    """Run the live-model section, or say why there is none.

    Args:
        client: A connected client.
    """
    print("\n--- the model proposes; the policy decides ---")
    choice = models.choose()
    if choice.model is None:
        print(f"  {models.why_no_model()}.")
        print("  the deterministic drive above is the whole demonstration: every outcome in it")
        print("  is decided from the principal and the proposed arguments, never from which")
        print(f"  model proposed them. {models.OPENROUTER_KEY_ENV_VAR} in .env at the repository")
        print("  root opts into a frontier model, and a local Ollama daemon with a tool-capable")
        print("  model is the path that needs no account.")
        return

    # The tier, the model id and the base URL, and nothing else. The credential that reaches
    # the frontier tier travels in a header and is printed nowhere -- `models.Choice` keeps it
    # out of its own repr for the same reason.
    print(f"  model: {choice.model} ({choice.tier} tier) at {choice.base_url}")
    await _live_model(client, choice, "alice", "Search the orders desk for up to 500 CN orders.")
    await _live_model(client, choice, "bob", "Export the open orders as a PDF, please.")
    # Two honest notes, because a live model earns the example nothing if its output is tidied
    # up afterwards. The proposals above went through the same governed dispatch the table
    # used — no second path, no prompt asking the model to behave. And the spelling of a
    # proposed value is the model's own: Cedar compares strings exactly, so a policy written
    # against "pdf" does not match "PDF", and a policy meant to catch both has to say so.
    print("\n  the proposals above took the same governed dispatch the table above took.")
    print('  Cedar compares strings exactly: a policy matching "pdf" does not match "PDF",')
    print("  and how a value is spelled is the model's choice, never the policy's.")


# --- driving it ----------------------------------------------------------------------------


async def demonstrate() -> None:
    """Drive the server in-process, as a client would, and print the whole story.

    No sockets: :class:`mcp.Client` accepts an :class:`~mcp.server.mcpserver.MCPServer`
    directly and speaks to it over an in-memory transport, which is also how the integration
    tests run.

    Resets the orders desk before driving anything, so the run is reproducible. Nothing else
    here writes to it.
    """
    # Several flows WRITE: each permitted refund books a row with a freshly allocated id, and
    # each export books a job. Without starting from identical rows, a second run would count
    # on from wherever the first one stopped, and none of the ids below would be the same
    # twice — so neither the table nor the documentation quoting it could be relied on.
    #
    # Only the self-drive does this. ``create_server()`` deliberately does not: a server that
    # emptied its database on startup would be a poor example of anything.
    desk.reset_desk()
    sink = InMemoryAuditSink()
    server = create_server(audit_sink=sink)
    async with Client(server) as client:
        await _manifests(client)
        await _flows(client)
        await _nested_records(client, sink)
        await _model_section(client)
    await _severed_comparison()


def _quiet_the_narration() -> None:
    """Turn down two loggers, so the narrative below is readable.

    Only ever called on the self-drive path. A server that is actually serving keeps every
    line: an operator wants "Authorization denied" in the log, and a demonstration wants it
    in the table it already prints.

    mcp's client logs under the top-level name ``client`` rather than under ``mcp``, so that
    is the name to reach for. It goes to ``ERROR`` because its one warning here is a false
    alarm dressed as a real one: the client validates a tool result against the manifest it
    was served, and this server serves a *filtered* manifest — so calling a hidden tool by
    name, which is the invariant this drive exists to prove, makes the client warn that it
    cannot validate a tool it was never shown. That is the demonstration working.

    ``sentrykit`` goes to ``WARNING``, which leaves exactly the ``Argument dropped by
    policy`` lines. Those are real, they are one per narrowed argument, and hiding them
    would misrepresent what a deployment sees.
    """
    logging.getLogger("client").setLevel(logging.ERROR)
    logging.getLogger("sentrykit").setLevel(logging.WARNING)
    print(
        "sentrykit logs `Argument dropped by policy` on every rejection. Those lines are"
        "\nthis run's own, one per argument narrowed in the table below.",
        # stdout is block-buffered when redirected and the log handler writes to stderr, so
        # without this the explanation lands after the lines it is explaining.
        flush=True,
    )


def main() -> None:
    """Serve over stdio, or self-drive when a human ran this at a terminal.

    A stdio server speaks JSON-RPC on stdin, which nobody types by hand, so an interactive
    terminal gets the in-process narrative instead. Piped stdin — which is what an MCP client
    gives a server it spawned — gets a real server.
    """
    if sys.stdin is not None and sys.stdin.isatty():
        _quiet_the_narration()
        anyio.run(demonstrate)
        return
    create_server().run()


if __name__ == "__main__":
    main()
