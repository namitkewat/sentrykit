# Agent tooling

sentrykit governs an agent's tool calls with the same decorator that governs a Flask view. The
model *proposes* a call; the policy *decides* it. Nothing about a protected function's body
knows it is being invoked by a language model.

Two integrations ship, behind two extras:

```bash
pip install "sentrykit[fastmcp]"        # MCP tool servers
pip install "sentrykit[pydantic-ai]"    # Pydantic-AI agents
```

!!! note "`sentrykit[fastmcp]` does not install `fastmcp`"
    It installs `mcp>=2,<3`. In mcp 2.0 the ergonomic server class was renamed
    `mcp.server.fastmcp.FastMCP` → `mcp.server.mcpserver.MCPServer`, and the separately
    published `fastmcp` distribution does not import against mcp 2.0 at all. sentrykit keeps
    the `fastmcp` name for the module, the extra and the DSN — those are stable, and the
    ecosystem still says "FastMCP" — but nothing in it imports that package.

## What an agent boundary needs that a web boundary does not

A web provider has one job: establish the ambient principal at the boundary. An HTTP client
already knows which URLs exist, so there is nothing to decide about *visibility*.

An agent boundary has a second job. It tells the model what it may attempt, and that manifest
is per-caller. So each agent integration does two things:

| | MCP | Pydantic-AI |
| --- | --- | --- |
| establish / release per dispatch | `SentrykitToolMiddleware` around `tools/call` | the adapter `governed_tool` registers |
| filter the manifest | `tools/list` result | the tool's `prepare` hook |

Both call the **same** decision, through one framework-free module
(`sentrykit.integrations.tools`), so they cannot answer the same question differently.

## The filtering guarantee

> **A tool is hidden from a principal if and only if invoking it would be refused by the
> authorization gate.**

Both halves are load-bearing, and both are asserted in the same test.

**Hiding is never the enforcement.** The dispatch path re-runs the identical decision, so a
client that skips `tools/list` and calls a hidden tool by name is refused exactly as if it had
never been hidden. "The model did not know the tool existed" is not an access-control
argument, and a filter that *were* the control would be a hole the moment a caller skipped the
manifest.

**A tool you may use is never hidden.** Hiding is a usability affordance — it stops the model
proposing calls that cannot succeed and burning turns on refusals it could not have predicted.
A filter that hid more than it had to would silently narrow what the agent can do for its user,
and nothing would report it.

What the manifest decides is *entitlement*, because that is the only question answerable before
the model has proposed anything. `AuthzDenied` and `NoContext` hide a tool. Argument-level
refusals — `DefaultUnavailable`, `NoValidArguments`, `ArgumentRejected`, `ValidationFailed` —
do not, and are enforced on dispatch instead. That split matters: a tool with a required
parameter and no policy default raises `DefaultUnavailable` for *everybody*, so treating it as
a denial would hide every such tool from every principal. Hiding is a usability affordance,
never a control: a tool is hidden if and only if invoking it would be refused, and invoking a
hidden tool is refused again on dispatch.

A callable with no `@protect` wrapper carries no action and no argument spec, so there is
nothing to decide about it. It is left **visible**: sentrykit does not silently hide a tool its
author never asked it to govern.

## MCP tool servers

```python
from mcp.server.mcpserver import MCPServer

from sentrykit import configure, install
from sentrykit.decorator import protect
from sentrykit.integrations.fastmcp import FastMCPProvider, governed_tool, protect_server


@protect(action="orders.search", resource='Tool::"orders"')
def search_orders(region: str, limit: int) -> dict[str, object]:
    """Search orders.

    Args:
        region: which region to search.
        limit: how many rows to return.
    """
    return {"region": region, "limit": limit}


def create_server() -> MCPServer:
    store = build_grants()
    provider = FastMCPProvider(grants=store)
    install(POLICY_TEXT, grant_store=store, context_provider=provider)

    server = MCPServer("orders")
    governed_tool(server)(search_orders)
    protect_server(server)
    return server
```

`protect_server` installs one middleware. It is idempotent, so wiring at import and again in a
test fixture cannot double-govern a dispatch.

### Register protected tools through `governed_tool`

This is the one sharp edge, and it is worth stating plainly rather than discovering.

`mcp`'s `Tool.run` wraps anything a tool body raises in a `ToolError`, which the server turns
into a result with **no structured content**. A `SentrykitError` raised by `@protect` therefore
never reaches a middleware, and a plain `@server.tool()` over `@protect` would return the
opaque string `"Error executing tool …"` with no `_authz` envelope at all.

`governed_tool` fixes that by carrying the refusal out inside an `MCPError`, which is the one
exception mcp re-raises. It also applies the argument re-declaration described below. Use it
for every protected tool.

### Where the principal comes from

`read_header` looks in two places, in order:

1. **`ctx.meta`** — the `_meta` object on the request params. Both `Client.call_tool` and
   `Client.list_tools` accept `meta=`, and it is the only carrier that exists on *every*
   transport, including stdio and in-memory. This is what makes the example server and the
   whole test suite drivable without a socket.
2. **The transport request's headers**, when the transport has one. Absent on stdio.

Either is enough for an example, a smoke test, or a server behind a gateway that has already
authenticated the caller — and nowhere near enough for anything else. A real deployment passes
`identify=`, typically reaching for `mcp.server.mcpserver.authenticated_principal`, which
resolves the OAuth `(client, issuer, subject)` identity from the ambient access token.

```python
from mcp.server.mcpserver import authenticated_principal

provider = FastMCPProvider(identify=authenticated_principal, grants=store)
```

### Manifest caching

A `tools/list` result carries `cacheScope: "private"` and `ttlMs: 0` by default, so a
per-principal manifest is not cached across callers. A server that sets `cache_hints=` must not
widen the `tools/list` scope.

## Pydantic-AI agents

```python
from dataclasses import dataclass

from pydantic_ai import Agent

from sentrykit.decorator import protect
from sentrykit.integrations.pydantic_ai import PydanticAIProvider, governed_tool


@dataclass(frozen=True)
class Caller:
    principal: str          # the human the agent acts for, not the agent


def build_agent() -> Agent[Caller, str]:
    store = build_grants()
    provider = PydanticAIProvider(grants=store)
    install(POLICY_TEXT, grant_store=store, context_provider=provider)

    agent = Agent(model, deps_type=Caller)
    governed_tool(agent)(search_orders)
    return agent


result = await agent.run("what is on order o-1?", deps=Caller(principal="alice"))
```

### On-behalf-of is not a special mechanism

An agent acting for a human **is** that human, as far as the policy is concerned. The
principal established for each dispatch is the one named in `deps` — never a service identity
for the agent process — so a delegation chain, a team edge or an expiry granted to *alice* is
what governs the call the model proposed on alice's behalf.

The model cannot influence it. `deps` is supplied by the application at `run()` time and never
appears in anything the model can write.

### Establish per dispatch, not per run

A run is a loop: the model proposes, a tool runs, the model proposes again. Context is
established and released around each individual tool call, not around the whole `run()`, so no
principal outlives the dispatch it was established for. The test suite pins this by driving two
dispatches inside one `contextvars` context and asserting the principal is gone in between —
and pins that the assertion has teeth, by checking it fails against a provider whose `release`
is a no-op.

### Refusals come back as data

A refused tool returns the `_authz` payload as its result rather than raising. The side effect
never happened, and the model is told *why* in a form it can act on: pick a different tool, ask
the user for authorization, or explain the refusal. Letting the error propagate would abort the
run and tell the user's agent nothing useful. Pass `on_refusal="raise"` to fail the run
instead.

## Omitted arguments, and why the tool signature changes

Per-principal **default injection** is one of the three things sentrykit does. Reaching it from
an agent takes one extra step, for a reason that is worth understanding.

Both frameworks validate the caller's proposal against the tool's advertised JSON schema
*before* dispatch. A parameter the schema marks `required` therefore cannot be omitted, and an
argument that cannot be omitted can never be filled in from policy — the framework rejects the
call before sentrykit sees it.

`governed_tool` handles this by registering the tool behind a shim
(`sentrykit.integrations.tools.proposable`) that re-declares the arguments policy supplies as
optional and forwards only the ones actually proposed. It is the same move the FastAPI example
makes one layer out, where the route declares `region: str | None = None` and forwards only
what the caller sent. An absent argument has to be *expressible at the boundary*, and on an
agent boundary the tool signature **is** the boundary.

By default every parameter with no Python-level default becomes omittable — precisely the set
whose value could only have come from policy. Name them explicitly with `optional=`.

!!! warning
    A parameter made omittable cannot carry a meaningful `None`: the shim reads `None` as *not
    proposed* and drops it. Do not list a genuinely nullable parameter.

The shim keeps both introspections working — the framework sees the optional schema through
`__signature__`, and the manifest filter reaches the `@protect` metadata through `__wrapped__`.

## Relationships are resolved by the policy, not by the model

This is the claim the MCP example exists to demonstrate. `read_order` is permitted by a single
policy that names only the far end of a four-hop chain:

```cedar
@id("project-members-may-read-project-orders")
permit (
  principal in Project::"orders-eu",
  action == Action::"orders.read",
  resource in Project::"orders-eu"
);
```

Alice reaches it through `User → Team → Division → Project`, and the order hangs off the same
project. The policy mentions neither her team nor her division. Cedar computes the transitive
closure; nothing in sentrykit walks the chain, and nothing in the model is asked to.

Three things follow, and the example demonstrates each:

* **Allowed.** Alice's `read_order("o-1")` succeeds, through edges no policy names.
* **Denied when the edge is absent.** Bob's chain is just as long and lands on a different
  project, so the same call is refused — and `read_order` is not in his manifest.
* **Denied when the edge is severed.** Detach the team from its division, change nothing else,
  and alice loses the access while her unrelated role-gated tools keep working.

Run it:

```bash
pixi run -e agent run-mcp
```

## Running the examples

Both run offline, with no API key and no network call.

```bash
pixi run -e agent run-mcp        # the MCP tool server
pixi run -e agent run-agent      # the Pydantic-AI agent
```

The agent example's default model is `pydantic_ai.models.test.TestModel`, and its narrative is
driven by `FunctionModel` so it can show exactly which tools the model was offered rather than
asserting it in prose. Set `SENTRYKIT_EXAMPLE_MODEL` to point the free-form run at a real model.
