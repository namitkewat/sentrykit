# Example: fastmcp_server

Three governed MCP tools showing the thing sentrykit exists for: **the model proposes, the
policy decides.** The model picks a tool and drafts its arguments; Cedar decides whether the
call may happen at all, which arguments survive, and which values are filled in when the model
supplies none. Nothing in this example asks a model to behave — it refuses the side effect
before it happens.

Built against **mcp 2.0** (`mcp.server.mcpserver.MCPServer`). The module is called
`fastmcp` because that is the name the extra and the docs commit to; the standalone `fastmcp`
distribution does not import against mcp 2.0 and is not used here.

## Layout

| File | What is in it |
| --- | --- |
| `policy.py` | `POLICY_TEXT` (Cedar *logic*, reviewed in git) and `build_grants(severed=...)` (roles, the entity graph, argument constraints — *data*) |
| `service.py` | The three `@protect`-ed callables. No MCP, no request object, no model |
| `server.py` | `create_server()`: settings, grants, policy, provider, `governed_tool` registration, `protect_server` |

## Who may do what

| Principal | Role | Team | May |
| --- | --- | --- | --- |
| `alice` | `support` | `eu-support` | `orders.search` (role), `orders.read` on `Order::"o-1"` (**relationship**) |
| `bob` | `auditor` | `us-support` | `orders.export` — but never `fmt="pdf"` |

Alice's argument constraints: `region` ∈ {`eu`, `uk`} defaulting to `eu`; `limit` ≤ 50
defaulting to `10`.

### The showcase: four hops, and no policy mentions any of them

```cedar
@id("project-members-may-read-project-orders")
permit (
  principal in Project::"orders-eu",
  action == Action::"orders.read",
  resource in Project::"orders-eu"
);
```

That policy names **only the far end of the chain**. Alice reaches it as

```
User::"alice" -> Team::"eu-support" -> Division::"emea" -> Project::"orders-eu"
                                       Order::"o-1"     -> Project::"orders-eu"
```

and **Cedar walks every one of those edges itself.** No application code resolves the
relationship, no model infers it, and there is no ladder of `if` statements approximating it.
Bob's chain is exactly as long and lands on `Project::"orders-us"`, so he is refused without
any policy naming him. `create_server(severed=True)` detaches `Team::"eu-support"` from its
division, changes nothing else, and alice's access disappears — because the relationship *was*
the authorization.

## Running it

```bash
pixi run -e agent run-mcp
```

At a terminal that self-drives in-process and prints the whole narrative. With its stdin wired
to a real MCP client it serves over stdio like any other server.

Identity is a stub: the caller names themselves in the request's `_meta`, under
**`x-sentrykit-principal`** (sentrykit's shipped `DEFAULT_PRINCIPAL_HEADER`). `_meta` is the one
carrier every MCP transport has — stdio, in-memory and HTTP alike — which is why everything
below runs with no socket. A real deployment passes `identify=` and reaches for
`mcp.server.mcpserver.authenticated_principal`, which resolves the OAuth identity from the
ambient access token.

The server calls `configure(verbosity="verbose")` so the envelope carries processed values,
applied defaults and rejection reasons. A production service would leave it at `summary`.

## Things to try

Every snippet below runs inside this harness — `mcp.Client` takes an `MCPServer` directly and
speaks to it over an in-memory transport:

```python
import anyio
from mcp import Client

from examples.fastmcp_server.server import create_server

ALICE = {"x-sentrykit-principal": "alice"}
BOB = {"x-sentrykit-principal": "bob"}


async def main() -> None:
    async with Client(create_server()) as client:
        ...  # the snippets below go here


anyio.run(main)
```

**Default injection.** The model proposes nothing at all, and policy answers with alice's
values:

```python
result = await client.call_tool("search_orders", {}, meta=ALICE)
print(result.is_error, result.structured_content["region"], result.structured_content["limit"])
# -> False eu 10
print(result.structured_content["_authz"]["defaults_applied"])
# -> {'region': 'eu', 'limit': 10}
```

Both values are in `defaults_applied` and neither is in `rejected`, which is the envelope
saying *the model chose none of this*. That distinction is the difference between a model that
can report honestly on what it did and one that cannot.

**Argument filtering.** `cn` is not in alice's allow-set, so it is dropped and replaced — and
the envelope says exactly what happened rather than hiding it:

```python
result = await client.call_tool("search_orders", {"region": "cn", "limit": 5}, meta=ALICE)
print(result.structured_content["region"], result.structured_content["limit"])
# -> eu 5
print(result.structured_content["_authz"]["rejected"])
# -> [{'name': 'region', 'rule': 'allow-set', 'reason': 'Value is not one of the permitted values', 'policy': 'alice-region', 'value': 'cn'}]
print(result.structured_content["_authz"]["defaults_applied"])
# -> {'region': 'eu'}
```

**The role gate.** Bob is an auditor, not support — and the refusal is *structured*, so the
model gets something it can act on instead of an opaque error string:

```python
result = await client.call_tool("search_orders", {}, meta=BOB)
print(result.is_error, result.structured_content["error"])
# -> True AuthzDenied
print(
    result.structured_content["_authz"]["decision"], result.structured_content["_authz"]["action"]
)
# -> deny Action::"orders.search"
print(result.content[0].text)
# -> The policy denied action Action::"orders.search".
```

**The manifest is per-principal.** Alice is shown `read_order`; bob is not, and neither is
shown a tool they could not invoke:

```python
print([tool.name for tool in (await client.list_tools(meta=ALICE)).tools])
# -> ['search_orders', 'read_order']
print([tool.name for tool in (await client.list_tools(meta=BOB)).tools])
# -> ['export_orders']
print([tool.name for tool in (await client.list_tools(meta={})).tools])
# -> []
```

**Hiding is not the enforcement.** Bob ignores the manifest and calls the hidden tool by name;
he is refused exactly as if it had never been hidden:

```python
result = await client.call_tool("read_order", {"order_id": "o-1"}, meta=BOB)
print(result.is_error, result.structured_content["error"])
# -> True AuthzDenied
print(result.structured_content["_authz"]["resource"])
# -> Order::"o-1"
```

**Four hops, resolved by Cedar.** The same tool, the same policy, a different chain:

```python
result = await client.call_tool("read_order", {"order_id": "o-1"}, meta=ALICE)
print(result.is_error, result.structured_content["order_id"])
# -> False o-1
print(result.structured_content["_authz"]["decision"])
# -> allow
```

**A policy that reads the argument.** Bob may export, but not as a PDF — one value of one
argument refused by a `forbid`, with his role unchanged:

```python
result = await client.call_tool("export_orders", {"fmt": "csv"}, meta=BOB)
print(result.is_error, result.structured_content["fmt"])
# -> False csv
result = await client.call_tool("export_orders", {"fmt": "pdf"}, meta=BOB)
print(result.is_error, result.structured_content["_authz"]["decision"])
# -> True deny
```

**Break one edge and the access goes with it.** Alice keeps her team and her role, the policy
keeps its wording, and only `Team::"eu-support" -> Division::"emea"` is gone:

```python
async with Client(create_server(severed=True)) as client:
    result = await client.call_tool("read_order", {"order_id": "o-1"}, meta=ALICE)
    print(result.is_error, result.structured_content["error"])
    # -> True AuthzDenied
    print([tool.name for tool in (await client.list_tools(meta=ALICE)).tools])
    # -> ['search_orders']
    result = await client.call_tool("search_orders", {}, meta=ALICE)
    print(result.is_error, result.structured_content["region"])
    # -> False eu
```

## The invariant

> **A tool is hidden from a principal if and only if invoking it would be refused.**

Both halves are load-bearing, and both are demonstrated above.

*Only if* — hiding is a **usability** affordance for the model. It stops the model proposing
calls that cannot succeed and burning turns on refusals it could not have predicted. It is
**never the only line of defence**: `tools/call` runs the identical decision, so the
hidden-tool-called-by-name snippet is refused just the same. "The model did not know the tool
existed" is not an access-control argument.

*If* — a tool the principal may invoke is never hidden, so the filter cannot silently narrow
what the agent can do for its user. A tool whose refusal is about *arguments* rather than
entitlement stays visible too: `read_order` needs an `order_id` that a manifest probe has not
got, and hiding it for that reason would hide it from everybody.

## Register with `governed_tool`, and never with a bare `@server.tool()`

This is the one sharp edge, so it is worth stating plainly: **a `@protect`-ed callable handed
straight to `@server.tool()` will have its refusals swallowed.** mcp's `Tool.run` wraps whatever
the body raised in a `ToolError` and `MCPServer._handle_call_tool` turns that into an error
result with `structuredContent: null` — so the model gets the string `"Error executing tool …"`
and the `_authz` envelope is gone before any middleware can see it. The gate still ran and the
side effect was still refused; the model is just told nothing it can act on.

`governed_tool` registers the tool behind two thin layers that each solve one measured problem:

- **An omittable-argument shim.** mcp validates a proposal against the advertised schema
  *before* the body runs, so `search_orders(region, limit)` — which declares no Python defaults
  on purpose — could never be called with none of them, and default injection would be
  unreachable from a model. The shim advertises exactly the policy-suppliable parameters as
  optional and forwards only what was genuinely proposed, so an omission arrives at the
  decorator *as an omission*. That is why the empty call above returns `eu`/`10` with both names
  in `defaults_applied`.
- **A refusal translator.** An `MCPError` is the one exception `_handle_call_tool` re-raises
  rather than swallowing, so a refusal travels out of the tool body as one and the middleware
  renders it as a `CallToolResult` carrying the envelope.

Both layers keep `__wrapped__` pointing at the protected callable, so the manifest filter still
finds its `@protect` metadata — and `governed_tool` **returns the protected callable
unchanged**, so it is still directly callable from the rest of the program under an established
context. Registering a tool does not take a function away from you.

The decision itself is made once, by the decorator, on the arguments the caller actually
proposed. Nothing re-decides and nothing reconstructs the envelope, so **one dispatch writes
exactly one audit record** whether it was allowed or refused.
