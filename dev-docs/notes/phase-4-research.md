# Phase 4 — research notes

Findings verified against the **actually installed** `agent` pixi environment on 2026-08-18,
by running code rather than by reading documentation. Phases 1–3 are in
`phase-1-research.md` … `phase-3-research.md` and are not repeated.

| Package | Version |
| --- | --- |
| Python | 3.13.15 (conda-forge) |
| **mcp** | **2.0.0** |
| pydantic-ai / pydantic-ai-slim | 1.47.0 |
| pydantic | 2.13.4 |
| anyio | 4.14.2 |
| starlette | 1.6.0 (pulled in by `mcp`, **not** by the `web` feature) |
| httpx | 0.28.1 |
| `fastmcp` (standalone) | 2.14.1 — **installed but unusable**, see §0 |

---

## 0. The headline: there is no `FastMCP` any more, and the standalone package is broken

Two things the plan's wording (`examples/fastmcp_server/`, "FastMCP") does not anticipate:

```python
>>> from mcp.server.fastmcp import FastMCP
ModuleNotFoundError: No module named 'mcp.server.fastmcp'
>>> import fastmcp
ImportError: cannot import name 'McpError' from 'mcp.shared.exceptions'
```

* In **mcp 2.0** the ergonomic server class was renamed: `mcp.server.fastmcp.FastMCP` →
  **`mcp.server.mcpserver.MCPServer`**. Same decorator-driven shape (`@server.tool()`), new
  home and new name.
* The **standalone `fastmcp` distribution** (2.14.1) is in the environment as a transitive
  dependency and does not import against mcp 2.0 — it still expects `McpError`, which mcp 2.0
  removed. It is not a viable target and nothing in sentrykit may import it.

> **Consequence.** The integration module keeps the name `sentrykit.integrations.fastmcp`
> and the extra keeps the name `sentrykit[fastmcp]` — those are the user-facing names the
> plan, the entry point and the docs already commit to — but everything it imports comes
> from `mcp.server.*`. The module docstring says so in as many words, because a reader who
> types `pip install fastmcp` on the strength of the module name gets a broken environment.

## 1. Intercepting tool dispatch: `ServerMiddleware`, and it is exactly the seam we need

`mcp.server.context.ServerMiddleware` is a `Protocol`:

```python
class ServerMiddleware(Protocol[_MwLifespanT]):
    async def __call__(
        self, ctx: ServerRequestContext[_MwLifespanT, Any], call_next: CallNext
    ) -> HandlerResult: ...

CallNext = Callable[[ServerRequestContext[Any, Any]], Awaitable[HandlerResult]]
HandlerResult = BaseModel | dict[str, Any] | None
```

Registered either at construction (`MCPServer(..., middleware=[...])`) or by appending to the
public `MCPServer.middleware` list. It runs at the top of `ServerRunner._on_request`, **before
params validation**, and wraps *every* inbound request and notification — `initialize`,
`tools/list`, `tools/call`, `METHOD_NOT_FOUND`, the lot.

Observed for a `tools/call`, driven in-memory:

| | value |
| --- | --- |
| `ctx.method` | `"tools/call"` |
| `ctx.params` | `{"name": "read_order", "arguments": {"order_id": "o-1"}, "_meta": {...}}` |
| `ctx.meta` | the `_meta` mapping, merged with the reserved `io.modelcontextprotocol/*` keys |
| `ctx.request_id` | `"3"` (`None` would mean a notification) |
| `ctx.request` | `None` on stdio/in-memory; the transport request on HTTP |
| `ctx.session` | the `ServerSession` |

This is the establish/release boundary, and it is the direct analogue of
`SentrykitMiddleware` on the ASGI side: one class, `try/finally`, same lifecycle.

**A middleware-established `ContextVar` does reach the tool body, and does not survive the
dispatch.** Measured with a deliberate probe — a `whoami` tool reporting the ambient value:

```
whoami with _meta principal=alice  ->  {'seen': 'alice'}
whoami with no _meta               ->  {'seen': None}      <- the release works
```

That second line is the agent analogue of the Phase 3 leak test and is what the no-leak
test asserts.

## 2. Reading the principal: three sources, one of which is transport-independent

1. **`ctx.meta`** — the client's `_meta` object on the request params. `RequestParamsMeta` is
   a `TypedDict(extra_items=Any)`, so arbitrary keys round-trip, and both `Client.call_tool`
   and `Client.list_tools` take `meta=`. Verified: `meta={"sentrykit/principal": "alice"}`
   arrives intact on `ctx.meta` for both methods. **This is the only channel that works on
   every transport**, including stdio and in-memory, so it is the provider's default and it
   is what makes the example server and the tests drivable with no HTTP server at all.
2. **`ctx.request`** — the transport request on HTTP, from which headers are readable. `None`
   on stdio, which is why it cannot be the default.
3. **OAuth.** `mcp.server.mcpserver.authenticated_principal(ctx) -> str | None` (re-exported
   from `mcp.server.request_state`) wraps
   `mcp.server.auth.middleware.auth_context.get_access_token()` and returns a compact-JSON
   `(client, issuer, subject)` identity, or `None` on unauthenticated transports. This is the
   real-deployment path and is what an app's `identify=` callback should reach for.

> **Consequence.** `read_header(request, name)` on the MCP provider reads `ctx.meta[name]`
> first, then falls back to the transport request's headers when there is one. "Header" stays
> the base class's vocabulary; on MCP the carrier is `_meta`. The header *name* defaults to
> `x-sentrykit-principal` for continuity with the web providers, and the example and tests
> use exactly that key in `_meta`.

## 3. Refusing a tool call: return a `CallToolResult` **model**, never a dict, and never raise

Three shapes were measured. Only one carries the `_authz` envelope:

| the middleware… | what the client sees |
| --- | --- |
| lets the tool raise | `is_error=True`, `structured_content=**None**`, content `"Error executing tool boom: kaboom"` — **the structure is lost** |
| returns a plain `dict` | **`ValidationError`: `CallToolResult.resultType` Field required** — the connection dies |
| returns `mcp.types.CallToolResult(...)` | `is_error=True`, `structured_content={'_authz': {...}}` ✔ |

`HandlerResult` nominally admits `dict[str, Any]`, but a middleware that short-circuits skips
`ServerRunner._serialize`, so the dict never gets the `resultType` discriminator the
2026-07-28 union needs. A returned **model** is serialized correctly.

> **Consequence.** The provider **short-circuits**: it plans the call, and on refusal returns
> `CallToolResult(content=[TextContent(...)], structured_content={..., "_authz": ...},
> is_error=True)` *without* calling `call_next`. The side effect is refused before it
> happens — which is the positioning (architecture §8) — and the model receives a structured
> refusal it can act on rather than an opaque error string.

## 4. `tools/list` filtering: rewrite the result, and the default cache scope is safe

`call_next(ctx)` for `tools/list` returns an **already-serialized `dict`**:

```json
{"cacheScope": "private", "resultType": "complete", "ttlMs": 0,
 "tools": [{"name": "...", "description": "...", "inputSchema": {...}, "outputSchema": {...}}],
 "_meta": {"io.modelcontextprotocol/serverInfo": {...}}}
```

Because it already carries `resultType`, rewriting `result["tools"]` in place is valid (unlike
§3's short-circuit) and was verified end-to-end: with a filter dropping `delete_order`, the
client's `list_tools()` returned `['read_order']`.

`cacheScope` defaults to **`private`** and `ttlMs` to **`0`**, so a per-principal manifest is
not cached across callers by default. A server that sets `cache_hints=` must not widen the
`tools/list` scope; the docs say so.

**Mapping an advertised tool name back to its callable.** `MCPServer` exposes no public
accessor for a registered tool's function. `MCPServer._tool_manager` is private, though the
`ToolManager.get_tool(name) -> Tool | None` / `.list_tools()` methods on it are ordinary
public methods, and `Tool` carries `.name`, `.fn`, `.parameters` (the JSON schema),
`.description` and `.output_schema`. The provider therefore reads it **defensively** — a
guarded lookup that degrades to "this name is not a sentrykit-protected tool" if the internal
shape ever changes — and accepts an explicit `tools=` mapping for hosts that would rather not
depend on it at all.

**`@protect` survives schema generation.** A tool registered as
`@server.tool()` over `@protect` advertises the *original* signature, because `@protect` uses
`functools.wraps` and `inspect.signature` follows `__wrapped__`. Verified: the wrapper
advertised `{"order_id": {"type": "string"}, "limit": {"default": 5, "type": "integer"}}`.

## 5. Pydantic-AI: `prepare` is the `list_tools` analogue, and `deps` is the principal channel

```python
ToolPrepareFunc  = Callable[[RunContext[Deps], ToolDefinition],       Awaitable[ToolDefinition | None]]
ToolsPrepareFunc = Callable[[RunContext[Deps], list[ToolDefinition]], Awaitable[list[ToolDefinition] | None]]
```

* Per-tool: `agent.tool(fn, prepare=...)` — returning `None` **hides the tool for that run**.
* Whole-run: `Agent(..., prepare_tools=...)`.

Measured with `FunctionModel` capturing `AgentInfo.function_tools`: with `deps.principal ==
"alice"` the model was offered `['read_order', 'delete_order']`; with `"bob"`, `['read_order']`.
`RunContext` carries `deps`, `tool_name`, `tool_call_id`, `run_id`, `messages`, `retry`.

**A `ContextVar` established outside `agent.run(...)` is visible inside a tool body** (probe
reported `'outer'`). Establishment per *tool dispatch* therefore also works, and is what the
provider does — run-scoped establishment would not let the no-leak test have teeth.

### The `ctx` problem, and the adapter that solves it

`@agent.tool` functions take `ctx: RunContext[...]` as their first parameter.
`@protect` would treat `ctx` as a *proposed argument*: it would land in the Cedar request, in
the constraint filter, and in the pydantic validation model. That is wrong on all three
counts.

So the pydantic-ai integration registers a **synthesized ctx-taking adapter** around a plain,
`@protect`-ed, ctx-free function. `functools.update_wrapper` plus an explicit
`__signature__`/`__annotations__` that prepend `ctx: RunContext[Any]` was verified to produce
exactly the right tool definition:

```json
{"additionalProperties": false, "type": "object",
 "properties": {"order_id": {"description": "which order.", "type": "string"},
                "limit": {"default": 5, "description": "how many lines.", "type": "integer"}},
 "required": ["order_id"]}
```

`ctx` is excluded from the schema, the docstring's argument descriptions survive, and the
adapter receives both `ctx` and the model's arguments. The author still writes one decorator
(`@protect`) plus one registration call, exactly as the web side is `@protect` plus
`protect_app`.

## 6. Driving both offline, with no live model

* **MCP.** `mcp.Client` accepts an `MCPServer` **directly** — `async with Client(server) as
  client:` runs it over `mcp.client._memory.InMemoryTransport`, in-process, no sockets. This
  is how every MCP test and the example's self-drive run.
* **Pydantic-AI.**
  * `pydantic_ai.models.test.TestModel` — calls every visible tool, then returns their
    outputs as JSON. One line, no configuration, and it makes the *tool manifest* observable
    through the output.
  * `pydantic_ai.models.function.FunctionModel(fn)` — `fn(messages, info) -> ModelResponse`
    with `info.function_tools: list[ToolDefinition]`. This is the one that lets a test assert
    **exactly which tools the model was offered**, which is the manifest-hiding assertion.

> **Consequence.** `pixi run -e agent run-agent` runs on a deterministic model by default and
> needs no API key. A real model is opt-in through `SENTRYKIT_EXAMPLE_MODEL`; when it is
> unset the example uses `TestModel` and prints the same narrative.

## 7. The `agent` environment breaks a Phase 3 typecheck, for a reason worth recording

`pixi run -e agent typecheck` failed on `integrations/fastapi.py` before any Phase 4 code was
written:

```
src\sentrykit\integrations\fastapi.py:279: error: Returning Any from function declared to
return "Response"  [no-any-return]
```

The `agent` environment is a combination none of the earlier phases produced: **starlette is
installed** (mcp depends on it) while **fastapi is not**. So `Response` resolves to a real
type while `JSONResponse` is `Any` under the `ignore_missing_imports` override, and returning
one as the other is an error. Fixed by binding an annotated local — the same idiom the module
already uses in `read_header`, for the mirror-image reason. No behaviour change.

> **Consequence for the gates.** The four environments are not a nesting; `agent` is not
> "default plus mcp". Every phase from here on runs `pixi run -e all check` last, and `-e
> agent check` is not redundant with it.

## 8. Decisions taken for Phase 4 as a consequence

1. **Target `mcp.server.mcpserver.MCPServer`**, never `fastmcp` and never `mcp.server.fastmcp`
   (§0). The module and extra keep the `fastmcp` name.
2. **One `ServerMiddleware` handles both methods** (§1, §4): establish/release around
   `tools/call`, filter the result of `tools/list`. Two hooks would be two places for the
   invariant in §9 to drift.
3. **A refusal short-circuits and returns a `CallToolResult` model** (§3). Never a dict, and
   never a raised exception — both lose the envelope or the connection.
4. **The principal travels in `_meta`** by default (§2), with the transport request's headers
   and an app-supplied `identify=` as the other two paths.
5. **Pydantic-AI tools are plain `@protect`-ed functions behind a synthesized adapter** (§5);
   `ctx` never reaches the policy.
6. **Filtering runs the real gate.** Both `list_tools` and `prepare` call the *same*
   `Governor.plan(...)` the enforcement path calls — the split between `Governor.plan` and
   `Governor.invoke` exists for exactly this (engine module docstring), so there is no second
   decision implementation to keep in step.
7. **Tests drive in-memory** (§6): `Client(server)` and `TestModel`/`FunctionModel`. No
   sockets, no API keys, no live model anywhere in the suite or the examples.

## 9. The invariant the filtering must satisfy

> **A tool is hidden from a principal if and only if invoking it would be denied.**

Hiding is a *usability* affordance for the model — it stops the model proposing calls that
cannot succeed and burning turns on refusals. It is **never the only line of defence**: the
enforcement path (§1, §3) runs the identical gate on dispatch, so a caller that ignores the
manifest and invokes a hidden tool directly is refused just the same. Both halves are
asserted together in the same test, because a filter that is *also* the enforcement would be
a security hole the moment a client skipped `tools/list`.

---

## 10. The one that changes a deliverable: a model cannot omit a schema-required argument

Found while integrating, and measured on **both** agent boundaries independently. Each
framework validates the caller's proposal against the tool's advertised JSON schema *before*
dispatch, so a parameter that is `required` in that schema never reaches sentrykit at all:

```
strict_tool(region: str, limit: int)               required = ['region', 'limit']
  call with {}  -> isError=True, "2 validation errors ... Field required"
                   the tool body was never entered

lenient_tool(region: str | None = None, limit: int | None = None)
                                                   required = None
  call with {}  -> isError=False, body entered with region=None, limit=None
```

Pydantic-AI behaves identically: a proposal of `{}` for a required parameter comes back to the
model as a `Field required` retry and never reaches the governor. Rewriting
`ToolDefinition.parameters_json_schema` from `prepare` does **not** help — it changes what the
model is *shown*, not the validator, which is built from the registered signature.

> **Consequence.** *Per-principal default injection is unreachable from an agent boundary for
> any parameter declared without a Python-level default* — which is exactly how the web
> examples declare the parameters whose value must come from policy. Left alone, the Phase 4
> acceptance criterion "an entitled tool call runs with filtered args **+ injected defaults**"
> would only be satisfiable by calling the protected function directly, bypassing the very
> boundary the phase exists to demonstrate.

### This is the same problem the web providers already solved, one layer out

The FastAPI example does not protect its route. It declares
`list_orders(region: str | None = None, limit: int | None = None)` and forwards **only the
parameters the caller actually supplied** to the protected `search_orders`:

```python
proposed: dict[str, object] = {}
if region is not None:
    proposed["region"] = region
...
return search_orders(**proposed)
```

An absent argument has to be *expressible at the boundary*, and on an agent boundary the
boundary **is** the tool signature. So the fix is the same shape: the registered tool is a thin
shim whose parameters are optional, and the protected callable sits behind it.

Hand-rolling that shim per tool is the wrong answer — it has to satisfy two competing
introspections at once:

* `inspect.signature` must report the **shim's** parameters, so the framework advertises the
  optional schema; and
* `governed_meta` must reach the **protected** callable, or the manifest filter reads the tool
  as ungoverned and shows it to everybody — silently breaking ADR-017.

Both are satisfiable together, because `inspect.signature` stops unwrapping at an object
carrying its own `__signature__`: a shim that sets **both** `__wrapped__` and `__signature__`
advertises itself and still resolves to the protected callable. That is precisely the pair
`tool_adapter` already sets on the Pydantic-AI side (§5), so the mechanism is not new — only
its second use is.

> **Decision.** `integrations/tools.py` grows one framework-free helper that builds that shim,
> so both providers and both examples share it, and `governed_meta` unwraps the whole
> `__wrapped__` chain rather than a single hop (an adapter around a shim around a protected
> callable is two hops on the Pydantic-AI side). Recorded as ADR-019.

## 11. A refusal can leave the tool body after all — `MCPError` is the one exception mcp re-raises

Integration turned up a correction to §3, and then a way around it.

**The correction.** §3 measured what happens to an exception raised *in the middleware*. What
happens to one raised *inside a tool* is worse: `Tool.run` wraps anything the body raised in a
`ToolError`, and `MCPServer._handle_call_tool` turns that into
`CallToolResult(is_error=True)` with `structured_content=None`. So a `SentrykitError` raised by
`@protect` **never reaches a `ServerMiddleware` at all** — a middleware that only wrapped
`call_next` in a `try` would catch nothing, and every refusal would arrive as the string
`"Error executing tool …"` with no envelope.

**The way around it.** `_handle_call_tool` catches everything *except* `MCPError`, and the
`ServerMiddleware` contract says as much: "a request-side failure reaches the middleware as a
raised `MCPError`". Measured with an `MCPError` subclass carrying a payload:

```
refusing_tool -> isError: True
                 structured: {'detail': 'denied', '_authz': {'decision': 'deny', 'x': 7}}
   middleware caught the smuggled refusal: {...}          <- it propagated
plain_raise   -> isError: True | structured: None         <- contrast: swallowed, as above
```

> **Consequence.** A refusal does **not** need to be decided ahead of the call in order to be
> rendered. The shim already sitting between mcp and the protected callable (§10) can catch the
> `SentrykitError`, re-raise it inside an `MCPError`, and let the middleware unwrap and render
> it. That matters because deciding ahead of the call means deciding **twice** — measured: one
> allowed dispatch wrote **two** `allowed` audit records, one per plan. For a library whose
> positioning is audit-first, and whose Phase 5 ships period aggregation over that log, an
> allow counted twice makes every aggregate wrong.
>
> With §10's shim and this, the MCP dispatch path collapses to: one plan, one audit record, an
> envelope built from the caller's *real* proposal (so `defaults_applied` is honest rather than
> reconstructed), and `is_error=True` preserved. The argument write-back and the envelope
> restoration that a pre-flight forces both become unnecessary.
