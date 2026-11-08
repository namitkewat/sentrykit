# Example: fastmcp_server

Seven governed MCP tools showing the thing sentrykit exists for: **the model proposes, the
policy decides.** The model picks a tool and drafts its arguments; Cedar decides whether the
call may happen at all, **which arguments survive**, and **which values are filled in** when the
model supplies none. Nothing here asks a model to behave — it refuses the side effect before it
happens.

The argument layer is the point. Relationship resolution — user → team → division → project →
order — composes underneath it, deterministically, and this example demonstrates that too.

Built against **mcp 2.0** (`mcp.server.mcpserver.MCPServer`). The module is called `fastmcp`
because that is the name the extra and the docs commit to; the standalone `fastmcp`
distribution does not import against mcp 2.0 and is not used here.

## Layout

| File | What is in it |
| --- | --- |
| `policies/10-orders.cedar` | Reviewed Cedar *logic* for orders, including the `@constraints` **argument ceiling** |
| `policies/20-refunds.cedar` | Reviewed Cedar *logic* for refunds — a broad permit under two narrow `forbid` rules: one reads an argument *together with* the principal, one reads two arguments against each other |
| `policy.py` | `POLICY_DIR` / `POLICY_TEXT` (read back from those files) and `build_grants(severed=...)` — roles, the entity graph, per-principal argument constraints, all *data* |
| `service.py` | The eight `@protect`-ed callables. No MCP, no request object, no model |
| `server.py` | `create_server()`: settings, grants, the policy directory, the provider, `governed_tool` registration, `protect_server` — plus the self-drive |

Those callables do real work: they read and write [`examples.desk`](../desk), a seeded SQLite
orders desk that takes no principal and imports nothing from sentrykit. That is what makes
narrowing legible rather than merely reported — a `limit` refilled with 10 brings back ten
orders, and a caller refused `region="cn"` is left holding the orders of the region policy gave
them instead of a field that says `eu`.

Policy logic lives in files that get reviewed. Grants live in a store an admin surface may
mutate. `install()` takes `policy_source=` **or** `policies=`, never both, so moving to real
files moves *all* the policy text out of Python:

```python
install(
    policy_source=FilesystemPolicySource(POLICY_DIR),
    grant_store=store,
    context_provider=provider,
    audit_sink=audit_sink,
)
```

## Who may do what

| Principal | Role | Team | May |
| --- | --- | --- | --- |
| `alice` | `support` | `eu-support` | search and brief orders, read `Order::"ord-0003"` (**relationship**), issue refunds up to the desk limit |
| `bob` | `auditor` | `us-support` | export orders — but never `fmt="pdf"` |
| `dana` | `admin` | `eu-support` | everything support may do, plus approve refunds and exceed the desk limit |

`Role::"admin"` has `Role::"support"` as a parent in the entity graph, so dana holds one role
grant and satisfies `principal in Role::"support"` by one edge — rather than by a second grant
on every admin.

### Argument rules come from three places

**1. The decorator** says what is being authorized. `@protect` takes `action=` and `resource=`,
works bare, and also accepts `governor=` to pin one specific `Governor` instead of the process
default — useful for a test or for a host running two policy sets side by side. There is no
sibling decorator for plain callables; `governed_tool` is a *registration* helper, not a second
`@protect`.

**2. Grant data** says what *this principal* may pass. The full vocabulary, each used at least
once in `policy.py`:

| Principal | Action | Argument | Rules |
| --- | --- | --- | --- |
| `alice` | `orders.search` | `region` | allow-set `{eu, uk}`, default `eu` |
| `alice` | `orders.search` | `limit` | maximum `50`, default `10` |
| `alice` | `refunds.issue` | `order_id` | pattern `ord-[0-9]{4}`, **no default** |
| `alice` | `refunds.issue` | `amount` | minimum `1`, maximum `750`, default `50` |
| `alice` | `refunds.issue` | `region` | allow-set `{eu, uk}`, default `eu` |
| `bob` | `orders.export` | `fmt` | deny-set `{xml}`, default `csv` |
| `dana` | `orders.search` | `limit` | default `25` — and no bound of its own |
| `dana` | `orders.search` | `region` | default `eu` |

**3. Reviewed policy text** says what *anybody* may pass. `10-orders.cedar` declares an
argument ceiling:

```cedar
@id("support-may-search")
@constraints("{\"limit\": {\"maximum\": 100}}")
permit (
  principal in Role::"support",
  action == Action::"orders.search",
  resource == Tool::"orders"
);
```

`@constraints` is a **Cedar policy annotation** — not a Python decorator, and not new syntax.
Cedar carries annotations verbatim and does not type-check their values, so sentrykit parses
this one at load: a malformed ceiling fails at wiring rather than quietly enforcing nothing.

The ceiling **intersects** with the principal's own grant and can only narrow. Alice's grant
caps `limit` at 50, so hers is the tighter bound and this line never bites her. Dana's grant
sets no maximum, so the reviewed 100 is her only bound — and what she gets back is **25**, her
own default. See below.

## Running it

```bash
pixi run -e agent run-mcp
```

At a terminal that self-drives in-process and prints the whole flow table. With its stdin
wired to a real MCP client it serves over stdio like any other server.

Identity is a stub: the caller names themselves in the request's `_meta`, under
**`x-sentrykit-principal`** (sentrykit's shipped `DEFAULT_PRINCIPAL_HEADER`). `_meta` is the one
carrier every MCP transport has — stdio, in-memory and HTTP alike — which is why everything
below runs with no socket. A real deployment passes `identify=` and reaches for
`mcp.server.mcpserver.authenticated_principal`, which resolves the OAuth identity from the
ambient access token.

The server calls `configure(verbosity="verbose")` so the envelope carries processed values,
applied defaults and rejection reasons. A production service would leave it at `summary`.

The self-drive resets the desk before it starts, because several flows **write**: a permitted
refund books a row with a freshly allocated id, and an export books a job. Starting from
identical rows is what makes two runs agree, and what makes the ids it prints worth quoting.
`create_server()` resets nothing — a server that emptied its database on startup would be a
poor example of anything.

## Things to try

Every snippet below runs inside this harness — `mcp.Client` takes an `MCPServer` directly and
speaks to it over an in-memory transport:

```python
import anyio
from mcp import Client

from examples.fastmcp_server.server import create_server

ALICE = {"x-sentrykit-principal": "alice"}
BOB = {"x-sentrykit-principal": "bob"}
DANA = {"x-sentrykit-principal": "dana"}


async def main() -> None:
    async with Client(create_server()) as client:
        ...  # the snippets below go here


anyio.run(main)
```

### The bare `@protect`

No `action=` and no `resource=`, so both are derived from the callable's import path:

```python
result = await client.call_tool("desk_status", {}, meta=ALICE)
print(result.structured_content["_authz"]["action"])
# -> Action::"examples.fastmcp_server.service.desk_status"
print(result.structured_content["_authz"]["resource"])
# -> Resource::"examples.fastmcp_server.service.desk_status"
```

The reviewed policy has to name that exact string, which is why an explicit `action=` is what
you want as soon as the policy outlives the module layout: renaming or moving the function
silently changes the id the policy is matching.

### A protected callable that is not a tool

`brief_orders` is registered; `summarize_orders`, which its body calls, is protected and
registered nowhere. Two decisions run, and the inner one leaves its own envelope in place:

```python
result = await client.call_tool("brief_orders", {}, meta=ALICE)
print(result.structured_content["_authz"]["action"])
# -> Action::"orders.brief"
print(result.structured_content["brief"]["_authz"]["action"])
# -> Action::"orders.summarize"
```

One dispatch, two audit records, the outer one written **before** the body ran:

```
seq 44  Action::"orders.brief"       allow  allowed    callable=examples.fastmcp_server.service.brief_orders
seq 45  Action::"orders.summarize"   allow  allowed    callable=examples.fastmcp_server.service.summarize_orders
```

Had the inner decision been a refusal, its `AuthzDenied` would have travelled out through
`brief_orders` unchanged. The gate is on the call, not on the tool registration.

### Default injection

The model proposes nothing at all, and policy answers with alice's values:

```python
result = await client.call_tool("search_orders", {}, meta=ALICE)
print(result.structured_content["region"], result.structured_content["limit"])
# -> eu 10
print(result.structured_content["_authz"]["defaults_applied"])
# -> {'region': 'eu', 'limit': 10}
```

Both values are in `defaults_applied` and neither is in `rejected`, which is the envelope
saying *the model chose none of this*. That distinction is the difference between a model that
can report honestly on what it did and one that cannot.

Those two values then went to the database, so the result carries ten real orders:

```python
print(result.structured_content["count"])
# -> 10
print(result.structured_content["orders"][0])
# -> {'order_id': 'ord-0003', 'region': 'eu', 'status': 'open', 'customer': 'Marta Rossi', 'total': 93500, 'items': 2}
```

`limit` is therefore readable twice over — as the number the call ran with, and as the number of
rows it brought back — and the two agree because the second was produced by the first.

### Reject-and-refill, from an allow-set

`cn` is not in alice's allow-set. It is **rejected**, and her own default fills the gap so the
call proceeds — `limit=5` was within her bound and stands untouched:

```python
result = await client.call_tool("search_orders", {"region": "cn", "limit": 5}, meta=ALICE)
print(result.structured_content["region"], result.structured_content["limit"])
# -> eu 5
print(result.structured_content["_authz"]["rejected"])
# -> [{'name': 'region', 'rule': 'allow-set', 'reason': 'Value is not one of the permitted values', 'policy': 'alice-region', 'value': 'cn'}]
print(result.structured_content["_authz"]["defaults_applied"])
# -> {'region': 'eu'}
```

### Several arguments decided in one call

One rejected and refilled, one omitted and defaulted, one left alone:

```python
result = await client.call_tool("search_orders", {"limit": 500, "status": "open"}, meta=ALICE)
print(result.structured_content["_authz"]["processed"])
# -> {'status': 'open', 'region': 'eu', 'limit': 10}
print(result.structured_content["_authz"]["rejected"][0]["reason"])
# -> Value is above the maximum of 50
print(result.structured_content["_authz"]["defaults_applied"])
# -> {'region': 'eu', 'limit': 10}
```

`region` and `limit` declare no Python defaults, so a policy default is reachable for them.
`status` declares one, because which slice of orders to look at is the caller's own business.
That contrast is the rule of thumb: **a value policy decides must stay omittable.**

### The reviewed ceiling, and why the answer is not the ceiling

Dana's grant bounds nothing, so the ceiling in `10-orders.cedar` is her only bound. She asks
for 500, the reviewed maximum is 100 — and she gets **25**:

```python
result = await client.call_tool("search_orders", {"limit": 500, "status": "open"}, meta=DANA)
print(result.structured_content["limit"])
# -> 25
print(result.structured_content["_authz"]["rejected"])
# -> [{'name': 'limit', 'rule': 'maximum', 'reason': 'Value is above the maximum of 100', 'policy': 'support-may-search', 'value': 500}]
print(result.structured_content["_authz"]["defaults_applied"])
# -> {'limit': 25, 'region': 'eu'}
```

Nothing was clamped. The proposal was **rejected**, and dana's own default refilled the gap.
Note the `policy` on the rejection: `support-may-search`, the reviewed file — a grant rejection
names the grant instead. Grants filter first, so whichever bound is tighter is the one that
reports.

She also gets twenty-five rows where alice's identical proposal got ten, which is the whole
point of putting a database behind these calls: two grants over one request are two different
answers, not one answer with two different numbers reported beside it.

### Four hops, resolved by Cedar

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
                                       Order::"ord-0003"     -> Project::"orders-eu"
```

and **Cedar walks every one of those edges itself.** No application code resolves the
relationship, no model infers it, and there is no ladder of `if` statements approximating it:

```python
result = await client.call_tool("read_order", {"order_id": "ord-0003"}, meta=ALICE)
print(result.is_error, result.structured_content["_authz"]["decision"])
# -> False allow
result = await client.call_tool("read_order", {"order_id": "ord-0003"}, meta=BOB)
print(result.is_error, result.structured_content["error"])
# -> True AuthzDenied
```

Bob's chain is exactly as long and lands on `Project::"orders-us"`, so he is refused without
any policy naming him.

Alice's result is the order in full — customer, one-line address, priced lines and shipment —
beside `'found': True`. An id the desk does not hold comes back as `{'order_id': …, 'found':
False}` rather than raising, and that choice is about this boundary in particular: mcp turns any
exception out of a tool body into an error result, which is the same shape a refusal has. A row
that is not there and a call that was refused are two different answers, and a tool that
reported them identically would cost the model the one distinction it most needs.

### A policy that reads the proposed argument

Cedar sees the caller's **raw** proposal, before any per-principal filtering. So a `forbid`
reading `context.args.fmt` fires on what the caller wrote:

```python
result = await client.call_tool("export_orders", {"fmt": "csv"}, meta=BOB)
print(result.is_error, result.structured_content["fmt"])
# -> False csv
result = await client.call_tool("export_orders", {"fmt": "pdf"}, meta=BOB)
print(result.is_error, result.structured_content["_authz"]["decision"])
# -> True deny
print(result.content[0].text)
# -> The policy denied action Action::"orders.export".
```

`fmt="xml"` passes that gate and is then rejected by bob's own deny-set and refilled:

```python
result = await client.call_tool("export_orders", {"fmt": "xml", "scope": "open"}, meta=BOB)
print(result.structured_content["fmt"])
# -> csv
print(result.structured_content["_authz"]["rejected"][0]["rule"])
# -> deny-set
```

Omitting `fmt` entirely reaches the same value by the other route — `defaults_applied` rather
than `rejected`:

```python
result = await client.call_tool("export_orders", {"scope": "open"}, meta=BOB)
print(result.structured_content["_authz"]["defaults_applied"])
# -> {'fmt': 'csv'}
```

### What a tool body knows that the model does not

Every one of those calls books a job, and the job carries a name the model never wrote:

```python
result = await client.call_tool("export_orders", {"fmt": "csv"}, meta=BOB)
print(result.structured_content["requested_by"], result.structured_content["region"])
# -> bob eu
print(result.structured_content["rows"])
# -> 81
```

The result also carries a `job_id` the desk allocated, which counts on from the jobs already
stored — so the self-drive resets before it prints one and these snippets do not promise a
particular handle.

`export_orders(fmt, scope="open")` has no parameter for `requested_by`. The body reads the
ambient principal with `current_principal()`, so the stored row records the human the agent is
acting for — and because it is not an argument, the model can neither see that name nor propose
a different one. That is the mechanism worth copying: a service layer learns who it is acting
for without taking a parameter, without being handed a request, and without importing a
framework to ask. `region` is the stated `EXPORT_REGION` constant, since no argument carries one
and borrowing the `region` rule from `orders.search` would apply a rule about searching to an
export.

The stored `scope` and `region` are what make the handle worth having: the job remembers the
narrowing it was created under, so whoever presents the id later can be held to it rather than
trusted about it.

### Two arguments that are only wrong together

`no-large-cross-region-refunds` forbids a large refund booked outside the EU. Neither value is
out of bounds on its own — alice's grants permit `region="uk"` and `amount=750` both — and the
combination is refused anyway:

```python
ok = {"order_id": "ord-0007", "amount": 100, "region": "uk"}
print((await client.call_tool("issue_refund", ok, meta=ALICE)).is_error)
# -> False
bad = {"order_id": "ord-0007", "amount": 750, "region": "uk"}
result = await client.call_tool("issue_refund", bad, meta=ALICE)
print(result.is_error, result.structured_content["error"])
# -> True AuthzDenied
```

That is Cedar evaluating the whole request from `context.args`. sentrykit needs no extra syntax
for a cross-argument rule, and no `if` statement in the tool body approximates one.

### The gate and the argument layer are two questions

The reviewed desk limit permits 1000. Alice proposes 900, the gate says yes — and her own grant
rejects it and refills with 50:

```python
call = {"order_id": "ord-0007", "amount": 900, "region": "eu"}
result = await client.call_tool("issue_refund", call, meta=ALICE)
print(result.structured_content["amount"])
# -> 50
print(result.structured_content["_authz"]["rejected"][0]["policy"])
# -> alice-amount
print(result.structured_content["status"])
# -> pending
```

The refund row the desk wrote carries the **50**, which is the part worth dwelling on: the side
effect that really happened is the one policy settled on, not the one the caller proposed. Its
`refund_id` is allocated by the desk, so it counts on from the refunds already there — which is
why the self-drive resets first and these snippets do not promise a particular id. It is written
`pending` because booking a refund and approving one are two calls under two different policies,
and a row that waits between them is what lets the next section show the second decision.

Push past the desk limit and the *gate* refuses instead — by a `forbid` that reads the proposed
`amount` **and** the principal at once:

```python
call = {"order_id": "ord-0007", "amount": 5000, "region": "eu"}
print((await client.call_tool("issue_refund", call, meta=ALICE)).is_error)
# -> True
print((await client.call_tool("issue_refund", call, meta=DANA)).is_error)
# -> False
```

Same call, same policy, and dana is exempted by its last clause because she is an admin. A
`forbid` that fires is determining, so alice's envelope names it at `verbosity="debug"`:
`determining_policies == ['refunds-above-the-desk-limit-need-an-admin']`. The permit underneath
it is unconditional on purpose — the manifest section below is what that buys.

### Two refusals that are not the gate

Both come from the argument layer, *after* the gate said yes. They still carry an `_authz`
block — built from the refusal itself rather than from a decision — so neither names an action
or a resource: there was no denied decision to name. What it carries instead is which arguments
were refused, and, for `NoValidArguments`, an `allowed` block describing what the principal may
pass. `allowed` appears on no allowed call's envelope, which makes it the tell that you are
reading an exception-derived report.

**Nothing the caller sent survived.** Narrowing refines a proposal; it does not rescue one:

```python
call = {"order_id": "refund-me", "amount": 900}
result = await client.call_tool("issue_refund", call, meta=ALICE)
print(result.structured_content["error"])
# -> NoValidArguments
print(result.content[0].text)
# -> Every supplied argument was rejected by policy.
print([item["name"] for item in result.structured_content["_authz"]["rejected"]])
# -> ['order_id', 'amount']
print(sorted(result.structured_content["_authz"]["allowed"]))
# -> ['amount', 'order_id', 'region']
```

`allowed` is what the caller may pass instead, which is what a model needs in order to retry.

**Rejected, with nothing to refill from.** Alice's `order_id` constraint is a pattern with no
default, so a malformed id is refused rather than replaced by one nobody asked for:

```python
call = {"order_id": "refund-me", "amount": 100, "region": "eu"}
result = await client.call_tool("issue_refund", call, meta=ALICE)
print(result.structured_content["error"])
# -> DefaultUnavailable
print(result.content[0].text)
# -> Argument 'order_id' is required and no policy default is configured.
```

Here `amount=100` survived, so the call was not refused for want of arguments — it was refused
because the one that failed had no answer available.

### The role gate, and the same call for two principals

```python
print((await client.call_tool("search_orders", {}, meta=BOB)).is_error)
# -> True
print((await client.call_tool("approve_refund", {"refund_id": "rf-0002"}, meta=DANA)).is_error)
# -> False
print((await client.call_tool("approve_refund", {"refund_id": "rf-0002"}, meta=ALICE)).is_error)
# -> True
```

Dana's answer is the settled refund, carrying `'approved_by': 'dana'` — the desk's admin *of
record*, resolved from its own roster, because the desk is never told who called it. Which
principal was authorized to approve this is in the audit trail instead, where it cannot drift
out of step with the decision that permitted it. Approving twice is not an error and does not
change the approver, and a refund id the desk does not hold comes back as `'found': False`.

These are the refusals that **name nothing**. No permit reaches bob for `orders.search`, and
none reaches alice for `refunds.approve`, so no policy was determining, the request falls
through to Cedar's default deny, and `determining_policies` is empty even at
`verbosity="debug"`. It is worth knowing before you go looking for the policy id that refused a
call — when nothing permitted it, there is not one. A refusal by a `forbid` is the other shape,
and always names the `forbid` that fired.

### The manifest is per-principal

```python
print([tool.name for tool in (await client.list_tools(meta=ALICE)).tools])
# -> ['desk_status', 'brief_orders', 'search_orders', 'read_order', 'issue_refund']
print([tool.name for tool in (await client.list_tools(meta=BOB)).tools])
# -> ['desk_status', 'export_orders']
print([tool.name for tool in (await client.list_tools(meta=DANA)).tools])
# -> ['desk_status', 'brief_orders', 'search_orders', 'read_order', 'issue_refund', 'approve_refund']
print([tool.name for tool in (await client.list_tools(meta={})).tools])
# -> []
```

`issue_refund` is the one to read twice. It is in alice's and dana's manifests and absent from
bob's, and the shape of `20-refunds.cedar` is why. The permit that authorizes it is
**unconditional**, so a probe proposing no arguments still reaches it, and neither `forbid`
fires on a proposal with no `amount` in it. Bob has no permit for the action at all, so the gate
refuses him and he is not shown the tool.

Write the desk limit as a `when` on that permit instead and the permit depends on
`context.args has amount`. A manifest probe carries no arguments, so the honest manifest-time
answer becomes *would be refused* — and `issue_refund` vanishes from every manifest while still
working perfectly well at dispatch. Permit broadly, forbid narrowly: the same decision, and a
tool the model can still see.

Alice's and dana's probes are not clean allows, either. `order_id` is required and has no
default, so the probe raises `DefaultUnavailable` — the *argument* layer answering after the
gate said yes. That refusal deliberately hides nothing; see the invariant below.

### Hiding is not the enforcement

Bob ignores the manifest and calls a hidden tool by name. He is refused exactly as if it had
never been hidden:

```python
result = await client.call_tool("read_order", {"order_id": "ord-0003"}, meta=BOB)
print(result.is_error, result.structured_content["error"])
# -> True AuthzDenied
print(result.structured_content["_authz"]["resource"])
# -> Order::"ord-0003"
```

### Break one edge and the access goes with it

Alice keeps her team and her role, the policy keeps its wording, and only
`Team::"eu-support" -> Division::"emea"` is gone:

```python
async with Client(create_server(severed=True)) as client:
    print([tool.name for tool in (await client.list_tools(meta=ALICE)).tools])
    # -> ['desk_status', 'brief_orders', 'search_orders', 'issue_refund']
    result = await client.call_tool("read_order", {"order_id": "ord-0003"}, meta=ALICE)
    print(result.is_error, result.structured_content["error"])
    # -> True AuthzDenied
    result = await client.call_tool("search_orders", {}, meta=ALICE)
    print(result.is_error, result.structured_content["region"])
    # -> False eu
```

The relationship *was* the authorization. Her role gate is untouched.

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
entitlement stays visible too: `read_order` and `issue_refund` both need arguments a manifest
probe has not got, and hiding them for that reason would hide them from everybody.

That is also why the desk limit is a `forbid` and not a `when` on the permit. A permit
conditional on `context.args` is unreachable by a probe that proposes nothing, which turns an
argument question into an entitlement answer and hides a tool the principal may in fact invoke.

## Register with `governed_tool`, and never with a bare `@server.tool()`

This is the one sharp edge, so it is worth stating plainly: **a `@protect`-ed callable handed
straight to `@server.tool()` will have its refusals swallowed.** mcp's `Tool.run` wraps whatever
the body raised in a `ToolError` and `MCPServer._handle_call_tool` turns that into an error
result with `structuredContent: null` — so the model gets the string `"Error executing tool …"`
and the `_authz` envelope is gone before any middleware can see it. The gate still ran and the
side effect was still refused; the model is just told nothing it can act on.

`governed_tool` registers the tool behind two thin layers that each solve one measured problem:

- **An omittable-argument shim.** mcp validates a proposal against the advertised schema
  *before* the body runs, so `search_orders(region, limit, status="open")` — whose first two
  parameters declare no Python defaults on purpose — could never be called with none of them,
  and default injection would be unreachable from a model. The shim advertises exactly the
  policy-suppliable parameters as optional and forwards only what was genuinely proposed, so an
  omission arrives at the decorator *as an omission*. That is why the empty call above returns
  `eu`/`10` with both names in `defaults_applied`.
- **A refusal translator.** An `MCPError` is the one exception `_handle_call_tool` re-raises
  rather than swallowing, so a refusal travels out of the tool body as one and the middleware
  renders it as a `CallToolResult` carrying the envelope.

Both layers keep `__wrapped__` pointing at the protected callable, so the manifest filter still
finds its `@protect` metadata — and `governed_tool` **returns the protected callable
unchanged**, so it is still directly callable from the rest of the program under an established
context. Registering a tool does not take a function away from you.

The decision itself is made once, by the decorator, on the arguments the caller actually
proposed. Nothing re-decides and nothing reconstructs the envelope, so **one dispatch writes
exactly one audit record** per protected callable it entered.

One thing to know about the boundary: mcp materializes a schema default before dispatch, so a
parameter carrying a Python default — `status`, `scope` — arrives at the decorator as a
proposed argument whether or not the caller named it. An *omittable* parameter is advertised as
nullable instead, and the shim reads that `null` as *not proposed*, which is how an omission
stays an omission across the wire.

## The optional local model

The server is model-agnostic and stays that way: a server exposes governed tools, and a client
drives it. The last section of the self-drive is the client half. It takes the **filtered**
manifest from `list_tools`, converts those schemas into Ollama's `tools=[…]` form, lets a local
model choose, and dispatches whatever came back through the same governed path:

```
--- the model proposes; the policy decides ---
  model: gemma4:e4b at http://localhost:11434

  [alice] Search the orders desk for up to 500 CN orders.
    offered   ['desk_status', 'brief_orders', 'search_orders', 'read_order']
    proposed  search_orders(limit=500, region='CN')
    policy    allowed  narrowed: region='CN' rejected by allow-set/alice-region -> refilled with 'eu'; narrowed: limit=500 rejected by maximum/alice-limit -> refilled with 10
```

Two live-proposed values, both refused, both refilled from alice's own grants — and the model
was never asked to behave.

To run that half:

1. install [Ollama](https://ollama.com) — no API key, no account;
2. pull a tool-capable model, for example `ollama pull qwen2.5:3b`;
3. optionally pin one with `SENTRYKIT_OLLAMA_MODEL`, or point at another daemon with
   `SENTRYKIT_OLLAMA_URL`.

Setting `SENTRYKIT_OLLAMA_URL` to an *empty* value turns the search off outright — no socket is
opened and the in-process drive above is the whole demonstration. That is how the test suite
stays hermetic, and it is also the switch to reach for when you have a daemon and want the
reproducible run anyway.

With no daemon reachable the section says so and the run continues:

```
--- the model proposes; the policy decides ---
  no tool-capable model answered at http://127.0.0.1:1.
  the deterministic drive above is the whole demonstration: every outcome in it
  is decided from the principal and the proposed arguments, never from which
  model proposed them. Install Ollama and pull a tool-capable model to see a
  real proposal here, or pin one with SENTRYKIT_OLLAMA_MODEL.
```

The fallback is not a lesser mode. Every authorization outcome is identical either way, because
the decision is made from the principal and the proposed arguments and never from which model
proposed them.

A small local model sometimes proposes a malformed call, a tool it was never offered, or
nothing at all. Any failure in that section prints one line and the run carries on — the
proposal being refused is exactly the point, and it is left visible rather than tidied away.
Two things are worth watching for while it runs. Cedar compares strings exactly, so a policy
written against `"pdf"` does not match a model that writes `"PDF"`; and how a value is spelled
is the model's choice, never the policy's.

Nothing in `create_server()` or `build_grants()` probes for a model, so importing this module
never touches a network. Only the self-drive does.
