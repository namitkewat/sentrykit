# Agent tooling

sentrykit governs an agent's tool calls with the same decorator that governs a Flask view. The
model *proposes* a call; the policy *decides* it — not only whether it may run, but which of the
proposed arguments survive and what to fill in for the rest. Nothing about a protected
function's body knows it is being invoked by a language model.

Two integrations ship, behind two extras:

```bash
pip install "sentrykit[mcp]"            # MCP tool servers
pip install "sentrykit[pydantic-ai]"    # Pydantic-AI agents
```

!!! note "`sentrykit[mcp]` installs `mcp>=2,<3`, and nothing else"
    The extra, the `sentrykit.integrations.mcp` module and the `mcp://` DSN all name that one
    distribution. Two names you may meet elsewhere are not it: mcp 2.0 renamed its own
    ergonomic server class `mcp.server.fastmcp.FastMCP` → `mcp.server.mcpserver.MCPServer`, so
    a 1.x snippet imports a class that is gone; and the separately published `fastmcp` project
    is a different library, which dropped `mcp` as a dependency and carries its own
    tool-authorization parameter. You need neither to use this page.

## The model proposes; the policy narrows

A gate that answers only yes or no leaves an agent one move: attempt the call and find out. The
decision sentrykit reaches is per argument as well as per call, so a value above what the
principal may have is *narrowed* rather than refused — the offending value is dropped and,
where the principal's grant holds a default, that default takes its place — and the call
proceeds. Where it holds none, the argument simply has no proposed value: the tool's own
default applies, or a required argument with nothing to fill it raises `DefaultUnavailable`.
The `_authz` envelope on the result names which arguments were narrowed and why.

That is what a model can act on. A refusal ends the attempt
and leaves the model guessing which part of its proposal was the problem; a narrowed result
carrying the reasons lets it continue, and tells it what it may ask for instead.

Narrowing *refines* a proposal rather than rescuing one. If every argument the model supplied is
rejected, the call is refused with `NoValidArguments` instead of being completed from defaults,
because completing it would answer a question nobody asked — see [errors](concepts.md#errors).
The bounds themselves come from two places that intersect: a grant says what *this* principal
may pass, and a `@constraints` annotation on a reviewed `permit` says what *anybody* may pass
for that action. See [argument ceilings](policies.md#argument-ceilings).

What that is worth against a model reading hostile text is measured rather than asserted:
[attack scenarios](scenarios.md) plants an instruction in a ticket thread, lets a model propose
what it likes, and runs the proposal both with the policy and without it.

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
never a control: the dispatch path re-runs the identical decision, so a client that skips the
manifest is refused just the same.

A callable with no `@protect` wrapper carries no action and no argument spec, so there is
nothing to decide about it. It is left **visible**: sentrykit does not silently hide a tool its
author never asked it to govern.

## MCP tool servers

```python
from mcp.server.mcpserver import MCPServer

from sentrykit import configure, install
from sentrykit.decorator import protect
from sentrykit.integrations.mcp import MCPProvider, governed_tool, protect_server


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
    provider = MCPProvider(grants=store)
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

provider = MCPProvider(identify=authenticated_principal, grants=store)
```

A provider built with no `identify` logs one `WARNING` when it is constructed, naming itself
and the key its fallback ends at. Both shipped agent examples emit it on startup, because both
take the example path on purpose; it disappears as soon as `identify=` is supplied. It is a
wiring-time line, not a per-request one.

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


result = await agent.run("what is on order ord-0003?", deps=Caller(principal="alice"))
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

Per-principal **default injection** is the other half of the narrowing above: an argument the
model omitted — and one that was just dropped — is filled in from what policy says this
principal may have. A default is itself checked against the constraint it belongs to and
withheld if it fails, so omitting an argument is not a way around the rule that governs it.
Reaching any of this from an agent takes one extra step, for a reason that is worth
understanding.

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

### A parameter with a Python default arrives whether or not the model proposed it

This is a property of the agent boundary itself, and it is worth knowing before you reason
about which refusals your tools can produce.

Both frameworks **materialize the advertised schema's defaults** before dispatch. A parameter
carrying a Python default is not made omittable — it needs no policy value, because it has one
of its own — so it is advertised with that value as the schema default, and the framework fills
it in. By the time `@protect` runs, it is a *proposed* argument. An omittable parameter is
advertised as nullable with a default of `null` instead, and the shim reads that `null` as *not
proposed* and drops it, which is how an omission survives the crossing.

The consequence is a difference in reachable refusals. `NoValidArguments` fires when every
argument the caller proposed was rejected, so at a web boundary — where a route forwards only
what the caller actually sent — proposing one argument that is then rejected is enough to reach
it. At an agent boundary that same call is not refused, because a parameter with a Python
default arrived alongside and survived filtering. Given
`export_orders(fmt: str, scope: str = "open")` and a principal whose `fmt` deny-set rejects
`xml`, an MCP or Pydantic-AI dispatch of `export_orders(fmt="xml")` runs:

```python
result = await client.call_tool("export_orders", {"fmt": "xml"}, meta=BOB)
print(result.structured_content["_authz"]["processed"])
# -> {'scope': 'open', 'fmt': 'csv'}
print(result.structured_content["_authz"]["rejected"][0]["rule"])
# -> deny-set
```

`scope` is in `processed` even though nothing proposed it. To reach `NoValidArguments` from an
agent, every parameter of the tool has to be one policy could supply — which is to say, none of
them may carry a Python default. Both agent examples reach it through `issue_refund`, whose
three parameters are all omittable, by proposing two arguments that are both rejected.

The same property makes `SignatureDefaultRejected` rare here and common at a web boundary. That
refusal fires when a governed parameter ends up with *no* value and the callable's own default
is one the constraint refuses — but at an agent boundary a Python default has already arrived
as a proposed argument, so it is filtered on the way in and reported as an ordinary rejection
rather than discovered in the gap afterwards. A tool whose governed parameters are all
omittable never meets it. One that mixes the two can: give a parameter both a constraint and a
Python default the constraint refuses, and the refusal is the same one a route would get.

## Relationships are resolved by the policy, not by the model

Underneath the argument layer is Cedar's entity hierarchy, and the two compose. Nested
relationships — user → team → project → resource, delegation, on-behalf-of — are resolved
deterministically by that hierarchy rather than by application `if` statements, and never by the
model. The MCP example shows it: `read_order` is permitted by a single policy that names only
the far end of a four-hop chain:

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

* **Allowed.** Alice's `read_order("ord-0003")` succeeds, through edges no policy names.
* **Denied when the edge is absent.** Bob's chain is just as long and lands on a different
  project, so the same call is refused — and `read_order` is not in his manifest.
* **Denied when the edge is severed.** Detach the team from its division, change nothing else,
  and alice loses the access while her unrelated role-gated tools keep working.

Run it:

```bash
pixi run -e agent run-mcp
```

## Running the examples

`examples/mcp_server/` and `examples/pydantic_ai_agent/` govern the same orders-and-refunds
desk the web examples do — the same three principals, the same grant data, the same reviewed
policy directory — at an agent boundary instead of an HTTP one. Seven governed tools, plus one
protected callable that is deliberately registered as no tool at all.

```bash
pixi run -e agent run-mcp        # the MCP tool server
pixi run -e agent run-agent      # the Pydantic-AI agent
```

Each drives itself and prints what policy did to 22 calls. Policy logic comes off disk, which
is what puts the argument ceiling under review beside the `permit` it hangs on:

```python
install(
    policy_source=FilesystemPolicySource(POLICY_DIR),
    grant_store=store,
    context_provider=provider,
)
```

Both call `configure(verbosity="verbose")` so the envelope carries processed values, applied
defaults and rejection reasons — the model is one of the audiences for that explanation, and it
is what lets it choose a different call rather than guess. A service in production would leave
that at `summary`.

The MCP server drives itself over an in-memory transport when a human runs it at a terminal,
and serves over stdio when its stdin is a pipe — so the whole demonstration runs with no socket
and no client to install. Identity is a stub on both: MCP callers name themselves in the
request's `_meta` under `x-sentrykit-principal`, and the Pydantic-AI agent takes the principal
from `deps`.

### The manifest is answered per principal

The Pydantic-AI example observes the manifest as the *model* is given it, by running one turn
on a `FunctionModel` that proposes nothing and reports `AgentInfo.function_tools`:

```
alice : desk_status, brief_orders, search_orders, read_order, issue_refund
bob   : desk_status, export_orders
dana  : desk_status, brief_orders, search_orders, read_order, issue_refund, approve_refund
```

The MCP example answers `tools/list` the same way, and adds the anonymous case:

```
  alice        ['desk_status', 'brief_orders', 'search_orders', 'read_order', 'issue_refund']
  bob          ['desk_status', 'export_orders']
  dana         ['desk_status', 'brief_orders', 'search_orders', 'read_order', 'issue_refund', 'approve_refund']
  (anonymous)  []
```

`issue_refund` is the entry to read twice. It is in alice's manifest and absent from bob's, and
the shape of the refunds policy is why: the permit authorizing it is unconditional, so a probe
that proposes nothing still reaches it, and neither `forbid` over it fires on a proposal with
no `amount` in it. Bob has no permit for the action at all. Fold the desk limit into a `when`
on that permit and it would depend on `context.args has amount` — false for a probe that
proposed nothing — and the tool would vanish from every manifest while still working perfectly
at dispatch. Permit broadly, forbid narrowly.

### Every flow, decided

This is what `run-agent` prints. The MCP server prints the same 22 flows in its own format:

```
  #  who    call                                                         outcome
  1  alice  desk_status()                                                allowed
  2  alice  brief_orders()                                               allowed
  3  alice  search_orders()                                              defaulted: region='eu', limit=10
  4  alice  search_orders(region='cn', limit=5)                          narrowed: region='cn' rejected (allow-set, alice-region) -> region='eu'
  5  alice  search_orders(limit=500, status='open')                      narrowed: limit=500 rejected (maximum, alice-limit) -> limit=10; defaulted: region='eu'
  6  dana   search_orders(limit=500, status='open')                      narrowed: limit=500 rejected (maximum, support-may-search) -> limit=25; defaulted: region='eu'
  7  alice  read_order(order_id='ord-0003')                              allowed
  8* bob    read_order(order_id='ord-0003')                              denied: The policy denied action Action::"orders.read".
  9  bob    export_orders(fmt='csv')                                     allowed
 10  bob    export_orders(scope='open')                                  defaulted: fmt='csv'
 11  bob    export_orders(fmt='xml', scope='open')                       narrowed: fmt='xml' rejected (deny-set, bob-fmt) -> fmt='csv'
 12  alice  issue_refund(order_id='refund-me', amount=900)               NoValidArguments: Every supplied argument was rejected by policy.
 13  bob    export_orders(fmt='pdf')                                     denied: The policy denied action Action::"orders.export".
 14* bob    search_orders()                                              denied: The policy denied action Action::"orders.search".
 15  alice  issue_refund(order_id='ord-0007', amount=100, region='uk')   allowed
 16  alice  issue_refund(order_id='ord-0007', amount=750, region='uk')   denied: The policy denied action Action::"refunds.issue".
 17  alice  issue_refund(order_id='ord-0007', amount=900, region='eu')   narrowed: amount=900 rejected (maximum, alice-amount) -> amount=50
 18  alice  issue_refund(order_id='ord-0007', amount=5000, region='eu')  denied: The policy denied action Action::"refunds.issue".
 19  dana   issue_refund(order_id='ord-0007', amount=5000, region='eu')  allowed
 20  alice  issue_refund(order_id='refund-me', amount=100, region='eu')  DefaultUnavailable: Argument 'order_id' is required and no policy default is configured.
 21  dana   approve_refund(refund_id='rf-0002')                          allowed
 22* alice  approve_refund(refund_id='rf-0002')                          denied: The policy denied action Action::"refunds.approve".
```

A starred row is a tool hidden from that principal's manifest, so no model could have proposed
it — the example dispatches it by name with no model in the loop, and the gate refuses it
exactly as if it had never been hidden. That is the second half of the filtering guarantee,
exercised rather than asserted.

### The ceiling, and why the answer is never the ceiling

Flows 5 and 6 are the same proposal from two people. `policies/10-orders.cedar` declares an
[argument ceiling](policies.md#argument-ceilings) on the permit that lets support search:

```cedar
@id("support-may-search")
@constraints("{\"limit\": {\"maximum\": 100}}")
permit (
  principal in Role::"support",
  action == Action::"orders.search",
  resource == Tool::"orders"
);
```

`@constraints` is a **Cedar policy annotation, not a Python decorator** — text carried on the
policy, parsed when the directory loads. It grants nobody anything. It says what *anybody*
reaching this permit may pass, and it **intersects** with the caller's own grant, so a grant
can tighten it and can never loosen it. Alice's grant caps `limit` at 50, tighter than the
reviewed 100, so hers is the bound that reports; dana's grant sets only a default, so the
reviewed ceiling is her only bound and the rejection names `support-may-search`.

`run-agent` spells that case out on its own, because it is the one most easily misread:

```
dana proposed limit=500.
The ceiling declared in policies/10-orders.cedar is 100.
She ran with limit=25, which is her own default.
```

The value that breached the ceiling was **rejected** and dana's own default was put in the gap.
The result is her default; it bears no relation to the bound that refused her, and nothing is
ever trimmed to that bound. That is what makes a narrowed result something a model can act on:
it is told what it asked for, what refused it, and what it got instead.

### Several arguments decided in one call

Flow 5 puts all three parts of the argument layer in one envelope:

```python
result = await client.call_tool("search_orders", {"limit": 500, "status": "open"}, meta=ALICE)
print(result.structured_content["_authz"]["processed"])
# -> {'status': 'open', 'region': 'eu', 'limit': 10}
print(result.structured_content["_authz"]["rejected"][0]["reason"])
# -> Value is above the maximum of 50
print(result.structured_content["_authz"]["defaults_applied"])
# -> {'region': 'eu', 'limit': 10}
print(result.structured_content["_authz"]["narrowed_arguments"])
# -> ['limit']
print(result.structured_content["_authz"]["guidance"])
# -> This result is valid and was served. The authorization policy adjusted limit before
#    the call ran, because the proposed value is not one this principal may use. Report the
#    result as delivered and say which parameters were adjusted; do not retry with the
#    original values.
```

`limit` was proposed, rejected and refilled; `region` was never proposed and was injected;
`status` was left alone because no constraint governs it. Only `limit` is in
`narrowed_arguments`, and that is the field a model should act on: `region` appearing in
`defaults_applied` is not an adjustment to anything the model asked for.

The `guidance` sentence is there for the model, and it is the difference between a tool result
a model relays and one it suppresses. Measured across seven language models on this exact
scenario, over four samples, pairing every run by `(sample, model)`: an envelope carrying only
`rejected` served the user real data in 50% of runs, and the same payload with the outcome
fields added served it in 79% — the two differ in 8 of 28 paired runs, and **all 8 favour the
outcome fields** (exact two-sided sign test, p = 0.0078). Twenty contrasts were computed over
that one corpus, and against a Holm family-wise correction across them this does not clear:
adjusted, it is 0.117. Quote both numbers wherever you quote either. The fields are worth
keeping on what the comparison *is* — the same narrowing reported two ways, so the reporting is
the only variable — rather than on the margin. Where the return type leaves no room for them the
adapters carry them out of band instead, and the two channels measured the same.

The result that needs no such caveat is the one about refusing: a tool that refuses an
out-of-range argument and hands back the permitted range served the user real data in **0 of
28 runs**, every model and every sample, and that is the only kind of contrast here that
survives a family-wise correction. Narrowing and reporting it is the alternative to that.

The contrast lives in the signature —
`search_orders(region: str, limit: int, status: str = "open")` — and it is the design rule
worth copying: a value **policy** decides carries no Python default, so it stays omittable and
a policy default can reach it. A value that is the caller's own business keeps its Python
default and never troubles the policy layer.

Flow 3 reaches the same two values by the other route: the model proposes nothing, so both
governed arguments turn up in `defaults_applied` and neither in `rejected`. That distinction is
the difference between a model that can report honestly on what it did and one that cannot. Its
`processed` is `{'status': 'open', 'region': 'eu', 'limit': 10}` all the same — `status` came
from the schema default, which is the boundary behaviour described above.

### Two rules that read more than the principal

The refunds policy permits support to issue refunds unconditionally and puts two narrow
`forbid` rules over it. Neither is expressible as a per-argument constraint.

**One argument together with the principal.** Flows 18 and 19 are the same call from two
people: `refunds-above-the-desk-limit-need-an-admin` refuses anything over 1000 from a caller
who is not an admin, and dana is exempted by its last clause because `Role::"admin"` has
`Role::"support"` as a parent.

**Two arguments against each other.** Flows 15 and 16 differ only in the amount, and each value
is fine alone — 750 is inside alice's range of 1–750, and `uk` is one of her permitted regions
— while the pair trips `no-large-cross-region-refunds`, which forbids anything over 200 booked
outside `eu`. Nothing in either tool body compares the two. Cedar receives the whole proposal
as `context.args` and answers about all of it at once.

Flow 17 separates the gate from the argument layer, which is easy to conflate: at `amount=900`
the gate says yes, because 900 is under the desk limit — and alice's own grant then rejects the
value and refills it with 50.

Both refusals are **named**, because a `forbid` that fires is determining. `run-agent` re-runs
three of them at `verbosity="debug"`, where the envelope carries `determining_policies`:

```
13  bob    export_orders(fmt='pdf')       denied: The policy denied action Action::"orders.export". [no-pdf-exports]
18  alice  issue_refund(.., amount=5000)  denied: The policy denied action Action::"refunds.issue". [refunds-above-the-desk-limit-need-an-admin]
14  bob    search_orders()                denied: The policy denied action Action::"orders.search".
```

Flow 14 is the other shape and names nothing: no permit matched bob at all, so the decision is
Cedar's default deny and nothing was determining. When nothing permitted a call there is no
rule to point at, and reporting one would be inventing it. Flow 8 reads the same way.

### Reject-and-refill from a deny-set

Bob's `fmt` constraint is a deny-set with a default — the mirror image of an allow-set:
everything passes except what is named. Flow 11 proposes `xml`, and the export runs on `csv`:

```python
result = await client.call_tool("export_orders", {"fmt": "xml", "scope": "open"}, meta=BOB)
print(result.structured_content["fmt"])
# -> csv
print(result.structured_content["_authz"]["rejected"][0]["rule"])
# -> deny-set
```

Flow 13 proposes `pdf` and is refused at the gate instead. Cedar sees the caller's **raw**
proposal, before any per-principal filtering, so a `forbid` reading `context.args.fmt` fires on
what the model actually wrote. Bob may export; he may not export a PDF.

Flow 12 is where `NoValidArguments` becomes reachable at this boundary, and it takes a tool
whose every parameter is omittable — see [the note above](#a-parameter-with-a-python-default-arrives-whether-or-not-the-model-proposed-it).
Both proposed arguments are rejected, so nothing the caller sent survives:

```python
result = await client.call_tool("issue_refund", {"order_id": "refund-me", "amount": 900}, meta=ALICE)
print(result.structured_content["error"])
# -> NoValidArguments
print([item["name"] for item in result.structured_content["_authz"]["rejected"]])
# -> ['order_id', 'amount']
print(sorted(result.structured_content["_authz"]["allowed"]))
# -> ['amount', 'order_id', 'region']
```

The `allowed` block is what the principal may pass instead, which is exactly what a model needs
in order to retry. It appears on no permitted call's envelope, which makes it the tell that a
report was built from a refusal rather than from a decision — such a report names no action and
no resource, because the gate had already said yes.

Flow 20 is the refusal with nothing to fall back on. Alice's `order_id` constraint is a pattern
with **no default**, so a malformed id is dropped and nothing can fill the gap:
`DefaultUnavailable`, with the detail `Argument 'order_id' is required and no policy default is
configured.` Here `amount=100` survived, so the call was not refused for want of arguments — it
was refused because the one that failed had no answer available.

### The bare `@protect`, and a protected callable that is not a tool

Flow 1 calls `desk_status`, decorated with a bare `@protect`. With no `action=` and no
`resource=`, sentrykit derives both from the callable's import path, and the reviewed policy
names the derived action verbatim:

```python
result = await client.call_tool("desk_status", {}, meta=ALICE)
print(result.structured_content["_authz"]["action"])
# -> Action::"examples.mcp_server.service.desk_status"
print(result.structured_content["_authz"]["resource"])
# -> Resource::"examples.mcp_server.service.desk_status"
```

Convenient, and fragile in one specific way: renaming or moving the function changes the id the
policy has to match. Pass an explicit `action=` as soon as the policy is expected to outlive
the module layout.

Flow 2 is the one that shows the gate is on the *call* and not on the registration.
`brief_orders` is a registered tool; the `summarize_orders()` its body calls is protected and
registered nowhere, so no model was ever told it exists and none could propose it. It is
decided anyway, against the same ambient principal:

```
outer  Action::"orders.brief"  allow
inner  Action::"orders.summarize"  allow
```

One dispatch, two decisions, two audit records — and the outer record is written **before** the
body runs, so a refusal inside cannot erase the fact that the outer call was permitted. Had the
inner decision been a refusal, its `AuthzDenied` would have travelled out through
`brief_orders` unchanged rather than becoming a partial answer.

The MCP example also severs one entity edge and reruns: detach `Team::"eu-support"` from
`Division::"emea"`, change nothing else, and `read_order` leaves alice's manifest and her
dispatch is refused, while `search_orders` — gated by her role, not by that chain — keeps
working. The relationship *was* the authorization.

## The optional live model

Both agent examples run on a real model when one is within reach, and on a deterministic
stand-in otherwise. Each prints which it is using. Three tiers are tried in order, and the
authorization outcome is the same whichever of them answers.

**A frontier model, over OpenRouter.** Put an `OPENROUTER_API_KEY` in a `.env` file at the
repository root. That file is read directly, so nothing has to be exported into a shell
profile, and it is the one place a key belongs. `SENTRYKIT_OPENROUTER_MODEL` pins which model
to ask for; `SENTRYKIT_OPENROUTER_URL` names the endpoint, or turns the tier off when set to
an **empty** value.

**A local daemon**, which needs no key and no account:

1. install [Ollama](https://ollama.com);
2. pull a model whose template supports tools, for example `ollama pull qwen2.5:3b`;
3. optionally pin one with `SENTRYKIT_OLLAMA_MODEL`, or point at a daemon that is not on
   `http://localhost:11434` with `SENTRYKIT_OLLAMA_URL`.

Tool support is a property of the model's template rather than of Ollama, so the examples ask
the daemon which installed models advertise it and fall back cleanly when none does. A pinned
name the daemon does not have is treated as *no pin* rather than as an error, because a typo in
an environment variable should not stop an example running.

**A deterministic stand-in.** With neither live tier reachable, the Pydantic-AI example runs
the free-form section on `pydantic_ai.models.test.TestModel`, which calls every visible tool
with generated arguments, and the MCP example says there is no model and stops there. Both say
why, and both halves of the answer appear because "no model" has two independent causes:

```
model: TestModel
  -- no OPENROUTER_API_KEY is set, and locally the search for one is turned off (SENTRYKIT_OLLAMA_URL is set to an empty value)
```

**Every authorization outcome is identical whichever tier answers**, because a decision is made
from the principal and the proposed arguments and never from which model proposed them. The
fallback is not a lesser mode; what a live model adds is that the proposal is genuinely the
model's — it picks the tool and drafts the arguments itself.

Setting either URL to an **empty** value turns that tier off outright: no socket is opened and
no model is found, so the deterministic path is taken. That is how the test suite stays
hermetic — an example's behaviour must not depend on what happens to be listening on the
machine running it, still less on whether whoever ran it keeps a key in `.env` — and it is also
the switch to reach for when you have a daemon and want the reproducible run anyway. The key
is emptied there too, because an absent `OPENROUTER_API_KEY` sends the examples to `.env`,
where a developer's real one lives.

A small local model will sometimes propose a malformed call, a tool it was never offered, or
nothing at all. The examples print that and carry on: sentrykit refusing a call the model
should not have proposed is the point, not a failure of the demonstration. Two things are worth
watching for while it runs. Cedar compares strings exactly, so a policy written against `"pdf"`
does not match a model that writes `"PDF"` — and how a value is spelled is the model's choice,
never the policy's.

Nothing probes for a model at import, in either example: importing the module opens no socket.
The MCP server is model-agnostic throughout — `create_server()` exposes governed tools and a
client drives them, so only its self-drive ever looks for a daemon. The agent needs a model to
be built at all, so `build_agent()` is where its probe happens, and passing `build_agent(model)`
explicitly skips it.
