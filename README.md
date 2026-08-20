# sentrykit

Framework-agnostic **authorization** for Python, built on
[AWS Cedar](https://www.cedarpolicy.com/). Clip a `@protect` decorator onto any callable — a
web route, a plain function, an agent tool — and sentrykit decides, per call, whether the
principal may invoke it, **which arguments they may pass**, and **which defaults to inject
when they pass none**; then narrows an over-broad request rather than refusing it — the value
the principal may not have is rejected and their own default fills the gap — and writes a
masked, hash-chained record of what it decided.

> The caller *proposes*; the **policy decides** — and what it decides includes the arguments,
> not only the call.

It targets two worlds with one decorator:

- **Web frameworks** — FastAPI, Flask (more to come).
- **Agent tooling** — FastMCP servers, Pydantic-AI (more to come).

What that gives you, in the order it matters:

- **Per-(principal, action) argument constraints.** Allow-sets, deny-sets, patterns and numeric
  bounds, resolved for the principal and the action, one argument at a time.
- **Narrow-and-continue instead of refuse.** A value above what the principal may have is
  rejected and their own default fills the gap, so the call proceeds instead of being turned
  away.
- **Policy-supplied default injection.** Arguments the caller omitted — and arguments that were
  just dropped — are filled in from what policy says this principal may have.
- **Grant-time constraint validation.** A constraint no value could satisfy, or whose own
  default it would reject, is refused when it is written rather than found by whoever calls
  next.
- **A masked, hash-chained audit trail.** One record per decision and per admin mutation,
  masked *before* the append-only write and pinned to a hash of the exact policy text.

Across the first four sits one more: **argument ceilings declared in reviewed policy text**. A
`.cedar` file says what *anybody* may pass for an action, the grant store says what *this*
principal has, and the two intersect — so the reviewed file states the maximum and can only
narrow.

sentrykit sits at the **action layer**: it refuses the side effect *before* it happens, rather
than inspecting what a model has already produced. It is self-hosted, Cedar-based, and
audit-first.

General-purpose policy engines — Cedar, including Amazon Verified Permissions, as well as OPA
and Casbin — and relationship-based systems such as OpenFGA answer a boolean question at the
gate: may this principal perform this action on this resource. sentrykit is built on one of
them, and adds the layer above that decision: which arguments the call may carry, which
defaults to supply when the caller omits them, and a record of both. If you already run a
policy engine, that argument layer is the part you would otherwise assemble yourself.

> **Status: 0.2.0 — everything below works.** `@protect`, ambient context, the Cedar gate,
> argument filtering, policy-declared **argument ceilings**, default injection, **constraint
> validation at the write**, signature validation and the `_authz` envelope; the three
> pluggable stores with entry-point discovery; masking and the tamper-evident audit log; the
> **FastAPI, Flask, MCP and Pydantic-AI** providers with four runnable example apps; the
> **shipped policy pack**; and the `sentrykit` command line. Not yet shipped: the durable WORM
> audit backends (S3 Object Lock, Iceberg) — those are a `Protocol` away rather than built.

## Install (once published)

```bash
pip install sentrykit                 # core
pip install "sentrykit[fastapi]"      # + FastAPI provider
pip install "sentrykit[flask]"        # + Flask provider
pip install "sentrykit[fastmcp]"      # + FastMCP provider
pip install "sentrykit[pydantic-ai]"  # + Pydantic-AI provider
pip install "sentrykit[all]"          # everything
```

The only pinned core dependency worth knowing about is **`cedarpy >= 4.8, < 5`**: the engine
parses a policy set, an entity graph and a schema once at wiring time and reuses the handles,
and releases below 4.8 do not expose those. See
[which cedarpy](docs/quickstart.md#which-cedarpy).

## The idea in 20 seconds

```python
from sentrykit import Entity, EntityRef, Principal, establish, install, protect

install(
    """
    @id("support-may-search-orders")
    permit (
      principal in Role::"support",
      action == Action::"tool.search_orders",
      resource == Tool::"orders"
    );
    """,
    entities=[Entity(EntityRef("Role", "support")), Entity(EntityRef("Tool", "orders"))],
)


@protect(action='Action::"tool.search_orders"', resource='Tool::"orders"')
def search_orders(customer_id: str, region: str = "eu", limit: int = 100) -> dict[str, object]:
    ...


with establish(Principal(id="alice", roles=("support",)), channel="agent"):
    search_orders(customer_id="c-1", region="us", limit=500)
```

A web dependency or an agent tool-runner establishes *who* is acting; the decorator supplies
*what* and *with which arguments*; Cedar decides; sentrykit filters the arguments, injects
per-principal defaults, validates, invokes, and returns the result with an `_authz` report of
what was processed, rejected, and defaulted.

If alice is only granted `region="eu"` and a page size up to 50, the call above still runs.
That is **narrow-and-continue**: the parts of the proposal she is not entitled to are dropped
and refilled from her own defaults, the call proceeds, and the envelope says so.

```json
{
  "customer_id": "c-1", "region": "eu", "limit": 10,
  "_authz": {
    "decision": "allow",
    "rejected": [
      {"name": "region", "rule": "allow-set", "reason": "Value is not one of the permitted values"},
      {"name": "limit",  "rule": "maximum",   "reason": "Value is above the maximum of 50"}
    ],
    "defaults_applied": {"region": null, "limit": null}
  }
}
```

Narrowing *refines* a proposal; it does not invent one. If **every** argument the caller
supplied is rejected, the call is refused with `NoValidArguments` rather than completed from
defaults — completing it would answer a question nobody asked, handing back alice's own orders
when she asked about a customer's.

With no established principal, the call is refused rather than run unguarded. Forgetting to
wire a provider fails closed.

### The reviewed file states the ceiling; the store states the grant

Constraints reach a decision from two places, and they **intersect**. A **grant** in the store
says what *this* principal may pass — mutable, per-principal, and the only layer that carries a
`default`. A **ceiling** declared on a `permit` in a reviewed `.cedar` file says what *anybody*
may pass for that action:

```cedar
@id("support-may-search")
@constraints("{\"limit\": {\"maximum\": 100}, \"region\": {\"allow\": [\"eu\", \"us\"]}}")
permit (
  principal in Role::"support",
  action == Action::"tool.search",
  resource == Tool::"orders"
);
```

Intersection can only narrow — allow-sets intersect, deny-sets union, bounds move inward — so a
grant capped at 10 stays capped at 10 under a ceiling of 100. The file under review states the
maximum anyone may have; the store stays the one place a per-principal value lives.

A ceiling is also the only declaration a policy can make that reaches narrow-and-continue
rather than the gate. Cedar answers allow or deny, so "you asked for 500, you may not have
that — here is what you may have" has nowhere else to live: the value above the bound is
rejected, the principal's own default fills the hole, and the call is served rather than
refused. Every part of a declaration is checked at load — the JSON, the rule names, the value
types, the pattern, and that the annotation sits on a `permit` — because Cedar does not
type-check annotation values, and a bound nobody enforces is worse than no bound. What load
cannot check is a misspelled argument name: nothing here imports your application, so read a
ceiling against the callable's signature. A failed evaluation reports no determining policies
and therefore no ceilings, so a policy set that declares any ceiling refuses an engine failure
under `fail_mode="open"` too, rather than proceeding unbounded. See
[docs/policies.md](docs/policies.md).

### A constraint nothing can satisfy is refused when it is written

Constraints are data, so one can be written that nothing satisfies. `minimum=100, maximum=10`
is the obvious case; an allow-set member the pattern rejects, or a default outside the
allow-set, are the quieter ones. Left to be discovered at call time, each is a refusal of
everything, found by whoever calls next:

```python
store.grant(GrantSpec(principal=..., kind="constraint", subject="limit",
                      constraint=ArgumentConstraint(minimum=100, maximum=10)))
# ConfigurationError: the constraint on argument 'limit' cannot be satisfied: ...
```

The check runs at the write rather than on the model itself, because a store also *reads*
constraints: refusing at construction would make one bad row already on disk fail the load of
every principal in the file. The write is where the fault is introduced and where someone is
present to fix it.

The same reasoning covers defaults at the call. A default is checked against its own constraint
and withheld if it fails, so omitting an argument is not a way around the rule that governs it.
The rules, how they resolve per `(principal, action)`, and their sharp edges are written up in
[docs/concepts.md](docs/concepts.md).

### Guard an HTTP route — same decorator, one extra line

A **context provider** is all a framework contributes. It establishes the principal at the
request boundary and renders a refusal as an HTTP response; nothing else changes.

```python
from fastapi import FastAPI

from sentrykit import install
from sentrykit.integrations.fastapi import FastAPIProvider, protect_app

provider = FastAPIProvider(identify=lambda request: request.headers.get("x-user"), grants=store)
install(POLICY_TEXT, grant_store=store, context_provider=provider)

app = FastAPI()
protect_app(app, provider=provider)          # <- the one extra line


@app.get("/orders/summary")                  # this route is NOT protected
def summary() -> dict[str, object]:
    return summarize_orders()                # this call is
```

Flask is the same shape (`from sentrykit.integrations.flask import protect_app`), and
`protect_blueprint` scopes it to one blueprint. `identify` answers *who is this*; the grant
store answers *what may they do*. A denial comes back as a 403 carrying the same `_authz`
envelope a success carries, trimmed by `verbosity`:

```json
{
  "detail": "The policy denied action Action::\"orders.search\".",
  "error": "AuthzDenied",
  "_authz": {"decision": "deny", "action": "Action::\"orders.search\"", "resource": "Tool::\"orders\""}
}
```

Two runnable apps — one orders-and-refunds desk built twice, with the same seven protected
callables, the same reviewed `.cedar` directory and the same grant data on both frameworks —
live in `examples/fastapi_app/` and `examples/flask_app/`. Each drives 22 requests through its
own test client and prints what policy did to every one before it starts serving. See
[docs/web-frameworks.md](docs/web-frameworks.md).

### Guard an agent's tools — same decorator, and the model is told what it may attempt

An agent boundary needs one thing a web boundary does not: the **tool manifest is
per-caller**. sentrykit filters it with the same decision that enforces the call.

```python
from mcp.server.mcpserver import MCPServer

from sentrykit import install
from sentrykit.integrations.fastmcp import FastMCPProvider, governed_tool, protect_server

provider = FastMCPProvider(grants=store)
install(POLICY_TEXT, grant_store=store, context_provider=provider)

server = MCPServer("orders")
governed_tool(server)(search_orders)         # register the protected callable
protect_server(server)                       # <- the one extra line
```

Pydantic-AI is the same shape, and its principal is **the human the agent acts for** — never a
service identity for the agent process, and never anything the model can write:

```python
from sentrykit.integrations.pydantic_ai import PydanticAIProvider, governed_tool

agent = Agent(model, deps_type=Caller)
governed_tool(agent)(search_orders)

await agent.run("what is on order o-1?", deps=Caller(principal="alice"))
```

The filtering guarantee is stated as an invariant and tested as one:

> **A tool is hidden from a principal if and only if invoking it would be refused.**

Hiding is a courtesy to the model, never the control. A client that skips the manifest and
calls a hidden tool by name is refused just the same — both halves are asserted in the same
test, because a filter that *were* the control would be a hole the moment someone skipped
`tools/list`.

An MCP tool server and an on-behalf-of agent govern that same desk in `examples/fastmcp_server/`
and `examples/pydantic_ai_agent/`, and print a 22-flow table of their own. Neither needs an API
key: each uses a local [Ollama](https://ollama.com) model when one is reachable and a
deterministic stand-in otherwise, and every authorization outcome is identical either way — a
decision is made from the principal and the proposed arguments, never from which model proposed
them.
Setting `SENTRYKIT_OLLAMA_URL` to an empty value turns the search off without opening a socket.
See [docs/agents.md](docs/agents.md).

### Relationships are Cedar's job, and this composes with them

Underneath the argument layer, nested relationships — user → team → project → resource,
delegation, on-behalf-of, expiry, break-the-glass — are resolved deterministically by Cedar's
entity hierarchy, rather than by a ladder of application `if` statements or by a model. A
policy therefore names only the far end of a chain:

```cedar
@id("project-members-may-read-project-orders")
permit (
  principal in Project::"orders-eu",
  action == Action::"order.read",
  resource in Project::"orders-eu"
);
```

Given `alice → Team::"eu-support" → Division::"emea" → Project::"orders-eu"`, alice may read
an order owned by that project. The policy mentions neither the team nor the division; sever
one edge and the access is gone, because the relationship *is* the authorization. That is
Cedar's strength and sentrykit inherits it — it is the foundation the argument layer stands on,
and a ceiling can be declared on exactly that permit.

## Every decision is auditable

Point sentrykit at a sink and each decision — allow *and* refusal — becomes one hash-chained
record: the principal's effective attributes snapshotted at decision time, the arguments
proposed, processed, rejected and defaulted, the policies that decided and where they came
from, and the `policy_set_hash` that lets the decision be replayed.

```python
install(
    policy_source="file://./policies",
    grant_store="memory://",
    audit_sink="jsonl://./var/audit.jsonl",
)
```

Sensitive values are masked **before** the write, never after — anything in an append-only
store is permanent, so masking at report time is too late. A policy says what to mask:

```cedar
@id("support-may-look-up")
@obligations("hmac:account, notify:secops")
permit (principal in Role::"support", action == Action::"tool.lookup", resource == Tool::"accounts");
```

The callable receives `ACCT-4417-9930`; the audit log receives
`hmac:9aceb229b6349cc0…`. Keyed HMAC is the default because it is the one
strategy that lets an auditor correlate records without the store ever holding the value.
Obligations that are not masking instructions — `notify:secops` — ride along on the record and
the envelope for your application to discharge.

Tampering is detectable, not preventable: each record's hash covers its predecessor's, so
`verify_chain` catches both an edited record and a deleted one. Preventing the rewrite is the
storage layer's job.

## A policy pack ships with it

The shapes every project ends up writing — a role the resource requires, ownership, a group
hierarchy, a delegation, an expiry, a break-the-glass — ship as **data**, reachable through
the same union as your own directory:

```python
install(policy_source=["pack://", "file://./policies"])
```

Eight patterns: `rbac`, `groups`, `ownership`, `delegation`, `expiry`, `break-glass`,
`separation-of-duties`, `jit-elevation`. None of them names a role, a resource type or an
action — a shipped pack cannot know your vocabulary, so each one reads the *shape* of the
request instead. The resource declares what it requires, the grant store supplies the
principal's edges, the context supplies `now`, `break_glass`, `on_behalf_of` and
`justification`. Adopting a pattern is putting an attribute on an entity.

Half the pack **forbids**, and that half is the part that contains rather than permits:

```cedar
@id("delegation-outside-scope-forbidden")
forbid (principal, action, resource)
when { principal has delegated_actions && !(action in principal.delegated_actions) };
```

Without it a delegated agent could reach the plain RBAC permit and ignore the scope it was
delegated. Same story for break-the-glass: the `forbid` is what makes an emergency-only
resource emergency-only, and the permit that reopens it demands an emergency role, the flag
**and** a justification — because a permit conditioned on a caller-supplied boolean alone
authorizes anyone at all. It carries `notify:secops` and `record:justification` as mandatory
obligations, so a call that proceeds that way cannot proceed quietly.

```python
with establish(ana, channel="web", break_glass=True, justification="incident 4471"):
    open_vault(item="master-key")
```

See [docs/policies.md](docs/policies.md).

## A command line for the parts an API is the wrong shape for

```bash
sentrykit policy validate ./policies
sentrykit grant 'User::"ana"' --role oncall --expires 2026-09-01 \
    --store jsonfile://./var/grants.json --policy file://./policies \
    --as 'User::"root"'
sentrykit audit-report --from 2026-01-01 --to 2026-12-31 --out audit.md
```

`policy validate` type-checks a directory against its schema before it deploys, groups errors
by the policy's `@id`, and exits non-zero — so it belongs in CI, where it catches the policy
set that cannot possibly permit anything and would otherwise deploy cleanly and deny every
request for the life of the process.

`grant` and `revoke` are **not** back doors into the store. Each is a `@protect`-ed callable
decided by the same governor the application uses, so a policy governs who may administer
grants *and which grants they may make* — the spec is built from the policy-processed
arguments, not from `argv`. An operator entitled only to `oncall` who asks for `--role admin`
stores `oncall`, and the audit log says so. `--policy` is required on both, with no default:
the shipped pack ships no permit for the admin actions, so defaulting to it would turn "you
named no policy source" into "you are not entitled". An allowed mutation leaves two records,
the decision and the mutation; a refused one leaves the refusal and an untouched store.

`audit-report` makes audit-first literal: the yearly report is a query. It aggregates by
**outcome** rather than allow/deny, because allow/deny folds six materially different refusals
into one bucket and both admin mutations into the other.

See [docs/audit.md](docs/audit.md).

## Everything on the outside is a plugin

Policy sources, grant stores, audit sinks and framework providers all
use one mechanism: a `Protocol`, a DSN, a `register_*` decorator, and an entry point. The
built-ins take exactly the path a third-party package takes.

```toml
# pyproject.toml of sentrykit-splunk
[project.entry-points."sentrykit.audit_sinks"]
splunk = "sentrykit_splunk.sink:SplunkAuditSink"
```

After `pip install sentrykit-splunk`, `audit_sink="splunk://..."` works with no change to
sentrykit. Pass a list instead of one DSN and you get a composite that satisfies the same
`Protocol` — policy sources union, grant stores merge or route by namespace, audit sinks fan
out — so the decision path never learns how many were configured.

## Develop

This repo uses [pixi](https://pixi.sh/) for environments and helper tasks.

```bash
git init                # required: `pixi run setup` installs git hooks
pixi install
pixi run setup          # install git hooks (incl. the commit-message gate)
pixi run -e all check   # format-check, lint, typecheck, tests+coverage, docs
```

`pixi run setup` installs pre-commit hooks into `.git/hooks`, so the repository has to be a
git repository first — on a fresh clone it already is.

The user docs cover [policies and grants](docs/policies.md),
[audit and masking](docs/audit.md), and [writing a plugin](docs/plugins.md).

`pixi run docs` builds them into HTML, a PDF, and `llms.txt` / `llms-full.txt` — the four
documentation artifacts every release attaches, since the repository is private and there is
no site to host.

## Security

[SECURITY.md](SECURITY.md) has the disclosure contact and, more usefully, an explicit account
of **what sentrykit defends and what it does not**. The short version: it authorizes the
action before the side effect and records a tamper-evident trail of every decision. It does
not sandbox a tool body — once a call is authorized, the function runs with your process's
privileges — and without a durable write-once sink behind the `AuditSink` protocol it
*detects* tampering rather than preventing it. It also does not authenticate: `Principal` is
whatever your context provider establishes, and sentrykit trusts it.

## License

Apache-2.0. See `LICENSE`.
