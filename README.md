# sentrykit

Lightweight, framework-agnostic **authorization** for Python — built on
[AWS Cedar](https://www.cedarpolicy.com/). Clip a `@protect` decorator onto any callable and
sentrykit decides, per call, whether the principal may invoke it, **which arguments** they may
pass, and **which defaults** to inject when they pass none — then records a masked,
tamper-evident audit trail.

It targets two worlds with one decorator:

- **Web frameworks** — FastAPI, Flask (more to come).
- **Agent tooling** — FastMCP servers, Pydantic-AI (more to come).

> The caller *proposes*; the **policy decides**. Nested, multi-hop authorization
> relationships — team → project → resource, delegation, on-behalf-of, expiry,
> break-the-glass — are resolved deterministically by Cedar, never guessed by a model.

sentrykit sits at the **action layer**: it refuses the side effect *before* it happens,
unlike output validators that run after a model finishes. It is self-hosted, Cedar-based, and
audit-first.

> **Status: 0.1.0 — everything below works.** `@protect`, ambient context, the Cedar gate,
> argument filtering, default injection, validation and the `_authz` envelope; the three
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

If alice is only granted `region="eu"` and a page size up to 50, the call above still runs —
narrowed to what she is entitled to, and saying so:

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

With no established principal, the call is refused rather than run unguarded. Forgetting to
wire a provider fails closed.

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

Two runnable apps — the same three routes, the same policy, the same service layer, on both
frameworks — live in `examples/fastapi_app/` and `examples/flask_app/`. See
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

An MCP tool server and an on-behalf-of agent live in `examples/fastmcp_server/` and
`examples/pydantic_ai_agent/`. Both run offline, with no API key and no network call. See
[docs/agents.md](docs/agents.md).

### Relationships are the policy's job

The point is not that sentrykit checks a role. It is that multi-hop relationships are
resolved by Cedar's entity hierarchy, so a policy names only the far end of a chain:

```cedar
@id("project-members-may-read-project-orders")
permit (
  principal in Project::"orders-eu",
  action == Action::"order.read",
  resource in Project::"orders-eu"
);
```

Given `alice → Team::"eu-support" → Division::"emea" → Project::"orders-eu"`, alice may read
an order owned by that project. The policy mentions neither the team nor the division. Sever
one edge and the access is gone — because the relationship *is* the authorization.

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
    --store jsonfile://./var/grants.json --as 'User::"root"'
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
stores `oncall`, and the audit log says so. An allowed mutation leaves two records, the
decision and the mutation; a refused one leaves the refusal and an untouched store.

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

## License

Apache-2.0. See `LICENSE`.
