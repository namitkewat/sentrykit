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

> **Status: the framework-agnostic core works.** `@protect`, ambient context, the Cedar gate,
> argument filtering, default injection, validation and the `_authz` envelope are implemented
> and tested. Still to come, in the phases laid out in `dev-docs/implementation.md`: the
> pluggable stores and the tamper-evident audit log, the FastAPI/Flask and FastMCP/Pydantic-AI
> providers, and the shipped Cedar policy pack with its CLI.

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

See `CLAUDE.md` for the build workflow, `dev-docs/architecture.md` for how it fits together,
and `dev-docs/design-decisions.md` for why.

## License

Apache-2.0. See `LICENSE`.
