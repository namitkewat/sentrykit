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

> **Status: pre-implementation scaffold.** This repository currently contains the design,
> standards, and a phased build plan (see `dev-docs/`). The library is implemented across the
> five phases in `dev-docs/implementation.md`. This README is regenerated as the
> implementation lands.

## Install (once published)

```bash
pip install sentrykit                 # core
pip install "sentrykit[fastapi]"      # + FastAPI provider
pip install "sentrykit[flask]"        # + Flask provider
pip install "sentrykit[fastmcp]"      # + FastMCP provider
pip install "sentrykit[pydantic-ai]"  # + Pydantic-AI provider
pip install "sentrykit[all]"          # everything
```

## The idea in 20 seconds (target API)

```python
from sentrykit import protect

@protect(action='Action::"tool.search_orders"', resource='Tool::"orders"')
async def search_orders(customer_id: str, limit: int = 10): ...
```

A web dependency or an agent tool-runner establishes *who* is acting; the decorator supplies
*what* and *with which arguments*; Cedar decides; sentrykit filters the arguments, injects
per-principal defaults, validates, invokes, and returns the result wrapped with an `_authz`
report of what was processed, rejected, and defaulted.

## Develop

This repo uses [pixi](https://pixi.sh/) for environments and helper tasks.

```bash
pixi install
pixi run setup          # install git hooks (incl. the commit-message gate)
pixi run -e all check   # format-check, lint, typecheck, tests+coverage, docs
```

See `CLAUDE.md` for the build workflow, `dev-docs/architecture.md` for how it fits together,
and `dev-docs/design-decisions.md` for why.

## License

Apache-2.0. See `LICENSE`.
