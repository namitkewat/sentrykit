# sentrykit

Lightweight, framework-agnostic authorization for Python, built on AWS Cedar. The caller
proposes; the policy decides — not only whether a principal may invoke a protected callable,
but **which arguments they may pass** and **which defaults to inject when they pass none**. A
proposal above what the principal is entitled to is narrowed rather than refused: the value
they may not have is rejected, their own default fills the gap, and the call proceeds. Once an
audit sink is configured, what was decided is written to a masked, hash-chained audit trail.
One `@protect` decorator does all of it, on a web route, a plain function or an agent tool
alike.

Start with the [quickstart](quickstart.md) for a working example in six steps, then
[concepts](concepts.md) for the pipeline, the constraint model, the two kinds of failure, and
how nested relationships — team, project, delegation — are resolved underneath by Cedar's
entity hierarchy.

## What is here

| | |
| --- | --- |
| **An argument layer** | Constraints resolved per `(principal, action)` — allow-set, deny-set, pattern, numeric bounds — decide which proposed arguments survive and which defaults fill the rest. A value above what the principal may have is rejected and their own default fills the gap, so the call proceeds; a proposal in which nothing the caller supplied survives is refused. A reviewed `.cedar` file can declare the [ceiling](policies.md#argument-ceilings) everybody is held to, and a constraint no value could satisfy is refused when it is written rather than found at the call. See [concepts](concepts.md#argument-constraints). |
| **One decorator, two worlds** | `@protect` gates the call, filters the arguments the caller proposed, injects the defaults policy supplies, and validates the result — for sync and async callables alike — on [FastAPI and Flask](web-frameworks.md) routes and on [MCP tool servers and Pydantic-AI](agents.md) tools, where a tool is also *hidden* from a principal who could not invoke it. Four runnable example apps. |
| **A policy pack** | Eight domain-neutral [patterns](policies.md#the-shipped-policy-pack) — RBAC, groups, ownership, delegation, expiry, break-the-glass, separation-of-duties, JIT elevation — shipped as data and composed through the same union as your own policy directory. |
| **An audit trail** | One masked, hash-chained [record per decision](audit.md) and per admin mutation, pinned to the exact policy logic that produced it. The yearly report is a query, not an afternoon of reading logs. |
| **A command line** | `sentrykit policy validate`, `grant` / `revoke`, and `audit-report` — with the admin surface governed by the very policy it administers. |
| **Plugins everywhere** | Policy sources, grant stores, audit sinks and framework providers are all [Protocol + DSN + entry point](plugins.md), so a third-party backend is indistinguishable from a built-in. |

**Status.** Version 0.2.0. Everything above is implemented and tested. This is a pre-1.0
library: the public API is typed, documented and covered, but it has not yet been through a
release cycle. The audit sinks that ship write to memory and to an append-only JSONL file; a
durable write-once backend (S3 Object Lock, an Iceberg table) is a `Protocol` away rather
than shipped, which matters because until you wire one up the hash chain *detects* tampering
rather than preventing it. [Audit & compliance](audit.md) covers the chain, and
[Plugins & extensions](plugins.md) covers writing the sink.

```{toctree}
:maxdepth: 2
:caption: Guide

quickstart
concepts
web-frameworks
agents
policies
audit
plugins
```

```{toctree}
:maxdepth: 2
:caption: Reference

api/index
```
