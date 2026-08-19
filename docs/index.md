# sentrykit

Lightweight, framework-agnostic authorization for Python, built on AWS Cedar. Clip a
`@protect` decorator onto any callable — a web route, a plain function, or an agent tool —
and let Cedar decide whether the principal may invoke it, which arguments they may pass, and
which defaults to inject, with a masked, tamper-evident audit trail.

Start with the [quickstart](quickstart.md) for a working example in six steps, then
[concepts](concepts.md) for the pipeline, the two kinds of failure, and why nested
relationships are Cedar's job rather than your application's.

## What is here

| | |
| --- | --- |
| **One decorator** | `@protect` gates the call, filters the arguments the caller proposed, injects the defaults policy supplies, and validates the result — for sync and async callables alike. See [concepts](concepts.md). |
| **Two worlds** | [FastAPI and Flask](web-frameworks.md) on the web side; [MCP tool servers and Pydantic-AI](agents.md) on the agent side, where a tool is also *hidden* from a principal who could not invoke it. Four runnable example apps. |
| **A policy pack** | Eight domain-neutral [patterns](policies.md#the-shipped-policy-pack) — RBAC, groups, ownership, delegation, expiry, break-the-glass, separation-of-duties, JIT elevation — shipped as data and composed through the same union as your own policy directory. |
| **An audit trail** | One masked, hash-chained [record per decision](audit.md) and per admin mutation, pinned to the exact policy logic that produced it. The yearly report is a query, not an afternoon of reading logs. |
| **A command line** | `sentrykit policy validate`, `grant` / `revoke`, and `audit-report` — with the admin surface governed by the very policy it administers. |
| **Plugins everywhere** | Policy sources, grant stores, audit sinks and framework providers are all [Protocol + DSN + entry point](plugins.md), so a third-party backend is indistinguishable from a built-in. |

**Status.** Everything above is implemented and tested. This is a pre-1.0 library: the public
API is typed, documented and covered, but it has not yet been through a release cycle. The
audit sinks that ship write to memory and to an append-only JSONL file; a durable write-once
backend (S3 Object Lock, an Iceberg table) is a `Protocol` away rather than shipped, which
matters because until you wire one up the hash chain *detects* tampering rather than
preventing it. [Audit & compliance](audit.md) covers the chain, and
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
