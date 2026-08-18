# sentrykit

Lightweight, framework-agnostic authorization for Python, built on AWS Cedar. Clip a
`@protect` decorator onto any callable — a web route, a plain function, or an agent tool —
and let Cedar decide whether the principal may invoke it, which arguments they may pass, and
which defaults to inject, with a masked, tamper-evident audit trail.

Start with the [quickstart](quickstart.md) for a working example in six steps, then
[concepts](concepts.md) for the pipeline, the two kinds of failure, and why nested
relationships are Cedar's job rather than your application's.

**Status.** The framework-agnostic core is implemented: `@protect`, ambient context, the
Cedar gate, argument filtering, default injection, validation, and the `_authz` envelope — as
are the [pluggable stores](plugins.md) and the [audit log](audit.md), and the
[FastAPI and Flask providers](web-frameworks.md) with runnable example apps. The agent
providers and the shipped policy pack land in the later phases described in
`dev-docs/implementation.md`; [agent tooling](agents.md) is still a placeholder.
