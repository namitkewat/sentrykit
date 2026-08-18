# sentrykit

Lightweight, framework-agnostic authorization for Python, built on AWS Cedar. Clip a
`@protect` decorator onto any callable — a web route, a plain function, or an agent tool —
and let Cedar decide whether the principal may invoke it, which arguments they may pass, and
which defaults to inject, with a masked, tamper-evident audit trail.

This documentation is filled out during the phased build (see `dev-docs/implementation.md`)
and regenerated with each increment. Start with the [quickstart](quickstart.md).
