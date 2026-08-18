# Coding standards

## Language & tooling
- Python **3.11+**. Use modern syntax (`X | None`, `match`, `Self`, PEP 695 generics where
  it aids clarity).
- **Ruff** is the linter and formatter (`pixi run fmt`, `pixi run lint`). **mypy --strict**
  is the type gate (`pixi run typecheck`). Both run in `pixi run check` and in pre-commit.
- Line length 100. Sentence-case log/error strings.

## Typing
- Public API is fully annotated; no untyped `def`s. Avoid `Any` on public signatures; if
  unavoidable, justify with a comment. Ship `py.typed`.
- Prefer `Protocol` for extension seams (stores, sinks, providers) over ABCs — structural
  typing keeps third-party backends unaware of us.
- Use pydantic v2 models for data crossing a boundary (config, `Principal`, `Invocation`,
  `AuthzAuditRecord`, argument models). Use plain dataclasses/`NamedTuple` for internal,
  perf-sensitive value objects.

## Structure & boundaries
- **The core imports no web framework and no agent SDK.** Framework code lives only under
  `sentrykit/integrations/*`, guarded by optional extras and imported lazily. A unit test
  asserts this by scanning core-module imports.
- Keep modules small and single-purpose (see the layout in `implementation.md`). One public
  concept per module.
- Dependency discipline: the **core runtime deps are minimal** (`cedarpy`, `pydantic`,
  `pydantic-settings`, `typing-extensions`). Everything else is an optional extra.

## Async
- Support both sync and async callables in `@protect` (detect with
  `inspect.iscoroutinefunction`). Provide sync and async engine entry points.
- Never block the event loop on I/O in async paths. `cedarpy` is sync and cheap; if a
  deployment needs it off-thread, offer an offload path that is `copy_context`-aware.
- Respect `contextvars` propagation rules (see architecture §3).

## Errors
- Raise the typed hierarchy in `errors.py`; never raise bare `Exception`. Each error carries
  structured, machine-readable detail (offending argument, reason, policy id) so providers
  can render it.
- No bare `except:`; catch narrowly. Do not swallow exceptions silently — surface or re-raise
  with context.

## Security hygiene
- Fail closed on missing context/policy. Never log secrets or unmasked sensitive values in
  operational logs. Apply masking before any audit write. No sensitive data in URLs.
- Keep untrusted input (LLM-proposed args, request bodies) as *data*; validate before use.

## Docstrings & comments
- Every public module, class, and function has a docstring (Google style). Document *why*,
  not *what the code plainly says*. Keep comments current with the code.
