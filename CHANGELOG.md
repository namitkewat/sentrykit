# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows SemVer.

## [Unreleased]
### Added
- Framework-agnostic core (phase 1). `@protect` guards any sync or async callable and runs
  the gate -> filter -> defaults -> validate -> invoke -> envelope pipeline.
  - `config.py` — `Settings` from `SENTRYKIT_` environment variables, with per-action
    overrides.
  - `context.py` — `Principal`, `Invocation`, ambient context via `establish()`, and
    `bind_context()` for thread-pool offload.
  - `cedar.py` — the only module that imports `cedarpy`; pre-parsed policy/entity/schema
    handles and a normalized `CedarDecision`.
  - `constraints.py` — allow-set / deny-set / pattern / range / default argument constraints.
  - `engine.py` — `Governor`, with `plan()` separated from `invoke()`.
  - `envelope.py` — the `_authz` report, trimmed at build time by verbosity.
- Project scaffold: design docs, standards, phased implementation plan, pixi + packaging
  configuration, and the commit-message enforcement hook.

### Fixed
- `pixi run clean` used `rm -rf`, which fails on `win-64` — a platform the manifest claims to
  support.
- pre-commit ran its own pinned ruff and mypy, which disagreed with the locked toolchain and
  could not resolve `pydantic-settings`; the hooks now run the pixi tasks.

### Notes
- `AuthzDenied.engine_errors` distinguishes a policy denial from a Cedar evaluation failure
  that `fail_mode="closed"` turned into one. `fail_mode` arbitrates engine failure only: a
  policy denial and a missing principal deny under both modes.
- Cedar has no floating-point and no null type. Values crossing into Cedar are coerced, since
  a stray `None` would otherwise turn every decision into a deny. See
  `dev-docs/notes/phase-1-research.md`.

<!-- Add an entry in the *fix & document* step of each loop iteration. -->
