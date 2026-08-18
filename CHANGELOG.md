# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows SemVer.

## [Unreleased]
### Added
- Pluggable stores, plugin registry, masking and the tamper-evident audit log (phase 2).
  - `stores/base.py` — the three `Protocol`s (`PolicySource`, `GrantStore`, `AuditSink`) plus
    the value objects that cross them, and a `ContextProvider` stub for phase 3.
  - `stores/filesystem.py` — `FilesystemPolicySource`: reads a directory of `*.cedar` files in
    sorted order, type-checks them against a `*.cedarschema`, and hashes the bundle.
  - `stores/memory.py` — `InMemoryGrantStore` (materializes a `Principal` with expired and
    revoked grants already excluded), `InMemoryAuditSink`, `InMemoryTokenVault`.
  - `stores/jsonl.py` — `JsonlAuditSink`: append-only, single-writer, hash-chained, and able
    to verify its own file.
  - `stores/composite.py` — union of policy sources, merge-or-route of grant stores, fan-out
    of audit sinks. Each composite *is* its `Protocol`, so the core always holds one instance.
  - `registry.py` — DSN parsing, `register_*` decorators, lazy entry-point discovery across
    the four `sentrykit.*` groups, and `build_*` factories returning one instance or the
    matching composite.
  - `masking.py` — `redact` / `partial` / `hmac` / `tokenize`, selected by a policy obligation,
    an `Annotated[..., Sensitive(...)]` marker, or the configured default, in that order.
  - `audit.py` — `AuthzAuditRecord`, the hash chain, and `AuditTrail`, which is the only thing
    that writes to a sink.
  - `install()` now accepts `policy_source=`, `grant_store=` and `audit_sink=` — a DSN, a list
    of DSNs, or an already-built instance — alongside the inline-policy form it always had.
  - `Settings` gains `audit_sink`, `hmac_key` (a `SecretStr`) and `mask_default`.
  - `cedar.py` gains `policy_annotations()` and `validate_policies()`, so the policy layer can
    read Cedar annotations and type-check a bundle without a second module importing `cedarpy`.
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
- The distribution version is now read from `sentrykit.__version__`, so the package and its
  metadata cannot drift apart. The `sentrykit` console script is commented out until the CLI
  it points at exists, rather than installing a command that raises `ModuleNotFoundError`.

### Notes
- **Obligations are Cedar annotations** on the determining policies, declared as a single
  comma-separated `@obligations("...")` (ADR-012). `cedarpy` exposes annotations only through
  `policies_to_json_str` on the policy *text*, keyed by generated ids that are positional in
  that text — so the annotation index must be derived from exactly the string the engine was
  built from, which is why `PolicySource.load()` owns it.
- **Masking on the audit path is not configurable** (ADR-014). The `redaction` setting governs
  the caller-facing envelope and the operational logs; an immutable write is the one place
  masking must not be switchable, because it is the one that cannot be taken back.
- **The JSONL sink is single-writer by design** (ADR-013), holds one handle open behind a
  lock, and writes `newline="\n"` on every platform. Measured on `win-64`: `open(path, "a")`
  per write is not atomic — 8 threads x 200 records produced 1346 of 1600 lines, three of them
  malformed — and default text mode writes CRLF, which would make the same record hash
  differently per platform. `fsync` costs ~3.7 ms per record against ~0.007 ms for a flush, so
  it is opt-in via `jsonl://path?fsync=true`.
- **Composing policy sources needs no precedence.** Cedar's `forbid` always beats a `permit`,
  so an override is a `forbid` and the union's decision is the same in either order. Source
  names namespace policy ids instead, because Cedar does not enforce `@id` uniqueness.
- `entry_points(group=...)` behaves identically on Python 3.11-3.13, but `EntryPoints` is a
  `list` subclass on 3.11 and a `tuple` subclass on 3.12+, so the registry only ever iterates
  it. See `dev-docs/notes/phase-2-research.md`.
- `AuthzDenied.engine_errors` distinguishes a policy denial from a Cedar evaluation failure
  that `fail_mode="closed"` turned into one. `fail_mode` arbitrates engine failure only: a
  policy denial and a missing principal deny under both modes.
- Cedar has no floating-point and no null type. Values crossing into Cedar are coerced, since
  a stray `None` would otherwise turn every decision into a deny. See
  `dev-docs/notes/phase-1-research.md`.

<!-- Add an entry in the *fix & document* step of each loop iteration. -->
