# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows SemVer.

## [Unreleased]
### Added
- The MCP and Pydantic-AI context providers, tool-manifest filtering, and two runnable
  example agents (phase 4).
  - `integrations/tools.py` — the framework-free half of an agent boundary. `decide_tool` /
    `permitted_tools` answer "may this principal be shown this tool?" by running the *same*
    `Governor.plan` the dispatch path runs, so MCP's `tools/list` and Pydantic-AI's `prepare`
    cannot drift apart. A tool is hidden if and only if invoking it would be refused
    (ADR-017); hiding is never the enforcement, and the dispatch path re-decides regardless.
  - `integrations/tools.proposable` — re-declares the arguments policy supplies as optional,
    so a model can omit them and receive its per-principal defaults. Both frameworks validate
    a proposal against the advertised schema before dispatch, which would otherwise put
    default injection out of reach from an agent entirely (ADR-019).
  - `integrations/fastmcp.py` — `FastMCPProvider`, `SentrykitToolMiddleware` (establish and
    release around `tools/call`, filter `tools/list`), `governed_tool` and `protect_server`.
    Built against **mcp 2.0**'s `MCPServer`; the `fastmcp` name is kept for the module, the
    extra and the DSN, but nothing imports the standalone `fastmcp` distribution (ADR-018).
    The principal travels in the request's `_meta`, which is the only carrier that exists on
    every transport, so a server is drivable over stdio and in memory.
  - `integrations/pydantic_ai.py` — `PydanticAIProvider` bridging `RunContext.deps` to ambient
    context per dispatch, `governed_tool`, `tool_adapter`, `tool_prepare` and `tool_filter`.
    The principal is the human the agent acts for, never a service identity for the agent
    process, and the model cannot influence it.
  - `examples/fastmcp_server/` — three protected tools, one of which is invocable only through
    a four-hop `User -> Team -> Division -> Project` relationship that the permitting policy
    never mentions. It demonstrates the allow, the denial when the edge is absent, the denial
    when the edge is severed, and the tool vanishing from the manifest in both cases.
  - `examples/pydantic_ai_agent/` — an on-behalf-of agent running on a deterministic model, so
    `pixi run -e agent run-agent` needs no API key and makes no network call. A real model is
    opt-in through `SENTRYKIT_EXAMPLE_MODEL`.
  - Both providers are registered under `sentrykit.context_providers` and reachable by DSN
    (`fastmcp://`, `pydantic-ai://`), indistinguishably from a third-party plugin.
  - `docs/agents.md`, with every example pinned by a test.
- The FastAPI and Flask context providers, and two runnable example apps (phase 3).
  - `integrations/base.py` — the shared half of every provider: the exception → HTTP status
    table, the verbosity-aware refusal renderer, and `BaseContextProvider`, which resolves an
    app's auth → identity callback through `GrantStore.get_principal` and owns the
    establish/release lifecycle. A subclass supplies four small methods (`name`, `narrow`,
    `read_header`, `render_error`) and inherits the rest.
  - `integrations/fastapi.py` — `FastAPIProvider`, a pure-ASGI `SentrykitMiddleware`, an
    `async` yield `context_dependency()`, `install_error_handlers()` and `protect_app()`.
  - `integrations/flask.py` — `FlaskProvider` with `before_request` / `teardown_request`
    hooks, `install_error_handlers()`, `protect_app()` and `protect_blueprint()` for governing
    one blueprint rather than a whole app.
  - `install()` now accepts `context_provider=` — a DSN (`"fastapi://"`) or a built provider —
    and `Governor.context_provider` exposes it, so the boundary adapters find their wiring
    without a second process-global. Both providers are registered under the
    `sentrykit.context_providers` entry-point group.
  - `examples/fastapi_app/` and `examples/flask_app/` — the same three routes, the same policy
    and the same service layer on both frameworks, run with `pixi run -e web run-fastapi` /
    `run-flask`.
  - `docs/web-frameworks.md`, with every example pinned by a test.
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
- The FastAPI error handler no longer fails `mypy` in an environment that has starlette but
  not fastapi — which is the `agent` environment, since mcp depends on starlette. It is the
  one combination no earlier phase produced: `Response` resolves to a real type while
  `JSONResponse` is `Any`. No behaviour change.
- The FastAPI and Flask example apps are built by a factory rather than at import. A
  module-level `app = create_app()` ran `configure()` and `install()` — both process-global —
  for anyone who so much as imported the module, including the test collector. `run-fastapi`
  and `run-flask` invoke the factory instead.
- `pixi run clean` used `rm -rf`, which fails on `win-64` — a platform the manifest claims to
  support.
- pre-commit ran its own pinned ruff and mypy, which disagreed with the locked toolchain and
  could not resolve `pydantic-settings`; the hooks now run the pixi tasks.
- The distribution version is now read from `sentrykit.__version__`, so the package and its
  metadata cannot drift apart. The `sentrykit` console script is commented out until the CLI
  it points at exists, rather than installing a command that raises `ModuleNotFoundError`.

### Notes
- **A provider must release the context it established** (ADR-015). Measured on the installed
  web environment: Flask serves a request on a pooled worker thread and its test client serves
  one in the caller's own context, so an un-reset `ContextVar` leaves the previous request's
  principal ambient — and anything running on that thread outside a request then acts as them.
  `release()` is total: it resets the scope when there is one, clears the context outright when
  there is not, and drops the last envelope either way.
- **Refusals are rendered from the exception, never from ambient state** (ADR-016). A sync
  FastAPI route runs in an AnyIO worker thread whose context copy is discarded on return, so
  `last_envelope()` is empty by the time an exception handler runs; a yield-dependency's
  teardown unwinds before the handler for the same net effect. Every sentrykit error already
  carries the structured detail the envelope needs.
- **A synchronous FastAPI dependency cannot establish context** and none is shipped. It runs in
  its own worker thread with a *copy* of the context, so its `establish()` is discarded on
  return and every protected call downstream fails closed. Middleware and `async` dependencies
  both work, and both reach `def` routes — `anyio.to_thread.run_sync` copies the context in.
  See `dev-docs/notes/phase-3-research.md`.
- A route declaring a pydantic `response_model` strips the `_authz` key the engine attaches to
  the returned mapping. The docs say so, and a test reproduces it.
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
