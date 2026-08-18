# Implementation plan

Five phases, each self-contained and shippable. Every phase is executed with the loop from
`CLAUDE.md` §4 (research → build → test → review → fix & document → repeat 2–3×) and
decomposed into sub-agent workstreams per `CLAUDE.md` §5. Do not start a phase before the
prior phase's acceptance criteria pass and `pixi run check` is green.

Target module layout (build it as the phases require it):

```
src/sentrykit/
  __init__.py        errors.py        config.py         context.py
  decorator.py       engine.py        cedar.py          constraints.py
  envelope.py        masking.py       audit.py          registry.py        cli.py
  stores/  base.py  filesystem.py  memory.py  jsonl.py  composite.py
  policy/  loader.py  pack/  (cedar policies + schema, as data)
  integrations/  base.py  fastapi.py  flask.py  fastmcp.py  pydantic_ai.py
```

---

## Phase 1 — Framework-agnostic core

**Goal.** A working decision core that guards any callable, end-to-end, using in-memory
policy and grants. No framework code. After this phase you can `@protect` a plain function
and see gate → filter → defaults → validate → envelope work in a unit test.

**Deliverables.**
- `errors.py` — exception hierarchy: `SentrykitError` → `AuthzDenied`, `NoContext`,
  `ArgumentRejected`, `NoValidArguments`, `DefaultUnavailable`, `ValidationFailed`,
  `ConfigurationError`. Each carries structured detail (offending arg, reason, policy id).
  (A starter `errors.py` already exists — extend it.)
- `config.py` — `Settings` (pydantic-settings) with env prefix `SENTRYKIT_`: `verbosity`
  (`off|summary|verbose|debug`), `arg_handling` (`lenient|strict`), `fail_mode`
  (`closed|open`), `redaction` on/off, `envelope_on_success` bool. Global accessor +
  per-action override hook.
- `context.py` — `Principal` and `Invocation` models; ambient `ContextVar`s for principal
  and environment; `establish(principal, **env)` and a context-manager form; helpers that
  are `copy_context`-aware for thread offload.
- `cedar.py` — thin wrapper over `cedarpy`: build/cache a reusable policy-set handle, call
  `is_authorized`, and translate the result into a normalized decision object exposing
  `allowed`, `determining_policies`, and errors. Sync (cedarpy is sync) but cheap.
- `constraints.py` — resolve per-(principal, action) argument constraints from entity
  attributes (allow-set / deny-set / pattern / range / default); `filter()` → (kept,
  rejected[]); `inject_defaults()`.
- `engine.py` — `Governor.plan(...)` and `.invoke(fn, plan)` / `.ainvoke(fn, plan)`:
  coarse gate → argument filter → default injection → pydantic validation → invoke → wrap.
  Honors `arg_handling`/`fail_mode`; raises the typed errors on the documented edge cases
  (all-args-invalid ⇒ `NoValidArguments`; missing default ⇒ `DefaultUnavailable`).
- `envelope.py` — build the `_authz` envelope (`decision`, `processed`, `rejected[]`,
  `defaults_applied`, `obligations`, `trace`) with verbosity control.
- `decorator.py` — `protect(action=None, resource=None)` reading ambient context with an
  explicit `_as=` override; `inspect.signature().bind_partial` for arg extraction; sync +
  async wrappers; fail-closed on no principal.

**Sub-agent split.** (a) errors+config+context; (b) cedar+constraints; (c)
engine+envelope+decorator; (d) unit tests spanning all of the above.

**Tests (`tests/unit/`).** gate allow/deny; determining-policy surfaced; filter keeps valid
and reports rejected; defaults injected when args omitted; `NoValidArguments` when all
supplied args invalid; pydantic validation error surfaces structured detail; envelope
verbosity levels; `ContextVar` propagates across `await`; explicit `_as=` overrides ambient;
no-principal ⇒ deny.

**Acceptance.** `pixi run test-unit` green; core modules have zero framework imports
(add a test that asserts this by scanning imports); `pixi run typecheck` clean.

---

## Phase 2 — Stores, plugin registry, masking, audit — **done**

Delivered as described. Working notes in `notes/phase-2-research.md`; the decisions it forced
are ADR-012 (obligations as policy annotations), ADR-013 (the JSONL sink's write model) and
ADR-014 (masking on the audit path is not configurable).

Three things landed differently from the plan below, each for a reason worth carrying forward:

- `cedar.py` gained `policy_annotations()` and `validate_policies()`. Cedar exposes annotations
  only through `policies_to_json_str`, and the filesystem source needs the validator — routing
  both through `cedar.py` preserves the phase 1 invariant that exactly one module imports
  `cedarpy`, now enforced by `tests/unit/test_cedar_confinement.py`.
- Two policy sources that share a *name* are refused, because names namespace policy ids. A
  `file://` source is therefore named after its directory rather than its scheme, so the
  ordinary two-directory union works without the caller naming anything.
- Two sources declaring the *same entity identically* is allowed; declaring it *differently* is
  a `ConfigurationError`. The original brief said any duplicate was an error, which would have
  made it impossible for two policy directories to each require `Role::"admin"` to exist.

**Goal.** The pluggable substrate and the audit-grade decision log, with fan-out/union/merge
composites and entry-point discovery.

**Deliverables.**
- `stores/base.py` — `Protocol`s: `PolicySource` (`load()`, `current_hash()`),
  `GrantStore` (`get_principal()`, `grant()`, `revoke()`), `AuditSink` (`write()`,
  `query()`). Include a `ContextProvider` protocol stub for Phase 3/4.
- `stores/filesystem.py` — `FilesystemPolicySource` (load Cedar policies + schema from a
  directory; hash the merged bundle).
- `stores/memory.py` — `InMemoryGrantStore` (roles/attrs/grants; mutation returns a
  `GrantRecord`).
- `stores/jsonl.py` — `JsonlAuditSink` (append-only file; tamper-evident hash chain).
- `stores/composite.py` — `CompositePolicySource` (union of policies, namespaced ids,
  provenance tag per policy), `CompositeGrantStore` (merge-by-precedence *or* route-by-
  namespace), `CompositeAuditSink` (fan-out with `primary-durable` vs `all-or-nothing`
  error policy). Each composite *is-a* the corresponding Protocol.
- `registry.py` — DSN/scheme parsing (`"file://"`, `"jsonl://"`, …); a name-keyed registry;
  `register_*` decorators for in-process registration; entry-point discovery for
  `sentrykit.policy_sources`, `sentrykit.grant_stores`, `sentrykit.audit_sinks`,
  `sentrykit.context_providers`; `build_*` factories that return a single instance or a
  composite from a list.
- `masking.py` — strategies `redact | partial | hmac | tokenize`; declarative selection via
  pydantic field annotations *and* honoring Cedar obligations; **applied before** the sink
  write. HMAC is the default for correlation-without-exposure; keys come from config.
- `audit.py` — `AuthzAuditRecord` (per `dev-docs/architecture.md`): effective-principal
  snapshot, `proposed/processed/rejected`, `defaults_applied`, obligations,
  `policy_set_hash`, provenance, `prev_hash`/`record_hash`. Wire the engine to emit one
  record per decision (and later, per admin mutation).

**Sub-agent split.** (a) base+filesystem+memory+jsonl; (b) composite+registry; (c)
masking+audit + engine wiring; (d) tests.

**Tests.** union merges and namespaces ids; forbid-overrides semantics preserved across
sources (an override is a `forbid`, not source precedence); fan-out writes to all sinks and
honors the error policy; masking runs before write and never leaks raw values into the sink;
hash chain detects tampering; registry discovers a dummy entry-point plugin; DSN routing
selects the right backend.

**Acceptance.** `pixi run test` green; a registered dummy third-party sink works via
entry-point discovery with no core change; audit records are reproducible given
`policy_set_hash` + captured context.

---

## Phase 3 — Web providers: FastAPI + Flask — **done**

**Goal.** The same `@protect` guarding real HTTP handlers on two frameworks, plus runnable
example apps.

**Deliverables.**
- `integrations/base.py` — `ContextProvider` contract: establish ambient context from the
  framework's request+auth; map sentrykit exceptions to the framework's error response
  (rendering the `_authz` envelope per `verbosity`).
- `integrations/fastapi.py` — a dependency and/or `BaseHTTPMiddleware` that calls
  `establish(principal, channel="http", request_id=...)`; an exception handler; helpers to
  attach the envelope to responses. Register under `sentrykit.context_providers`.
- `integrations/flask.py` — `before_request` establishment (ContextVar valid for the
  request thread), `errorhandler` rendering, blueprint helper. Register the provider.
- `examples/fastapi_app/` and `examples/flask_app/` — minimal apps with an auth stub, two
  protected routes and one protected non-route callable, wired to the in-memory grant store
  and a small policy set.

**Sub-agent split.** (a) integrations/base + fastapi + fastapi example; (b) flask +
flask example; (c) integration tests for both.

**Tests (`tests/integration/`, `pixi run -e web ...`).** via TestClient/Flask test client:
allowed route returns result + envelope; forbidden route denied with reason; argument
filtering drops invalid query/body fields and reports them; defaults injected when omitted;
a protected non-route function inside a handler is governed by the same ambient context.

**Acceptance.** `pixi run -e web test-integration` green; `pixi run run-fastapi` and
`run-flask` serve working apps; extras `sentrykit[fastapi]` / `sentrykit[flask]` resolve.

**Outcome.** Both gates green: `pixi run check` (default env, 705 passed / 5 skipped, 88.59%
coverage) and `pixi run -e web check` (779 passed, 93.11%). Both example apps were driven over
real HTTP under `uvicorn` and `flask run`, demonstrating the gate, argument filtering, default
injection, a denial, the audit envelope, and a protected non-route callable governed by ambient
context. Two decisions came out of the phase and are recorded as ADR-015 (establish at the
boundary, release at teardown) and ADR-016 (render refusals from the exception). The measured
basis for both is in `notes/phase-3-research.md`; the sharpest finding is that a **sync FastAPI
dependency cannot establish context**, so no sync-dependency form is shipped.

---

## Phase 4 — Agent providers: FastMCP + Pydantic-AI — **done**

Delivered as described. Working notes in `notes/phase-4-research.md`; the decisions it forced
are ADR-017 (the manifest-filtering invariant), ADR-018 (mcp 2.0 is the target, `fastmcp` is a
name we keep) and ADR-019 (omittable arguments, and a refusal carried out in an `MCPError`).

Four things landed differently from the plan below, each measured rather than assumed:

- **There is no `FastMCP`.** mcp 2.0 renamed it `mcp.server.mcpserver.MCPServer`, and the
  standalone `fastmcp` distribution does not import against mcp 2.0 at all. The module, the
  extra and the DSN keep the `fastmcp` name; nothing imports that package (ADR-018).
- **A tool's advertised schema had to change.** Both frameworks validate a proposal against it
  *before* dispatch, so an argument marked `required` can never be omitted — and per-principal
  default injection was therefore unreachable from an agent. `integrations/tools.proposable`
  re-declares the policy-suppliable parameters as omittable, which is the same move the
  FastAPI example already makes at its route (ADR-019).
- **A refusal cannot simply be raised on the MCP side.** `Tool.run` launders it into a result
  with no structured content, so the `_authz` envelope is lost before any middleware sees it.
  It travels out inside an `MCPError` instead — the one type mcp re-raises — which is why a
  protected MCP tool must be registered through `governed_tool`.
- **`integrations/tools.py` is a fourth module the plan did not name.** MCP's `tools/list` and
  Pydantic-AI's `prepare` are two spellings of one question, so they get one framework-free
  implementation and cannot answer it differently.

The plan's sub-agent split held. What it did not anticipate is that the first working build of
the MCP dispatch path decided every allowed call twice — one dispatch, two `allowed` audit
records — which for an audit-first library is a correctness defect rather than an
inefficiency, and was only visible by counting records off a real sink. It is worth counting
that sort of thing in Phase 5 too.

### The plan, as written


**Goal.** The same enforcement on agent tool calls, including per-principal tool-manifest
filtering, demonstrating that nested relationships are resolved by policy, not the model.

**Deliverables.**
- `integrations/fastmcp.py` — protect tool handlers (and/or server middleware intercepting
  tool dispatch); establish principal from the MCP auth context; **`list_tools` filtering**
  so tools/argument shapes a principal is not entitled to are hidden from the model.
- `integrations/pydantic_ai.py` — bridge `RunContext.deps` → `establish(...)`; protect
  `@agent.tool` functions; surface `_authz` in tool results.
- `examples/fastmcp_server/` — a small FastMCP server exposing 2–3 protected tools, one of
  which is only invocable when a **multi-hop relationship** holds (e.g. principal may act on
  a resource only via a delegation/team edge). This is the showcase for relationship
  resolution offloaded to Cedar.
- `examples/pydantic_ai_agent/` — an agent whose tools are protected and whose principal is
  the human the agent acts for (on-behalf-of / delegation).

**Sub-agent split.** (a) fastmcp integration + server example + list_tools filtering; (b)
pydantic_ai integration + agent example; (c) tests for both.

**Tests.** simulate proposed tool calls: entitled call runs with filtered args + defaults;
unentitled call denied; `list_tools` returns only permitted tools for a given principal; the
multi-hop scenario allows the call only when the relationship edge exists and denies
otherwise; the agent's on-behalf-of principal is enforced.

**Acceptance.** `pixi run -e agent test-integration` green; `run-mcp` and `run-agent`
work; extras `sentrykit[fastmcp]` / `sentrykit[pydantic-ai]` resolve.

---

## Phase 5 — Policy pack, CLI + audit report, docs & release

**Goal.** Ship the sensible-defaults policy pack, the maintenance/audit CLI, and make the
project releasable and fully documented.

**Deliverables.**
- `policy/pack/` + `policy/loader.py` — a domain-neutral Cedar policy pack expressed only in
  authz vocabulary (principal/action/resource/context/obligation): RBAC roles, group
  hierarchy, ownership, delegation / on-behalf-of, expiry/TTL (with injected `now`),
  break-the-glass (emergency flag flips forbid→permit with mandatory obligations),
  separation-of-duties, just-in-time elevation. Ship as data with a schema; provide
  template-linked-grant helpers for time-boxed grants.
- `cli.py` (`sentrykit` entry point) — `policy validate <dir>` (validate/lint the pack;
  confirm what your installed cedarpy exposes and fall back to the Cedar CLI where formal
  validation isn't available — see design-decisions ADR-002), `grant` / `revoke` (mutate the
  grant store, each emitting an audit record), `audit-report --from --to --out`
  (period aggregation → markdown; optional pdf). Admin mutations are themselves governed by
  the engine (self-governed) and logged.
- Docs pass — fill `docs/` (quickstart, concepts, web, agents, policies, audit, plugins) and
  regenerate the README; ensure `pixi run docs` builds `--strict`.
- Release readiness — extras matrix verified, `py.typed` shipped, version set, CHANGELOG
  updated, `pixi run build` produces a wheel+sdist.

**Sub-agent split.** (a) policy pack + loader + scenario tests; (b) cli + audit-report; (c)
docs + packaging/release checklist.

**Tests (`tests/scenarios/`).** each policy pattern has a scenario: BTG grants with
obligations and denies without the flag; a delegation chain authorizes only within scope and
expiry (use frozen time); SoD blocks conflicting roles; expired grant denied; report
generator produces the expected aggregates over a seeded audit log.

**Acceptance.** `pixi run -e all check` green; all four example apps demonstrate the full
flow; `sentrykit audit-report` emits a document; `pixi run build` succeeds.

---

## Cross-phase reminders

- Update `docs/`, `dev-docs/`, and `README.md` in the *fix & document* step of every loop —
  never defer documentation to a later phase.
- Keep the core free of framework/agent imports; keep every backend and integration behind
  an entry point and an optional extra.
- Commit per the rule in `CLAUDE.md` §2. Never let a tooling reference into a commit message.
