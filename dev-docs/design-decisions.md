# Design decisions (ADRs)

Lightweight architecture decision records. Status: Accepted unless noted. Add new ADRs
rather than rewriting old ones; supersede explicitly.

## ADR-001 — Cedar as the single policy engine
**Decision.** Use AWS Cedar (via `cedarpy`) as the *only* policy engine. Do not add Casbin,
and do not run "both."
**Why.** The workload is attribute-rich and argument-level; even the coarse gate needs
context (args, channel, time, break-glass) that Cedar handles natively and Casbin does not.
One engine means one auditable surface, one policy language, and Cedar's determining-policy
diagnostics + human-readable, analyzable policies. Running two engines splits the model and
forces an auditor to prove they compose.
**Alternatives.** PyCasbin (boolean, no argument filtering/defaults); Oso (open-source line
deprecated); Vakt/py-abac (ABAC, boolean). "Both" only makes sense as a migration bridge off
a large existing Casbin base — not our case.

## ADR-002 — Boolean gate + Python-side argument filtering now; TPE later
**Decision.** Cedar returns allow/deny; sentrykit performs argument filtering and default
injection in Python from entity attributes. Keep a Cedar `forbid` backstop as defense in
depth.
**Why.** Attribute-driven filtering works today, is maintainable, and — the part that
matters for ADR-006 — is explicable to an auditor: a rejection names the rule it violated.
**Amended 2026-08-18 (phase 1 research).** The original rationale said `cedarpy` "does not
expose partial evaluation". That is no longer true: 4.8.7 ships `is_authorized_partial` and
`PartialAuthzResult` with `residuals`, `must_be_determining` and `nontrivial_residuals`. The
decision stands anyway, for different reasons: cedarpy's own docstring warns that a partial
result **must not** be used as a final authorization decision, so a residual-driven filter
would still need a full `is_authorized` re-run per candidate argument set; and turning a
residual AST into an allow-set / range / pattern is a compiler, not a module. The blocker is
residual *interpretation*, not availability.
**Also confirmed.** `validate_policies(policies, schema)` is available and returns a
structured `ValidationResult`, so the phase 5 `sentrykit policy validate` command does not
need to shell out to the Cedar CLI.
**Amended 2026-08-18 (phase 2 research).** The `validate_policies` contract is now pinned by
experiment rather than inferred: the signature is `(policies: str, schema: str | dict |
Schema) -> ValidationResult`, the result carries `validation_passed`, `errors` (each with
`.policy_id` and `.error`) and `id_annotations_by_policy_id`, and it **never raises** — a
policy parse error and a schema parse error both come back as ordinary entries in `errors`
with an empty `policy_id`. `FilesystemPolicySource` (phase 2) and `sentrykit policy validate`
(phase 5) therefore branch on `validation_passed` and translate failure into
`ConfigurationError` themselves. `Schema.from_str` accepts Cedar schema syntax only, not the
JSON schema form.

## ADR-003 — Ambient context via `contextvars`, fail-closed
**Decision.** Providers set an ambient `ContextVar` at the boundary; `@protect` reads it;
explicit `_as=` overrides; no principal ⇒ deny.
**Why.** It is the Pythonic way to make an arbitrary nested callable authz-aware without
threading the principal through every signature. Propagates across `await`/`to_thread`;
`ThreadPoolExecutor` needs `copy_context()` (shipped helper).

## ADR-004 — Everything pluggable via Protocols + entry points; multiplicity via composites
**Decision.** Stores, sinks, policy sources, and framework providers are `Protocol`s,
addressed by name/DSN, discovered via `importlib.metadata` entry points. Multiple-of-a-type
is a composite that satisfies the same Protocol.
**Why.** Built-in and third-party backends become indistinguishable to the core; "add a
framework" and "add a sink" are the same task; the core stays thin and framework-free.

## ADR-005 — Policies-as-code (git) + versioned S3 distribution; grants-as-data
**Decision.** Author/review Cedar *policy logic* in files under version control; distribute
the compiled bundle at runtime from a **versioned S3 prefix** (filesystem locally). Keep
*grants/assignments* as mutable entity data in a store; represent time-boxed grants as
attributes + `context.now` (or template-linked policies). The admin surface mutates data
only.
**Why.** Reconciles a mutable admin API with finance-grade change control: git history is the
policy-change record; S3 object versioning is a second artifact-level record; DynamoDB is the
option for dynamic/per-tenant policy but requires modeling versioning yourself. Local is the
zero-config default; S3 is the default *remote*.

## ADR-006 — Audit-first
**Decision.** Emit one tamper-evident `AuthzAuditRecord` per decision and per admin mutation;
snapshot effective principal attributes at decision time; pin `policy_set_hash` for
reproducibility; tag per-policy provenance; hash-chain records. Durable backends: Iceberg-on-
S3 (period query = the report) or S3 Object Lock (WORM).
**Why.** The yearly audit report is a query, not manual log-reading; reproducibility and
provenance are what survive scrutiny.

## ADR-007 — Mask upstream of the immutable write
**Decision.** Apply masking (`redact | partial | hmac | tokenize`) *before* handing data to
an append-only sink. Reversible token maps live in a separate mutable vault, never in the
audit store. HMAC (keyed) is the default so records can be correlated without exposing raw
values.
**Why.** Anything written to WORM is permanent — raw sensitive data there collides with
erasure obligations. Masking at read/report time is too late.

## ADR-008 — Action-layer positioning; relationship resolution offloaded to policy
**Decision.** Position sentrykit as pre-action authorization that refuses side effects, not a
content/output validator. Treat nested, multi-hop authorization relationships as Cedar's job,
never the model's.
**Why.** Output validators run after the model and can't refuse an action. The differentiator
vs other action-layer tools (APort, MS Agent Governance Toolkit, Rego-based guards) is the
combination: self-hosted, framework-agnostic across web *and* agents, Cedar-based, audit-
first, one decorator. An agent acting for a user is the delegation/on-behalf-of pattern, so
agent authz reuses the same machinery.

## ADR-009 — One decorator, N context providers
**Decision.** A single `protect()` decorator works on any callable; frameworks contribute
only a context provider (establish + error mapping).
**Why.** Uniform mental model and uniform enforcement across routes, plain functions, and
agent tools.

## ADR-010 — pixi for dev environments; hatchling + PEP 621 for packaging
**Decision.** `pixi.toml` owns dev environments, feature composition, and governance tasks;
`pyproject.toml` (hatchling, src layout) owns packaging, extras, entry-point groups, and tool
config. Apache-2.0 license.
**Why.** Reproducible multi-extra dev environments and a clean, standard package.
**Confirmed (phase 1).** pixi 0.70.2 accepts the `[workspace]` manifest form; no change
needed. Governance tasks must stay cross-platform — the manifest lists `win-64`, so a task
that shells out to a POSIX utility is a broken task, not a shortcut.

## ADR-011 — Commit messages carry no tooling attribution
**Decision.** Conventional Commits, enforced by `scripts/check_commit_msg.py` as a
`commit-msg` hook; no references to AI assistants/models or "generated with/by" trailers.
**Why.** Project requirement; enforced mechanically so it cannot be forgotten.

## ADR-012 — Obligations are Cedar annotations on the determining policies
**Decision.** An obligation is declared in the policy itself, as a single comma-separated
`@obligations("...")` annotation, and is surfaced at decision time by joining
`CedarDecision.determining_policies` against an annotation index built from the policy text.
Only the determining **permit** policies contribute obligations to a call that proceeds; a
determining `forbid`'s annotations are recorded on the denial instead. Each obligation is a
`verb:target` pair (`mask:customer_id`, `redact:ssn`, `hmac:email`, `tokenize:iban`,
`notify:secops`); masking verbs are consumed by `masking.py`, the rest are carried on the
envelope and the audit record for the host to discharge.
**Why.** Phase 2 research established that `cedarpy` exposes *every* annotation — but only
through `policies_to_json_str(text)`, never through the opaque `PolicySet` handle, and keyed
by Cedar's generated `policyN` ids, which are positional in the policy text. So the index has
to be derived from exactly the text the engine was built from, and `PolicySource.load()` is
the only place that owns both. Putting obligations in the policy keeps ADR-005 intact:
"what must also happen when this is permitted" is reviewed logic, not mutable grant data.
**Constraints this inherits from Cedar.** An annotation key cannot repeat on one policy
(`ValueError: duplicate annotation`) — hence one comma-separated value rather than repeated
annotations. Keys cannot contain dots. A valueless annotation parses to `None`, and a policy
with no annotations parses to `None` rather than `{}`; both are read as "absent".
**Alternatives.** Obligations as grant-store data (loses review; an obligation is a rule, not
an assignment). A side-car obligations file keyed by `@id` (a second thing to keep in sync,
and `@id` is not unique across sources). Inferring obligations from the resource type
(implicit, unauditable).

## ADR-013 — The JSONL audit sink is single-writer, byte-pinned, and flush-by-default
**Decision.** `JsonlAuditSink` holds one file handle open for its lifetime, opened in append
mode with `encoding="utf-8", newline="\n"`, serializes `write()` behind a `threading.Lock`,
recovers `prev_hash` from the last line when it opens an existing file, flushes every record,
and calls `os.fsync` only when the DSN asks (`jsonl://path?fsync=true`). One file has exactly
one writing process; concurrent writers get separate files (or a `CompositeAuditSink`).
**Why.** All four parts are forced by measurement on the win-64 platform this repo targets:
- Default text-mode append writes `\r\n` on Windows. A hash chain is over bytes, so the same
  record would hash differently per platform and an external verifier would disagree with the
  writer. `newline="\n"` is a correctness requirement.
- `open(path, "a")` per write is **not** atomic on Windows — the CRT emulates append as
  seek-to-end plus write. Measured: 8 threads × 200 records produced 1346 of 1600 lines, 3 of
  them malformed. One shared handle behind a lock produced 1600/1600 in 0.01 s.
- `record_hash` depends on `prev_hash`, so the writer must know the file's tail. That state
  cannot be shared across processes without a distributed lock, which makes single-writer an
  invariant of the chain rather than a shortcut. `fcntl` does not exist on Windows anyway.
- `fsync` costs 3.71 ms per record versus 0.007 ms for `flush` alone. Paying 3.7 ms on every
  authorization decision to defend against machine crash (process crash is already covered by
  `flush`) is the wrong default for a pre-action gate; it stays available as a DSN option, and
  WORM-grade durability is what the phase 5 S3 / Iceberg backends are for.
**Consequence for `fail_mode`.** A sink that cannot be written to raises, and under
`fail_mode="closed"` the call is refused — "can't prove it, don't do it", per the logging
standards.

## ADR-014 — Masking is unconditional on the audit path
**Decision.** Every value crossing into an `AuditSink` is masked first, and the `redaction`
setting cannot switch that off. `redaction` governs the caller-facing `_authz` envelope and
the operational logs. Selection precedence is: a policy obligation (`mask:field`) beats a
`Sensitive(...)` annotation on the callable's signature, which beats the configured default
strategy. Reversible token maps live in a separate vault the audit store never sees.
**Why.** ADR-007 turns on the write being immutable: a raw value in a WORM store cannot be
withdrawn, so the one place masking must not be configurable is the one place it is
permanent. Making it a setting would mean a single environment variable silently converts the
compliance artifact into a liability. Policy beats code because an obligation is reviewed
logic and an annotation is a developer's default.

## ADR-015 — A context provider releases at teardown what it established at the boundary
**Decision.** Every provider pairs `establish()` at the request boundary with `release()` at
teardown — in a `finally` for ASGI, in `teardown_request` for Flask. `release()` is total: it
resets the scope when there is one, clears the ambient context outright when there is not, and
drops the last envelope either way.
**Why.** Not tidiness — measured. Flask serves a request on a pooled worker thread and its test
client serves one in the caller's own context, so an un-reset `ContextVar` leaves request *N*'s
principal ambient after it ends, and anything on that thread outside a request acts as them.
Removing the Flask teardown and calling a protected function from the test process returned a
`200` as `alice`; with teardown in place the same call raises `NoContext`.
**Consequence for tests.** Because `establish()` also *clears* the context for an
unauthenticated caller, a behavioural "principal A, then anonymous ⇒ denied" test passes even
with the release deleted. The assertions with teeth are `current_principal() is None` between
two requests in one context, and driving the ASGI app twice inside a single `contextvars`
context. Both are in `tests/integration/test_web_context_isolation.py`.

## ADR-016 — Refusals are rendered from the exception, not from ambient state
**Decision.** The verbosity-aware refusal renderer in `integrations/base.py` builds the
`_authz` body from the raised error alone. `last_envelope()` is not consulted.
**Why.** It is not reliably there. A sync FastAPI route runs in an AnyIO worker thread that
receives a *copy* of the context, so anything written inside it — including the envelope the
engine records — is discarded on return, and an exception handler sees nothing. A
yield-dependency has the mirror problem: its teardown unwinds below `ExceptionMiddleware`, so
the context is already released when the handler runs. Every sentrykit error carries structured
detail (the refused action and its determining policies, the offending argument and reason, the
allowed set, pydantic's field errors), so reading the exception is both sufficient and
deterministic — the same refusal renders identically on every framework and every code path.

## ADR-017 — Manifest filtering is the enforcement decision, made twice
**Decision.** A tool is hidden from a principal **if and only if** invoking it would be
refused by the authorization gate. MCP's `tools/list` and Pydantic-AI's `prepare` both call
the same `Governor.plan(...)` the dispatch path calls, through one framework-free module
(`integrations/tools.py`), and the dispatch path re-runs it in full regardless of what the
manifest said. An entitlement refusal (`AuthzDenied`, `NoContext`) hides; an argument-level
refusal does not.
**Why.** Hiding is a *usability* affordance, never a control. A model that is not shown a tool
it may not use stops burning turns proposing calls that cannot succeed — but a client is free
to skip `tools/list` and call any name it likes, so "the model did not know it existed" is not
an access-control argument. Making the two answers come from one implementation is what stops
them drifting into a hole; asserting *both halves in the same test* is what proves they have
not. The *if* half matters too: a filter that hid more than it had to would silently narrow
what an agent can do for its user, and nothing would report it.
The split between entitlement and argument refusals follows from the probe having no
arguments. A tool with a required parameter and no policy default raises `DefaultUnavailable`
for *everybody*; treating that as a denial would hide every such tool from every principal.
Argument-level refusal is therefore deferred to dispatch, where the model has actually
proposed something to decide about.
**Alternatives.** A separate, cheaper visibility predicate (two implementations, one of which
is not the one that enforces — rejected outright). Filtering only, with no dispatch check
(security by obscurity). No filtering (correct but wasteful, and it leaks the shape of other
principals' entitlements to every caller).

## ADR-018 — The agent providers target mcp 2.0; `fastmcp` is a name we keep, not a package we import
**Decision.** `sentrykit.integrations.fastmcp`, the `sentrykit[fastmcp]` extra and the
`fastmcp://` DSN keep their names. What they are built against is `mcp>=2,<3` —
`mcp.server.mcpserver.MCPServer` and `mcp.server.context.ServerMiddleware`. Nothing in
sentrykit imports the standalone `fastmcp` distribution.
**Why.** mcp 2.0 renamed `mcp.server.fastmcp.FastMCP` to `MCPServer`, and the separately
published `fastmcp` package no longer imports against mcp 2.0 at all (it still expects
`McpError`, which mcp 2.0 removed). The user-facing names were already committed to by the
plan, the entry point and the docs, and renaming them would churn every host's configuration
to describe an implementation detail. Keeping the name while stating plainly, in the module
docstring and in `docs/agents.md`, that no `pip install fastmcp` is needed costs one paragraph
and avoids a broken environment for anyone who reads the module name as an instruction.
**Alternatives.** Rename everything to `mcpserver` (churns the DSN and the extra for no
behavioural gain, and the ecosystem still says "FastMCP"). Support both packages (the
standalone one does not import; there is nothing to support).

## ADR-019 — An agent tool advertises omittable arguments, and carries its refusal out in an `MCPError`
**Decision.** A protected callable is registered as an agent tool through a shim
(`integrations/tools.proposable`) that re-declares the arguments policy supplies as optional,
and — on MCP — through a translator that re-raises a refusal inside an `MCPError`. Both agent
integrations expose one registration helper, `governed_tool`, that composes them.
**Why.** Two framework behaviours, each measured on both boundaries
(`notes/phase-4-research.md` §10, §11), otherwise break a promise the library makes.
*First*, both frameworks validate the caller's proposal against the tool's advertised JSON
schema **before** dispatch, so an argument marked `required` can never be omitted and can
therefore never be filled from the principal's defaults. Per-principal default injection —
one of the three things sentrykit does — would be unreachable from an agent, demonstrable only
by calling the protected function directly and bypassing the boundary the integration exists
to govern. The shim is the same move the FastAPI example already makes one layer out: declare
the parameter optional at the boundary and forward only what was actually supplied. An absent
argument has to be *expressible*, and on an agent boundary the tool signature is the boundary.
*Second*, mcp's `Tool.run` wraps anything a tool body raises in a `ToolError`, which
`_handle_call_tool` turns into a result with **no structured content** — so a `SentrykitError`
never reaches a `ServerMiddleware` and the `_authz` envelope is lost. `MCPError` is the one
exception it re-raises, so the refusal travels inside one and the middleware renders it.
**Alternatives.** Deciding the call *before* dispatch, in the middleware, and writing the
planned arguments back over the request's. It works and was built first, but it decides every
allowed call twice: measured, one allowed dispatch wrote **two** `allowed` audit records. For a
library positioned audit-first, whose reporting aggregates that log over a period, an allow
counted twice makes every aggregate wrong. It also forces the caller-facing envelope to be
*reconstructed* from the pre-flight plan rather than reported from the real one, so
`defaults_applied` describes a decision the decorator did not make. Re-deciding *after*
dispatch instead trades the same defect onto denials.
**Consequence.** A protected MCP tool **must** be registered through `governed_tool`; a plain
`@server.tool()` over `@protect` still has its refusal swallowed. That sharp edge is stated in
the module docstring and in `docs/agents.md` rather than engineered away, because the
alternative is monkey-patching another library's dispatch.
