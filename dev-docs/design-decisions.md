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
**Amended 2026-08-20 — the argument layer leads; relationship resolution is a capability, not
the differentiator.** The original "Why" made *relationship resolution offloaded to policy* the
defining value. It is not one. An entity hierarchy resolving `user → team → project → resource`
is Cedar's own strength, available to anyone calling `is_authorized` directly, so a reader who
knows Cedar reads that claim as sentrykit taking credit for the engine it is built on — and the
question it invites, "then why not call Cedar directly?", has a better answer than the one the
ADR was giving. The order is re-weighted to: per-(principal, action) argument constraints;
**narrow-and-continue**, where a proposal above what the principal may have is reduced to what
they may have and the call proceeds; policy-supplied default injection, with each default
checked against its own constraint before it is applied (ADR-027); constraint self-consistency
refused at the grant write rather than discovered at the call; and the masked, hash-chained
record of all of it. Argument ceilings (ADR-028) sit across the first four and are the sharpest
statement of the line: a ceiling is the only thing a reviewed policy file can declare that
reaches narrow-and-continue rather than the gate, because Cedar's effect vocabulary is
permit/forbid and "you asked for 500, you may not have that — here is the call at what you may
have" is not expressible in it.
**What does not change.** Pre-action rather than output validation stands, and so does the
niche being the *combination* — self-hosted, web *and* agents, Cedar-based, audit-first, one
decorator. Relationship resolution stays a first-class, documented capability: shorter and later
on each page, framed as composing with the argument layer, and never deleted — an agent acting
for a user is still the delegation pattern, still on the same machinery. Cedar is described as
the foundation sentrykit stands on and never as something being out-done. One honesty
requirement falls out of the re-weighting and is now in `SECURITY.md`: the verified engine is
Cedar's, covering the gate; sentrykit claims no verification for the layer above it, which is
ordinary tested Python.

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

**Amended 2026-11-08 — the invariant is one writer per *chain*, not per *process*, and this
ADR fixed the lock at the wrong layer.** The third bullet above reasons that `prev_hash` state
"cannot be shared across processes without a distributed lock, which makes single-writer an
invariant of the chain". The premise is true and the conclusion does not follow from it: the
state the chain depends on lives on `AuditTrail`, and one process with eight threads shares one
`AuditTrail` while satisfying every word of the single-writing-*process* rule. So this ADR
anticipated threads — its own measurement is 8 threads × 200 records — put a lock in
`JsonlAuditSink.write` to defend the *file*, and left the read-modify-write of `_prev_hash` and
`_sequence` one layer above it unprotected.

Measured through the public decorator path at 8 × 200: the in-memory sink wrote 1600 of 1600
records with 1597 distinct sequence numbers and `verify_chain` returned
`ok=False broken_at=189`; the JSONL sink wrote 1600 of 1600 lines with **1452** distinct
sequences and `broken_at=2`. The durable, recommended sink is the worse of the two, and
instructively so: the lock this ADR added serialises slow file IO *inside* the trail's
unprotected window, so the fix below it widened the defect above it.

Nothing crossed a security boundary — the gate decided correctly, every record was written,
each record's own hash still verified, and masking still ran upstream of the write. What broke
is the integrity *evidence*, in both directions: `verify_chain` reported "a record was removed
or altered" over a healthy log, which `docs/audit.md` tells an operator to treat as fatal, and
once breaks are ambient noise a genuine deletion is indistinguishable from them. See ADR-032
for the decision that closes it, and for the cost of closing it that way.

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

## ADR-018 — The agent providers target mcp 2.0, and the integration is named after it
**Decision.** `sentrykit.integrations.mcp`, the `sentrykit[mcp]` extra and the
`mcp://` DSN keep their names. What they are built against is `mcp>=2,<3` —
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

**Amended 2026-11-08 — the name is `mcp`, and the borrowed spelling is gone everywhere.** The
original decision rested on two premises, and the ecosystem moved under both.

*What changed.* `fastmcp` 4.x is no longer merely a package we do not import. It ships its own
`auth=` parameter on `@mcp.tool` — tool-call authorization, declared at the registration site.
That is sentrykit's own primitive, so `sentrykit[fastmcp]` had stopped reading as a borrowed
convention and started reading as a claim about a direct competitor's integration surface. The
second premise was that the names were committed to. They were committed to by this
repository's own plan, entry point and docs — not by any release: 0.2.0 is unpublished, so the
set of users whose imports a rename would break is empty.

*What was decided.* The extra, the module, the class, the DSN and the entry point are spelled
after the one distribution they name: `sentrykit[mcp]`, `sentrykit.integrations.mcp`,
`MCPProvider`, `mcp://`. Three reasons beyond the collision. First, it restores a convention
this repository already follows everywhere else — `fastapi`, `flask` and `pydantic-ai` each
name the distribution their extra installs, and `fastmcp` was the only registry name that
pointed at a package sentrykit does not depend on. Second, `docs/agents.md` had to carry a note
titled "`sentrykit[fastmcp]` does not install `fastmcp`"; a name needing a disclaimer inside
the install block is the wrong name, and the rename retires the disclaimer rather than
rewording it. Third, `mcp` names the protocol, which no single vendor can capture the way
`fastmcp` captured "FastMCP". `mcpserver` was rejected again, for a sharper reason than last
time: it tracks another project's internal module path, which is exactly the kind of name that
gets renamed a second time. Verified before committing to it — a module at
`sentrykit/integrations/mcp.py` imports the top-level `mcp` with no shadowing, since absolute
imports are the Python 3 default.

*No deprecated alias.* Argued both ways. For: the ecosystem still says "FastMCP", so a reader
may guess `fastmcp://`, and an alias turns their failure into a success. Against, and
decisive: there are no users, so the alias protects nobody, while costing four permanent shims
(extra, module, entry point, DSN name) that each need a test, a documented line and a
deprecation cycle they never earned. Worse, an alias reintroduces the defect it is meant to
soften — a resolving `fastmcp://` keeps that spelling in the registry listing, in copied
`pip install` strings and in error messages, permanently pointing at a competitor's primitive.
A guess that works teaches the wrong name. A guess that fails teaches the right one, and the
registry already fails informatively: `no context provider is registered as 'fastmcp';
available: fastapi, flask, mcp, pydantic-ai`.

*What still spells `fastmcp`, deliberately.* The mcp 1.x class name `mcp.server.fastmcp.FastMCP`,
cited as the thing mcp 2.0 renamed. One line in the module docstring and in `docs/agents.md`
saying the separately published project is a different library and is not installed by the
extra — now a clarification rather than a defence of a borrowed name. And
`test_the_standalone_fastmcp_project_is_never_imported`, which keeps checking mechanically that
the declared requirement is `mcp<3,>=2` and that nothing in the module came from `fastmcp`.

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

## ADR-020 — The shipped pack is a policy source, and its schema is opt-in
**Decision.** The policy pack reaches a governor as an ordinary `PolicySource` under a
`pack://` DSN, registered in the same entry-point group a third party would use, unioned by
the same composite. Its `pack.cedarschema` ships with it but is **not** put on the loaded
bundle unless the DSN asks (`pack://?schema=true`).
**Why.** Two separate reasons. The source part is CLAUDE.md §3 applied to ourselves: a pack
that arrived through a private mechanism would be a second policy system to keep in step, and
would be privileged in a way no third-party pack could be. The schema part is a measurement
(phase 5 research §4, §7): `CompositePolicySource` concatenates its members' schemas, and a
Cedar engine built *with* a schema validates every **request** against it — so a pack that
contributed one by default would make every request naming an action the pack never heard of
fail to parse, in an application that was working a moment earlier. The pack's decisions were
measured identical with and without it, so the default costs nothing.
**Consequence.** Adopting the pack is additive and reversible: drop the DSN and it is gone.
A host that *does* opt into the schema must declare only what the pack does not — redeclaring
`User`, `Role`, `Group` or `Resource` is a Cedar schema parse error.
**Alternatives.** Shipping the pack as a directory users copy (loses the ability to fix a
pattern in a release). A `sentrykit.pack` import hook (a second mechanism). Namespacing the
pack's entity types (`sentrykit::User`) so schemas could never collide — which would force
every principal in the system to change type in order to use one pattern.

## ADR-021 — Every pack pattern is attribute-driven, and half of them forbid
**Decision.** No shipped policy names a role, a resource type or an action. The **resource**
declares what it requires (`required_role`, `group`, `owner`, `emergency_only`,
`emergency_role`, `conflicting_role`, `prepared_by`), the **grant store** supplies the
principal's edges and attributes, and the **context** supplies `now`, `break_glass`,
`on_behalf_of` and `justification`. Five of the eight patterns contribute a `forbid`.
**Why.** A shipped pack cannot know anyone's vocabulary, so a pattern that named one would be
an example rather than a policy. Reading the *shape* of the request instead makes adoption a
matter of putting an attribute on an entity — which is data, which is ADR-005 restated. The
forbids are what make a pattern *contain* rather than merely permit:
`delegation-outside-scope-forbidden` is the reason a delegated principal cannot reach the
plain RBAC permit and ignore the scope it was delegated, and
`emergency-resource-forbidden-without-flag` is the whole of what makes an emergency-only
resource emergency-only.
**Measured.** Entity-valued attributes work as the right-hand side of `in`
(`principal in resource.required_role`), a `Set<Action>` attribute works with
`action in principal.delegated_actions`, and transitive `in` resolves a group hierarchy at
any depth. Timestamps are epoch **`Long`s**, because `coerce_value` renders every `datetime`
that way and Cedar has no ordering on strings.

## ADR-022 — Break-the-glass takes an entitlement, a flag *and* a justification
**Decision.** The `break-the-glass` permit requires the principal to be in the resource's
`emergency_role`, the context to carry `break_glass`, and the context to carry a **non-empty**
`justification`. It carries `notify:secops` and `record:justification` as mandatory
obligations.
**Why.** The obvious draft — permit when `resource.emergency_only && context.break_glass` —
was written, measured, and found to authorize **anyone at all**: the flag is caller-supplied,
and a Cedar `permit` needs no base entitlement to fire. The same run showed the symptom
downstream, with a closed JIT-elevation window still allowed because the break-glass permit
had fired instead. An emergency path is the highest-risk rule a pack can ship, so it is the
one that must not be convenient.
**Consequence.** A host adopting break-the-glass must model an emergency role and must pass a
justification through `establish(...)`. That is more setup than a boolean, and it is the
point.

## ADR-023 — Templates are linked by sentrykit, and produce a policy *and* a grant
**Decision.** `link_template` fills `?principal` / `?resource` textually, prepends an `@id`,
and appends `when { context has now && context.now <= <epoch> }` when an expiry is asked for.
It returns the concrete policy **and** the matching `GrantSpec`. Templates live under
`pack/templates/*.cedartemplate`, outside the `*.cedar` glob.
**Why.** `cedarpy` 4.8.7 exposes no linking API at all — measured: `dir(cedarpy)` has no
`link`, no `template`, no `PolicyTemplate`. An unlinked template in a policy set is inert, and
`policy_annotations` drops it entirely (though cedarpy keeps positional ids aligned, so
provenance survives one). Returning both halves is ADR-005 honoured rather than dodged: a
time-boxed grant is reviewable logic *and* revocable data, and emitting only the policy would
leave nothing for an admin surface to list or an auditor to query.
**The `has` guard is not cosmetic.** Cedar's validator refuses an unconditional read of an
optional context attribute (`unable to guarantee safety of access to optional attribute
'now'`), so an unguarded link would evaluate correctly and fail `sentrykit policy validate`
the day anyone wrote one out to a directory.

## ADR-024 — The CLI's admin surface is governed, and the pack ships no permit for it
**Decision.** `sentrykit grant` and `sentrykit revoke` are `@protect`-ed callables decided by
the same governor the application uses, against `Action::"admin.grant"` /
`Action::"admin.revoke"` on `Resource::"admin.grants"`. The `GrantSpec` is built from the
**policy-processed** arguments, not from `argv`. The shipped pack contains **no** permit for
either action, and there is no bootstrap flag.
**Why.** Architecture §5 says the admin surface is self-governed and self-logged; making it a
`@protect`-ed callable is the cheapest way for that to be literally true rather than
approximately true, and it means an argument constraint decides *which* grants an operator may
make, not merely whether they may make any. Shipping a permit for the action that hands out
authority is not something a library gets to do on a host's behalf, and a `--bootstrap` flag
that skipped the gate for the first grant would be a back door that never closes — so the
first operator is seeded in provisioning code, where the store is an ordinary object.
**Consequence.** An allowed mutation writes **two** audit records (the decision, then the
mutation) and a refused one writes **one**. Those counts are asserted in the scenario suite,
because the phase 4 double-write was invisible to every behavioural assertion. The default
`--policy pack://` therefore refuses until a host writes the permit, and the refusal says so
rather than printing an empty policy list.

## ADR-025 — A file-backed grant store ships, subclassing the in-memory one
**Decision.** `JsonFileGrantStore` persists grants to one JSON document, written to a sibling
temp file and renamed over the target, with reads gated on `(st_mtime_ns, st_size)`. It
**subclasses** `InMemoryGrantStore` rather than reimplementing the `GrantStore` contract. One
writing process at a time, stated in the docstring rather than defended with a lock.
**Why.** Not in the phase 5 plan, and added because the plan's own acceptance criterion could
not otherwise hold: `sentrykit grant` resolves the operator through the grant store and fails
closed, so with only an in-process store shipping, every shell invocation began against an
empty store and refused itself. Architecture §4 calls the grant store the admin surface's only
write target; shipping the surface without a durable target left the command group unreachable
outside a test. Subclassing keeps materialization — expiry, revocation, parent edges,
per-action constraints — as one piece of code, because a second hand-written materializer is
precisely how two stores start disagreeing about who holds what.
**`exclude_unset=True` is a correctness requirement.** `ArgumentConstraint.has_default` is
derived from `model_fields_set`, so a plain `model_dump()` writes `"default": null` for a
constraint that configured none — and read back, that constraint would begin injecting `None`
into every call that omitted the argument.
**Alternatives.** A `--as-role` flag letting an operator declare their own roles (a hole that
defeats the self-governance in ADR-024). Leaving the gap and documenting it (the criterion
"grant/revoke work" would have been false from any shell).

## ADR-026 — Cedar's reserved `__` keys are refused, not dropped or escaped
**Decision.** `_coerce_mapping` rejects any supplied record key beginning with `__` — the
whole reserved prefix, not the two spellings Cedar defines today — with a new `ReservedKey`
error, checked before the value is coerced and at any nesting depth. The refusal is raised in
`cedar.py` and converted by `Governor.plan` into an audited refusal that `fail_mode` never
sees. `EntityRef` keeps its own trusted path to `{"__entity": ...}` and is unaffected.
**Why.** `coerce_value` recursed into supplied mappings and stringified their keys, so a
dict-valued argument carrying `{"__entity": {"type": "Group", "id": "approved"}}` reached the
evaluator as a genuine `Group::"approved"`. Measured end to end through `PolicyEngine` against
the argument-aware `forbid` backstop the docs describe: the forged group produced **allow,
`failed=False`** — invisible to `fail_mode="closed"` — while `Region::"cn"` correctly denied.
Cedar's `in` is reflexive, so passing the approved group *as* the region satisfies
`context.args.region in Group::"approved"`. A Cedar schema declaring `context.args` contains
it (the forgery becomes `no-decision`, `failed=True`), but `PolicyEngine`'s `schema` is
optional and the shipped `pack.cedarschema` declares no `context.args` member, so the
mitigation is not one a host reliably has.
**Why not drop, and why not escape.** Dropping the reserved key leaves the enclosing record
present but empty, and dropping the whole entry makes `context.args has region` false — which
silently switches *off* the backstop the check exists to protect. Escaping the key leaves a
record where an entity was expected, which fails only as a Cedar **type error**; that is an
engine failure, and `fail_mode="open"` tolerates engine failures. Refusing ahead of the gate
is the only option that holds under both fail modes, and it keeps fail-open meaning "tolerate
operator error" rather than "tolerate attacker input".
**On `__extn`.** The sibling form is less severe — it produces an engine error, so
`fail_mode="closed"` already refused it — and was a live bypass only under `fail_mode="open"`.
The same prefix check closes it, so it needs no separate rule.
**Consequence.** A host that legitimately wants an argument to reach policy as an entity
passes an `EntityRef`, which is the only way it ever worked as intended. `ReservedKey` maps to
403 rather than 400: naming the rejected spelling back to the caller would be telling them
what to try next.
**Amended 2026-08-20 — the original consequence over-claimed, and adversarial review found the
second route.** The first draft of this ADR, the `coerce_value` docstring, `docs/concepts.md`
and `SECURITY.md` all said some version of *"only an `EntityRef` your application constructed
becomes an entity reference."* That is false, and `isinstance` is the reason: it is a type
check, not a provenance check. Reproduced end to end on two boundaries:

- **FastAPI** — a route parameter annotated `Annotated[EntityRef | None, Body()]`. The
  `@protect` wrapper is signature-preserving *by design* (`decorator.py`, so framework
  introspection sees the original function), so FastAPI validates the caller's JSON against
  that annotation **before** the wrapper runs and hands `Governor.plan` an already-constructed
  `EntityRef`. `{"type": "Region", "id": "cn"}` → 403 (the guard fires);
  `{"type": "Group", "id": "approved"}` → **200, tool body ran**, clean allow, `failed=False`.
  `["Group", "approved"]` works too, since pydantic builds a `NamedTuple` from a sequence.
- **MCP** — identical, and worse in one respect: `tools/list` *advertises* the shape to the
  model (`{"$defs": {"EntityRef": {"prefixItems": [...], "maxItems": 2, "minItems": 2}}}`), so
  on the boundary whose premise is "the LLM proposes, the policy decides", the model is told it
  may name an entity type.

**Decision on the amendment: correct the claim, do not change the behaviour.** Promotion of an
`EntityRef` object is what that type is *for*, and a parameter typed as one is the application
saying the caller names an entity. Three defenses close it, and two were measured:
Cedar's `is` operator pinning the type (`context.args.region is Region && ...` → the forgery
denies); an allow-set of `EntityRef` values in a grant or a declared ceiling (→ the forgery is
refused at the constraint layer); and a Cedar schema typing `context.args` (→ the request fails
to parse, which `fail_mode="closed"` refuses).

**Alternatives considered and rejected.** Refusing to promote any `EntityRef` found under
`context.args` — it would break the legitimate `context.args.order in principal.owned_orders`
shape and cannot distinguish an app-built reference from a caller-built one, which is the
same `isinstance` limitation one layer up. Refusing a proposed `EntityRef` unless a constraint
bounds it — genuinely fail-closed, but it also refuses in-process application code passing a
reference it built itself, which is over-reach for a library. A typed annotation
(`Annotated[EntityRef, EntityType("Region")]`) would be the real fix and is a new feature; the
constraint layer already expresses the same thing as data.

The accurate invariant, now stated everywhere the old one was: **supplied data can never spell
Cedar's escape form**; an `EntityRef` object is promoted, and typing a caller-facing parameter
as one is a decision the application makes.

## ADR-027 — Constraint self-consistency is checked at the grant write, and defaults are checked at the call
**Decision.** `ArgumentConstraint.inconsistencies()` returns one sentence per way a constraint
contradicts itself — an uncompilable `pattern`, `minimum` above `maximum`, an `allow` member
the constraint's own other rules reject, a `default` it would reject. `GrantStore.grant()`
runs it and raises `ConfigurationError`. Independently, `ConstraintSet.inject_defaults` runs
`check()` on every default before injecting it and **withholds** one that fails, returning it
as a third `DefaultsResult` field rather than raising.

**Extended by ADR-035.** The second half of this decision — a default answers to the constraint
that governs it, so omitting an argument is not a way around the rule on it — held for *policy*
defaults only. A withheld default, or a rejected proposal with no default behind it, left the
parameter absent from what sentrykit passes, and Python then filled the slot from the
callable's signature: a default from another source, which no constraint had seen. ADR-035
applies this rule to that one too.
**Why two places.** The write is where the fault is introduced and where an operator is
present to fix it, so it is the primary defense. But a `ConstraintSet` can also be built in
code and handed to a `Principal` without a store ever seeing it — the `Principal` constructor
takes constraints directly, and that is how the examples and half the tests wire them — so the
decision path cannot assume the write-time check ran.
**Why the value-level checks delegate to `check()`.** Anything else is a second implementation
of the same rules, and the two would drift. The cost is that a structural fault makes `check()`
reject every value, so an uncompilable pattern or inverted bounds short-circuit the value-level
probes rather than restating the same fault once per allow-set member.
**Why not a pydantic validator on the model.** A store also *reads* constraints:
`JsonFileGrantStore` deserializes `ArgumentConstraint` out of its document on every stat-gated
reload. Refusing at construction would make one bad row already on disk fail the load of
**every** principal in the file — a refusal far wider than the fault, and one that arrives at
the worst moment (a restart) rather than at the write. The call path is fail-closed per
argument regardless, so nothing is lost by allowing the object to exist.
**Why `required=True` with a `default` is not reported.** It reads like "this can never fail"
and it is not: `inject_defaults` skips any name not in `spec.parameters`, so a required,
defaulted constraint naming a parameter the callable does not accept still raises
`DefaultUnavailable` legitimately. A rule here would flag a working configuration.
**Why a withheld default is not `arg_handling="strict"`'s business.** `arg_handling` decides
what happens to the *caller's proposal*. Raising `ArgumentRejected` for an argument the caller
never mentioned would report an operator's misconfiguration as the caller's mistake and give
them nothing to change. The withholding is logged at `ERROR`, carried on the envelope and
written to the audit record instead.
**Consequence.** `DefaultsResult` gained a third field. Attribute access is unaffected; code
that unpacked exactly two names needs a third. Pre-1.0, recorded in `CHANGELOG.md`.

## ADR-028 — An argument ceiling is a Cedar annotation, ceilings only, intersecting
**Decision.** A policy may declare argument bounds in a `@constraints` annotation carrying one
compact JSON object of `{argument: {rule: literal}}`. Parsed at bundle load into
`PolicyProvenance.ceiling`; applied at decision time to the determining **permit** policies
only. A ceiling may set `allow`, `deny`, `pattern`, `minimum`, `maximum`, `required` — never
`default`. Ceilings and grant constraints **intersect**; two determining permits' ceilings
intersect with each other. A ceiling on a `forbid`, or any malformed declaration, is a
`ConfigurationError` at load. Under `fail_mode="open"` a governor whose bundle declares any
ceiling refuses an engine failure rather than proceeding.
**Why at all, given it adds no predicate power.** Cedar already evaluates `context.args` in a
`when` clause, so `forbid when { context.args.limit > 100 }` works today. What a ceiling adds
is *effect* power, not predicate power: a `forbid` can only deny the call, whereas an
annotation-carried bound reaches narrow-and-continue and default injection. "You asked for
500, you may not have that — here is the call at what you may have" is not expressible in Cedar
at all — noting that the mechanism is reject-and-refill rather than clamping, so the value the
call runs with is the principal's own default. That single
sentence is the whole justification, and it is the reason the feature earns its place given
that narrow-and-continue is core to the positioning. Secondary and real: it puts the ceiling
in reviewed, version-controlled text that `policy_set_hash` already digests, so a
ceiling-driven decision replays. Every constraint before this was mutable grant data an admin
API could rewrite.
**Why the plumbing is nearly free.** `PolicyProvenance.annotations` already carried *every*
annotation, and `PolicyBundle.provenance_for` already joined a decision against them, keyed
three ways to survive namespacing. `ceilings_for` is a sibling of `obligations_for`. `cedar.py`
is untouched, so the cedarpy-confinement invariant is unaffected.
**Why no `default`.** `ArgumentConstraint.describe()` already withholds a default *value* from
callers on the grounds that a per-principal default can itself be sensitive — someone else's
tenant id. The repo therefore already classifies `default` as principal-scoped grant data, and
putting it in a reviewed policy file inverts policies-as-code/grants-as-data. It is also the
field application developers will ask for first; the answer is the grant row.
**Why intersection, and why that will be reported as a bug.** Two determining permits producing
the *intersection* of their ceilings is inverted relative to Cedar's disjunctive permits, so it
will read as wrong to someone who knows Cedar. It is the security-correct direction and the
answer to "make this one override" is "write the grant row" — because conceding a precedence
marker inside the blob is the first step toward a combination language in a data field.
**Why every check is at load.** Measured: Cedar's `validate_policies` ignores unknown
annotations entirely — a bogus `@totally_made_up("{...}")` gives `validation_passed=True,
errors=[]`. Annotation-carried values therefore get *zero* type checking from Cedar, so all of
it is ours, and the only moment that fails closed is wiring. A declaration checked at decision
time would sit in a green policy set enforcing nothing.
**Why a ceiling on a `forbid` is an error rather than a no-op.** A determining `forbid` never
coexists with an allow, so the ceiling could never apply — and a reviewer reading the file
would believe a bound was enforced. Silent is the failure mode this whole design is arranged
against.
**Why the fail-open refusal is on the path and not at wiring.** `fail_mode` is per-action
overridable through `override_action`, and `apply_overrides` runs on every authorize, so a
wiring-time check would be checking a value that changes later.
**Two limits, stated rather than engineered away.** A misspelled argument name is inert:
`sentrykit policy validate` reads `.cedar` files and never imports the application, so there is
no signature to cross-check — that would need a different command. And narrowing refines a
proposal rather than replacing one: `NoValidArguments` still fires when *every* supplied
argument was rejected, so a single-argument proposal above the ceiling is refused rather than
narrowed. Both are documented on the policies page.

**A third limit was missing from that list, and was not a limit but a defect.** A ceiling over a
parameter carrying a Python default did not bound the call at all: the rejected or omitted
value left the slot empty and Python filled it from the signature, so `maximum: 10` over
`def search(q, limit=1000)` ran at 1000 — and reported a clean allow when the caller omitted
the argument. The paragraph above claimed the limits were stated rather than engineered away;
this one was neither. ADR-035 closes it.
**Alternatives.** An ad-hoc mini-syntax (`"limit<=100,region in eu|us"`) is already a language:
comparison, membership and alternation operators, and no escaping story. One annotation per
rule (`@sk_arg_limit_maximum("100")`) dies on Cedar's duplicate-annotation-key error the moment
two rules share a prefix. The existing `@obligations` encoding survives only because its
grammar is "split on comma, yield opaque labels" — no operator, no nesting, no
interpretation — and it should be treated as the maximum ad-hoc encoding this project ever
ships. The design rule for the JSON is: **no string in the blob is ever re-interpreted as an
expression.** `{"maximum": "principal.tier_cap"}`, a `$ref`, or a `"when"` key would cross that
line.

---

## ADR-029 — Narrowing reaches the caller through the boundary's recorder; the `_authz` key is a mapping-return convenience
**Decision.** `last_envelope()` and the boundary's `EnvelopeRecorder` are the reporting
channel; the `_authz` key inside a mapping result is a convenience layered on top of it, not
the mechanism. `BaseContextProvider.establish` installs a recorder and `release` closes it, so
every shipped adapter has one. The web providers emit `x-sentrykit-narrowed: true` and
`x-sentrykit-narrowed-arguments: a, b` **only when something was narrowed**. The agent
adapters annotate a result that could not carry the envelope in band — MCP via prefixed `_meta`
keys plus one appended text block, Pydantic-AI via `ToolReturn(return_value=…, content=…,
metadata=…)`. `guidance` is **not** emitted as a response header.

**Why a recorder and not `last_envelope()` alone.** Measured, and it is the whole reason this
exists: a `ContextVar` write propagates *downward* into a copied context and never back *up*. A
sync FastAPI route runs in an AnyIO worker thread holding a copy, so a decision made inside it
leaves `last_envelope()` returning `None` to the middleware that has to write the headers —
while the identical route declared `async` reports fine. ADR-016 already recorded that
asymmetry and concluded "render refusals from the exception"; that answer does not extend to a
*successful* narrowed call, which has no exception to render from. A recorder closes the gap by
being a **mutable object reached through** the context variable rather than a value stored in
it: the worker's copy points at the same instance, so the engine's mutation is visible to the
boundary still holding it. Nothing else in the library needed this, which is why it had not
been noticed.

**Why the recorder accumulates rather than holding the last envelope.** A boundary's question
is not "what was the last decision" but "was anything narrowed while serving this response",
and one request may make several protected calls. `narrowed_arguments` is therefore the union
across the scope in first-seen order. `envelope` still holds the most recent, so the two
readings are both available and neither is inferred from the other.

**Why `_authz` is demoted rather than extended.** It only ever worked for a `MutableMapping`
return, and a web route returning a JSON array is the single most common shape there is. The
three narrowing fields shipped before this change therefore reached no list-returning,
str-returning or model-returning callable at all, which made the measured benefit of adding
them conditional on a detail of the application's return type — an indefensible place for an
authorization report to live. Reversing the hierarchy costs nothing in compatibility (`_authz`
is unchanged where it applied) and makes the documented mechanism the one that always works.

**Why `guidance` is not a header.** It is a sentence of prose, over 300 characters, and its
unsupplied-argument form contains an em dash, which is not spellable in an HTTP field value
without encoding. Headers also cost every byte on every response and are commonly capped
around 4–8 KB in total by servers and proxies. A header should carry a fact a machine acts on;
`narrowed` and `narrowed-arguments` are that, and the prose is available in the body for a
mapping return and from `last_envelope()` for everything else. The cost is accepted and real: a
web caller receiving a list gets the facts and not the sentence, and a host that wants the
sentence in the response has to put it there.

**Why headers only on narrowing.** The same discipline `AuthzEnvelope.as_dict` applies to
`narrowed`: the exceptional outcome is the one worth a line. The cost is that an absent header
cannot be distinguished from "sentrykit is not wired", which is a question nobody asks of a
response they are already parsing — and the alternative is two headers on every ordinary
response forever, paid by every caller, to say that nothing happened.

**Why the agent adapters append rather than substitute.** The failure this change exists to fix
is a reader being told about the exceptions instead of the result. Replacing a tool's content
with a note about it would be that same failure inverted and worse. `ToolReturn`'s additivity
was verified rather than assumed: `return_value` still reaches the model as the
`ToolReturnPart`, and `content` arrives as a separate prompt part. MCP's `_meta` is the spec's
open map and the appended text block is model-visible, because `_meta` is protocol metadata a
client is under no obligation to show anyone.

**Why in-band-ness is a recorded fact, not an inspected shape.** The adapters must not annotate
a result that already carries `_authz`. Inferring that from the serialized result does not work
— mcp populates `structuredContent` only when it has an output schema to validate against, so
the envelope may be in the content text instead — so `attach_envelope` records
`EnvelopeRecorder.last_was_in_band` and the adapters read it. Per-decision rather than
cumulative, because the question is about one return value.

**Why out-of-band did not become the default channel.** The obvious follow-on to demoting
`_authz` is to demote it the rest of the way and annotate every return shape out of band, and
the first two samples of the harness pointed that way — the out-of-band arm served more often
than the in-band one. It does not survive pairing. Across four samples of seven models, pairing
each run by `(sample, model)`, the two differ in **3 of 28 runs, split 2 to 1, exact two-sided
sign test p = 1.000**. There is no measured difference, so the decision above stands on its
merits rather than on a benefit: `_authz` stays where the return type allows it because it costs
nothing and is already where a reader looks, and the out-of-band channel exists because for most
return shapes there is nowhere else to put the facts. The one contrast in that experiment that
*does* reach significance is the one this change was made for — adding the outcome fields to the
exceptions-only envelope, 8 discordant runs all favouring the outcome fields, p = 0.0078. The
harness is `research/snippets/sentrykit/06_ab_narrow_vs_refuse.py`, pooled by `07`; that tree is
deliberately not distributed, so treat the figures here as this project's record of what was
measured rather than as something a reader of the package can re-derive.

**What is still not covered.** A protected callable invoked outside any framework boundary has
no recorder, so `narrowing()` reports nothing and `last_envelope()` remains the only channel —
correct, since there is no response to annotate. And a host writing its own `ContextProvider`
without inheriting `BaseContextProvider` must call `record_decisions()` and `close()` itself;
the docs say so, and nothing enforces it.

## ADR-030 — The envelope reports the outcome of a narrowed call, justified by the one contrast that survives pairing
**Decision.** `AuthzEnvelope` carries `narrowed`, `narrowed_arguments` and `guidance` alongside
`rejected` and `defaults_applied`. The exceptions say what policy would not accept; the outcome
says what happened. `narrowed` is defined against the caller's *proposal* rather than against
`rejected`, and `Plan.narrowing()` is the seam. This ADR exists because the fields shipped
without one: ADR-029 records the *channel* that carries them, and the justification for the
fields themselves lived only in `CHANGELOG.md`.

**Why — the stated justification, and the only one.** A narrowed call succeeded: real data was
returned, on values the principal is entitled to. An envelope naming only what was refused
describes that success in the vocabulary of a failure, and a reader acting on it withholds the
answer it already holds. Adding the three fields to that same payload is **the one contrast in
the harness that survives a paired test**: pairing every run by `(sample, model)` across four
samples of seven models, the exceptions-only envelope and the outcome-carrying envelope differ
in **8 of 28 runs, and all 8 favour the outcome fields — exact two-sided sign test p = 0.0078**.
The same contrast against the out-of-band variant is p = 0.0039. Nothing else about this change
is load-bearing on a measurement.

**Retracted: "the old envelope was worse than no envelope at all."** This is recorded rather
than deleted, because the fault was in the method and the method is the thing worth keeping.
The claim was that stripping the envelope entirely served data more often than the
exceptions-only envelope did — that the field being fixed was not merely incomplete but *net
negative*. Unpaired it looks that way, 64% against 50%. Paired, it is **7 of 10 discordant runs
at p = 0.344**: the right direction, and not a result. It was asserted causally in the same
document that ran a paired test on a neighbouring comparison and declared *that* one refuted at
p = 1.000 — so the test was applied to the hypothesis its author was willing to lose and
withheld from the one that flattered the change. A justification built on it would have rested
on the contrast that did not survive.

**Also retracted: the single-sample figure.** "Four of seven narrowed calls" was one sample of
seven models read as an aggregate. Pooled it is near enough one in two. It had reached the
README, `narrowing_guidance`'s docstring, `CHANGELOG.md` twice and the generated
`llms-full.txt`; `dev-docs/documentation-standards.md` now carries the rule that keeps
unverifiable figures out of shipped text, and names the instance still outstanding.

**What stops it recurring is structural, not anybody's discipline.** The pooling script
`research/snippets/sentrykit/07_rescore_saved_runs.py` now computes and prints **all ten**
pairwise contrasts with their sign tests, every time it runs. Selecting which comparison to
test is no longer possible, because they are all already there — and the four that reach
significance (B→D, B→E, and C against everything) are visible beside the six that do not.

**What this does not establish.** That narrowing is better than refusing *in general* — the
harness is one over-broad request against one tool. That the wording is optimal; `guidance`'s
prose is explicitly not stable API (`dev-docs/api-surface.md`). And nothing about how a human
reader, as opposed to a model, reads an envelope: every run in the corpus is a model.

**Amended 2026-11-07 — the family-wise correction, and the claim against silence.** The
pooling script now computes all ten pairwise contrasts on *both* measures, served and
disclosed, which makes twenty tests over one corpus. Three corrections follow, and the
decision above survives all three on a narrower base than it was first given.

*"The one contrast that survives a paired test" was too strong.* Holm-adjusted across the
twenty, the only survivors are the four arm-vs-**C** contrasts on served data, none of them
near the threshold. **B→D does not clear the correction: raw p = 0.0078, Holm-adjusted 0.117.**
It stands as a *pre-specified primary endpoint* — `06`'s module docstring names "D vs B is the
acceptance test for the envelope change", written before any sample existed — and a
pre-registered primary is read at its raw value rather than corrected for contrasts computed
afterwards. That argument is sound and it is also the whole of what the raw value rests on. It
is not a licence to quote 0.0078 beside the other nineteen rows; quoted there it is an
exploratory result and the adjusted figure is the honest one.

*The case against silent narrowing does not resolve in this corpus, on either measure.* On
served data silence is not measurably worse than the new envelope — A vs D is p = 0.289, A vs
E is p = 0.125. On disclosure the direction is unanimous (across A vs B, A vs D and A vs E,
every one of the 18 discordant pairs favours the arm carrying an envelope, none favours
silence) and still short of significance: A vs D is 5 discordant pairs at p = 0.0625, which is
the *floor* at five pairs, so it could not have reached 0.05; A vs E is p = 0.0156 raw and
0.219 adjusted. Disclosure sits near ceiling in every arm, so only five to seven discordant
pairs exist per contrast and the test cannot resolve below six. Underpowered by construction.
More samples would settle it; more analysis of these will not.

*So the justification for reporting narrowing at all is narrower than a throughput claim.* It
is the pre-registered B→D result against the *exceptions-only* envelope — fixing a report that
was actively misleading — plus first principles, that a caller cannot act on what it is not
told, plus the single run in the corpus that fabricated a table of invented orders rather than
relay a narrowed result. **It is not that the envelope out-performs silence**, on throughput or
on disclosure. Any positioning text that argues otherwise is arguing past the data.

## ADR-031 — A described constraint is masked before the audit write, and bounds are not
**Decision.** `AuditTrail._snapshot` masks the **value-bearing** rules of every described
constraint it writes: each member of `allow`, each member of `deny`, and `pattern`, for every
argument the decision's masking plan names. `minimum`, `maximum`, `policy`, `required` and
`has_default` reach the sink as written. The masking key is the **argument name**, not the rule
name, so a value masked as an argument and the same value masked as an allow-set member produce
the same digest. `PrincipalSnapshot.of()` still does not mask, and now says so.

**Why.** `ConstraintSet.describe()` withholds the default *value* — that was deliberate, and the
reason is in its docstring — and emits the allow-set, the deny-set and the pattern verbatim. So a
principal fenced to two tenant ids under `@obligations("hmac:tenant")` got `proposed.tenant` as a
digest and, two fields away, both tenant ids in the clear, in the same record. The leak was not
one value but the principal's whole authorization surface, including values they never passed, on
every decision, into an append-only sink where an erasure request cannot be honoured. ADR-007 and
ADR-014 both state the opposite, `docs/audit.md` states the opposite, and the field's own
docstring stated the opposite.

**Why the bounds are exempt.** A bound is a rule, not a value. `maximum: 50` is the thing an
auditor came to read, it identifies nobody, and masking it would make the record unreadable for
the question it exists to answer. The distinction is that `allow`, `deny` and `pattern` carry
data drawn from the domain, while a bound carries a policy author's number.

**Why `pattern` is in rather than left out.** A per-principal pattern can embed a literal —
`^TENANT-SECRET-7781$` — so masking the two sets and not the pattern leaves the same hole through
a third door.

**Why the argument name is the masking key.** `hmac` is keyed and deterministic and binds the
field name into the digest, so keying both by the argument preserves set-membership replay
exactly: `record.proposed["account"] in record.principal.constraints[action]["account"]["allow"]`
still answers *"was what the caller proposed one of the values they were permitted to pass"*.
That disposes of the one principled argument for leaving an allow-set in the clear, which was
that reproducibility needed it.

**What this does not fix, and it is not small.** Two residual holes, both named rather than
quietly left:

- **A mutation record is still unmasked, by construction.** `record_mutation` builds its plan
  with a bare `masker.plan()`, which is always empty, so an `attribute` grant's raw `value`, the
  actor's own snapshot attributes and the grant's own described constraint all reach the sink in
  the clear. This is not an oversight at that line: a mutation has no determining policies and no
  protected-callable signature, so there is no plan to *derive*. Giving it one means either a new
  parameter on `record_mutation` supplied by the admin surface, or a way to ask the bundle for
  obligations by action rather than by determining policy. Either is a design change and belongs
  in its own ADR.
- **The boundary is still per-field-name.** A constraint on `customer_id` whose allow-set holds
  account numbers is masked only if `customer_id` itself is in the plan. That is the same limit
  `proposed`, `processed` and `attributes` already have, so this change does not widen it — but a
  value is protected here because of the name it sits under, not because of what it is.

**Also corrected.** The `constraints:` attribute docstring on `PrincipalSnapshot`,
`PrincipalSnapshot.of`'s docstring and the `audit.py` module docstring each asserted a property
the module did not have. The one test that would have caught this —
`tests/unit/test_audit_invariants.py`'s leniently-dropped-argument case — was *vacuous*: its
allow-set member was a placeholder deliberately outside the module's `RAW_VALUES`, so its
whole-record string search never inspected the allow-set, and 132 masking and audit tests passed
over the leak. The placeholder is gone, and a permitted peer value is now a raw constant like any
other.

## ADR-032 — The chain append and the sink write happen together, under one lock
**Decision.** `AuditTrail` holds a `threading.Lock`. `_append` takes it around *both* the chaining
of the record and the `sink.write` that follows, and releases it after advancing `_prev_hash` and
`_sequence`. Every existing behaviour inside that window is unchanged, including
advance-only-on-success. This supersedes the part of ADR-013 that located this guarantee in the
sink; the amendment there records what that ADR got wrong, and the measurements.

**Why both, and not just the reservation.** Holding the lock only long enough to reserve
`(prev_hash, sequence)` and writing outside it is the cheaper shape, and it is wrong twice. Two
threads would then call `write()` in an order that need not match the order their links describe,
so the file's sequence of records and the chain's sequence of records could disagree. And
advance-only-on-success depends on a failure being observed before the next reservation, which a
released lock does not provide.

**What it costs, stated rather than discovered.** Audit writes are now fully serialized per trail.
For the in-memory sink and for `jsonl://` that is no change in kind — the JSONL sink already
serialized its own writes — but with `jsonl://path?fsync=true` the per-record durability call
becomes a process-wide serialization point on every authorization decision. ADR-013 measured that
call; this ADR is what makes it everybody's. An operator who needs both per-record fsync and
concurrency wants a sink per writer, which ADR-013 already prescribes, or a sink that batches.

**What this does not establish.** Anything about processes. Two processes sharing one file still
corrupt the chain, still silently, and that is a separate unfixed finding. This lock makes one
process correct, which is the deployment shape every shipped example and every documented wiring
actually has.

**The test is probabilistic, and says so.** The regression test races eight threads through the
public governor path. Against the unfixed code it detected the break in 13 of 14 runs, and smaller
shapes were materially worse, so the shape was kept rather than shrunk. It cannot flake *red*
against correct code: with the lock, a linking chain and non-repeating sequence numbers are
invariant rather than likely.

## ADR-033 — A deny-set is read element-wise; the rest of the vocabulary is scalar-only
**Decision.** `ArgumentConstraint.check` matches a `deny` member against the value and,
recursively, against the elements of any container that is not `str` or `bytes` — a `Mapping`'s
values *and* its keys included. `str` and `bytes` are leaves. Nesting deeper than a fixed limit,
or a self-referential structure, is **rejected unsearched**. `allow`, `pattern`, `minimum` and
`maximum` continue to judge the whole value and continue to refuse a container, as they already
did. A NaN is `not-comparable` against a bound.

**Why deny had to change.** `deny` was the only rule whose "no match" outcome is *keep*, and it
had no not-comparable guard where `pattern` and the two bounds each have one. A container never
equals a scalar member, so `deny=('prod',)` admitted `['prod']`, `['dev','prod']`, `('prod',)`,
`{'prod'}` and `{'env':'prod'}` while correctly refusing the bare string. Wrapping a forbidden
value in a one-element list defeated the rule — and `list[str]` is exactly the shape an LLM sends.
The envelope then recorded `rejected=[]`, so the audit trail showed a clean allow with nothing to
replay, and a `default` carrying a denied element passed the grant-write check and was injected
later. That last part needed no separate fix: `inconsistencies()` reaches the same `check`, so the
write-time guard inherited the walk.

**Why the asymmetry is the decision and not a leftover.** Denial is the fail-closed direction, so
reading it element-wise can only ever refuse more. Permission element-wise would *widen*: it would
have to decide whether `allow=('eu','uk')` admits `['eu','uk']`, `['eu']` or `[]`, and what
`minimum` means for a list — questions whose wrong answer grants something nobody granted. So the
vocabulary is deliberately half element-wise and half whole-value, and the half that refuses is
the element-wise one. Someone who reaches for `allow`, `pattern` or a bound on a container learns
immediately, through a loud refusal; the one who reached for `deny` used to get silence.

**Why the depth limit rejects rather than raises.** `filter` promises not to raise, and a proposal
is caller input. A structure too deep to read is a structure that cannot be shown to satisfy the
rule, which is a rejection.

**Why NaN moved with it.** Widening a numeric bound to accept `Decimal` makes a proposed
`Decimal("NaN")` *raise* `decimal.InvalidOperation` from the ordering comparison, which would
break `filter`'s no-raise promise — and a signalling NaN raises from `!=` as well, so it has to be
recognised rather than compared. Excluding `float('nan')` on the same terms closes a pre-existing
fail-open nobody had filed: `maximum=1000` *kept* `float('nan')`, because `nan > 1000` is `False`.
Infinities are untouched; they are ordered, so `Decimal("Infinity")` is rejected by the bound
rather than as not-comparable.

**Related, and deliberately separate: a bound now accepts `Decimal` and any `numbers.Real`.**
`_as_number` admitted `int` and `float` only, so `def issue_refund(amount: Decimal)` under
`maximum=1000` refused **every** value as not-comparable — the desk limit in this project's own
canonical example was unusable, and the value then fell through to the callable's signature
default. The *bound* stays `int | float`: widening the field would put a `Decimal` into
`ConstraintSet.describe()`, which flows into `NoValidArguments(allowed=…)` and from there into a
framework JSON error body, where `json.dumps` raises on it. `Decimal` compares exactly against
`int` and `float`, so nothing needed the field to widen. Note for anyone extending this —
`Decimal` is registered as a `numbers.Number` but **not** a `numbers.Real`, so it has to be named
explicitly, and a `numbers.Real` branch alone does not catch it.

**What this does not establish.** That container-valued arguments are *supported*. There is still
no way to express "every element must be in this set", and the breadth of the deny walk is
uncapped, so one very large collection is walked in full. Both are design work, not guards.

## ADR-034 — A record the sink refused is admitted by the next record that lands, and by the report
**Decision.** `AuditTrail` counts the records a sink refused, and `AuthzAuditRecord` carries that
count as `dropped_since_last_write` on the next record that does land. The count is set inside
`chained()`, so it is inside `record_hash` and cannot be stripped without breaking it, and it is
reset only on a successful write, so no loss is reported twice. `payload()` **omits the key when
it is zero**, so a record with nothing to admit hashes exactly as it did before this field
existed. Separately, `SentrykitError.audit_failure` carries the sink failure out on the refusal
itself, and `audit-report` sums the counts into `records_lost` and refuses to call such a window
intact.

**Why a lost refusal was the worst case.** `_audit_decision` lets `AuditUnavailable` propagate,
so under `fail_mode="closed"` an unprovable *allow* is refused before the side effect — correct,
and the record is attempted before the call, which is the right order. `_audit_refusal` swallows
it, which is also correct: the call is already being refused, and raising would replace the
precise `AuthzDenied` the caller needs with an operational error. The defect was that the fact
then went nowhere an auditor could reach. Measured with a full-disk sink: three records
attempted, none landed, both refusals proceeded normally. So with the sink down, a caller can
enumerate the policy boundary — which actions exist, which argument values are accepted, whose
grants cover what — and the reconnaissance is exactly the phase not recorded.

**Why the next record has to say so.** `_append` advances `_prev_hash` and `_sequence` only on
success, which is the right rule and is what makes the gap *invisible*: the records that survive
an outage are perfectly contiguous, so `verify_chain` returns `ok=True` across it. An integrity
check that reads clean over a hole is worse than no check, because the operator concludes
something false from it. The only place that can carry the admission is a record that landed,
and the only channel that counts as evidence is the record itself — `audit.py` says plainly that
the operational log is not the audit trail, so a fact that lives only in an ERROR line is a fact
nobody can prove afterwards.

**Why the key is omitted when zero, which is not a micro-optimisation.** `payload()` is the
canonical pre-image of `record_hash`. A new field with a default would have added
`"dropped_since_last_write": 0` to the pre-image of *every* record, so every record already
written would have re-hashed differently and re-verification of a deployed log would have failed
wholesale — the field meant to improve the integrity story would have destroyed it. Verified
against the previous implementation rather than reasoned about: a zero-drop record's
`record_hash` is byte-identical to the hash the old code computed for the same record, an
existing JSONL log reads back and verifies unchanged, and a lossy record is still tamper-evident
in both directions — forging the count up or down breaks its own hash.

**The forward direction does not survive, and that is inherent.** `AuthzAuditRecord` is
`extra="forbid"`, so a record written with a non-zero count cannot be read by an older install.
A mixed-version fleet reading one file upgrades its readers first. There is no way to add a
field to this model without that, and pretending otherwise by making the model lenient would
give up the thing `extra="forbid"` is there for.

**Why `audit_failure` is not the whole fix, and this corrects an earlier assumption.** Attaching
the sink failure to the error covers `fail_mode="closed"` only. Under `fail_mode="open"` the
trail absorbs the failure and returns normally, so nothing reaches the engine to attach — which
is what the counter is for. The two halves are complementary by fail mode rather than redundant:
one tells the caller's own boundary that this refusal is unrecorded, the other tells a later
auditor that something was.

**What this does not close.** A process that dies while its sink is down takes its unreported
count with it; nothing on the sink side can be probed for a record that never reached it, so
`_resume` has nothing to recover and does not try. This narrows the window in which a loss is
invisible; it does not eliminate it. A spool — writing the already-masked, already-chained record
to a local file when the primary refuses, and replaying on recovery — is what would, and it is
cheap precisely because the record is already masked and chained. That is separate work.

## ADR-035 — The callable's own default answers to the constraint that governs its parameter
**Decision.** When the resolved constraint set governs a parameter that has no value in the
final argument mapping — nothing the caller proposed survived, and no policy default applied —
the callable's **signature default** is checked against that constraint. A default that
satisfies it is left to Python exactly as before and the parameter is named in a new
`signature_defaults` tuple, carried on `Plan`, on `AuthzEnvelope` and on `AuthzAuditRecord`.
One that does not satisfy it refuses the call with `SignatureDefaultRejected`, audit outcome
`signature-default-rejected`. Nothing is added to the argument mapping, so what sentrykit
*passes* is unchanged and `processed` still means what it meant.

**Why this is ADR-027's rule and not a new one.** ADR-027 already decided that a default is
checked against the constraint that governs it, so that *omitting* an argument is not a way
around the rule on it. That held for policy defaults only. The pipeline is
filter → inject_defaults → validate → split → `fn(*positional, **keyword)`, and both
`validate` and `split` emit only the keys they were given — so a governed parameter with no
value is simply absent, and Python fills the slot from the signature. A signature default is a
default from the other source. It now answers to the same check.

**The failure it closes, in the two shapes that make it serious.** A ceiling of
`limit: {maximum: 10}` over `def search(q, limit=1000)`: a caller proposing `limit=500` had
their value rejected and the body ran at **1000** — strictly *more* than they asked for, so
narrow-and-continue inverted into widen-and-continue. And a caller who *omitted* `limit` got a
**clean allow with no rejections** in both the envelope and the record, while the body ran at
1000 against a declared maximum of 10. The second is the one that matters most: the reviewed
`.cedar` file is the artifact a change-control process signs off on, and it was stating a bound
the system did not enforce, silently. The sharper spelling is
`target: {deny: ["prod"]}` over `def wipe(target="prod")`, which wiped prod both when proposed
and when omitted. Not ceiling-specific — a plain grant behaved identically — and a correctly
*withheld* policy default, ADR-027's own backstop firing, landed in the same hole.

**Why a refusal rather than a warning, and why the behaviour break is acceptable.** The
population it breaks is exactly the population at risk: a deployment where a governed
parameter carries a Python default its own constraint refuses was already running outside its
policy, and the alternative to refusing is continuing to do so quietly. A deployment whose
signature defaults satisfy their constraints is unaffected — measured, not assumed: of 1494
tests, the only ones that changed behaviour were two fixtures that had been relying on the
hole, and they now exercise reject-and-refill instead.

**Why ceilings are checked separately from grants.** `SignatureDefaultRejected` carries
`declared`. True means the refusing rule came from an argument ceiling: reviewed,
version-controlled policy text, so the fault is a disagreement between an operator's policy
file and their own code, it affects every caller of the action equally, and the message says
so. False means a per-principal grant, which is mutable data and ordinary authorization. The
engine already filters layer by layer so a rejection keeps the id of whatever produced it; this
reuses that, checking the ceilings first and on their own.

**Why it is not a `ConfigurationError` even when declared.** Two reasons, and the second is the
binding one. It refuses one call rather than failing the wiring — and there is no moment at
which it *could* fail the wiring instead, because nothing enumerates protected callables for a
policy load to check against. `@protect` caches its spec on the wrapper it returns and no
registry collects them, so `install()` has no set of signatures to read. A load-time check is
the better shape and it needs a registry first, which is its own design with its own
import-order hazards. Classifying this with configuration faults would also make it
unqueryable in the trail, where it has an outcome of its own.

**Why the check runs last.** After `missing_required`, so a call that some other rule already
refuses keeps the error it has always raised. A policy-`required` argument with no usable value
is still `DefaultUnavailable`. The new error fires only where nothing else would have refused
at all, which is what makes the change additive rather than a reclassification.

**Why `signature_defaults` is names-only and separate from `processed`.** The value is the
application's own literal, so the name is the part an auditor needs and carrying the value
would raise a masking question for no gain. Keeping it out of `processed` preserves the
distinction `defaults_applied` exists to make: policy-supplied and application-supplied values
are different facts, and a field that blurred them would answer neither question. It is present
at every verbosity, because the defect being fixed is that this case was *invisible*.

**Rejected: the documentation-only option.** `docs/web-frameworks.md` already carried the
design rule — a policy-decided parameter should carry no Python default — as a style tip inside
a worked example, and `SECURITY.md` asserted the opposite property three times in "what
sentrykit defends". Writing the hazard down more loudly was available and is not sufficient,
because the claim a ceiling makes is the product: a reviewed file that says what anybody may
pass has to mean it. The documentation is corrected as well, and those three claims are now
true rather than aspirational.

**Corrected in the same pass, from the same finding's neighbourhood.** `processed` was
documented in several places as "what the callable actually ran with", which was never quite
true for a parameter the signature filled and is now precisely wrong. It is the set the policy
decided and passed; the wording says that, and `signature_defaults` carries the rest.

**What this does not establish.** That a ceiling is checkable before the first call — see
above. That a misspelled ceiling argument is detected: a ceiling naming a parameter the
callable does not have still parses, loads and bounds nothing, which `SECURITY.md` names as a
limit and which `policy validate` cannot see, because it never imports the application. And
nothing here changes the arity rule: a single proposed argument that is rejected still refuses
with `NoValidArguments` before this check is reached.

**Reconsidered and deliberately not changed: `ConstraintSet.missing_required` still ignores the
signature.** The research pass recommended filtering it by the callable's parameters, as
`inject_defaults` does, on the grounds that the protection was "half-applied" — one transposed
character in a reviewed ceiling, `limti` for `limit`, refuses every call to the action and
names an argument that cannot exist. The two filters guard different things. `inject_defaults`
filters so that a stale grant cannot make a call fail with an unexpected keyword argument; a
`required` rule naming a parameter that does not exist can never be satisfied, and refusing is
the fail-closed answer. Dropping it would mean a rule the operator wrote silently did not
apply, which is the same class of fault as this ADR closes. The repo already had a reasoned
test pinning the refusal, which the finding recorded as absent. What was genuinely missing was
the *diagnosis*: the refusal now logs an error naming the parameter the callable does not
accept, so the operator reads their actual mistake rather than inferring it.

## ADR-036 — A state handle carries no authority; the host re-expresses its narrowing as arguments
**Decision.** sentrykit does not track, sign or scope the identifiers a protected callable
hands back. A call that was narrowed to `region="eu"` may return an export id, a job handle, a
cursor or a row key, and a later call presenting that identifier is decided **only** on the
principal and the arguments of *that* call. Where the narrowing of the first call has to bind
the second, the host resolves the handle before the gate and passes what it resolved to as an
ordinary argument, which the principal's own constraints then decide. The obligation is named
rather than discharged, and the audit trail is what makes it checkable: both calls carry the
same action and principal vocabulary, so a report can ask whether the second call's arguments
agree with the first call's decision.

**Why this is not a gap we are deferring.** It is the consequence of what a pre-action
authorization decision *is*. The decision is a function of the principal, the action, the
resource and the proposed arguments. A handle is a string the application minted; sentrykit
cannot know whether `exp-0004` names an export, a tenant, a file or nothing, cannot know which
of a host's identifier spaces is capability-bearing, and has no session in which to remember
what the call that minted it was narrowed to. Making it know any of that means owning a store
of issued handles keyed by decision, which is a different product: a capability service.

**What the alternative would cost, concretely.** Three things we are not taking on. A durable
map from handle to decision, which has to outlive the process and be replicated wherever the
next call might land — so the "no infrastructure, one decorator" claim stops being true. A
vocabulary for the host to declare *which* return values are handles and which of their fields
are scoping, which is a schema for every application's identifier space. And a failure mode
worse than the one it closes: a handle the map has forgotten is either refused, breaking calls
that were legitimate, or allowed, which is the behaviour we started with plus a store.

**Why the host's half is one line and not a workaround.** `fetch(job_id)` becomes
`fetch(job_id, region=lookup(job_id).region)`. The narrowing moves from a row the policy cannot
read into an argument it decides, and from there everything already built applies unchanged:
the allow-set refuses it, a ceiling can bound it, a default can refill it, the envelope reports
it and the record pins it. Nothing new is needed because the problem was never that the
mechanism was missing — it was that the fact had not been put where the mechanism could see
it. A narrowing that is not in the request cannot be enforced by anything that only sees the
request, and that is a property of gates rather than of this one.

**What we still owe the reader, and where it is paid.** An unanswered hazard that the
documentation does not name is worse than one it does, because the shape of the API invites the
mistake: a function that returns a handle looks like it is handing out something safe.
`examples/scenarios/` runs the sequence as three scenarios — the handle presented bare, the
handle re-expressed, and the handle re-expressed *wrongly* — and the first of those is a
scenario the governed arm does not win. `docs/scenarios.md` and `SECURITY.md` say it in prose.

**The third scenario is the one that generalises.** A caller who presents a valid handle
together with a region they *are* entitled to is allowed by policy and must still be served
nothing, because the handle and the argument disagree. sentrykit answered the question it was
asked, and whether this job is that caller's job was never put to it. So the host's obligation
is two-part: put the narrowing in the request, and check in the body that the request and the
row agree. Only the first part is authorization.

**Rejected: a `handle=` constraint rule.** A rule shape that said "this argument is a handle,
resolve it with this callable" was considered and is the worst of the options: it puts I/O
inside the argument filter, which is a pure function today and is on the path of every call; it
makes a decision depend on a database the audit record cannot pin a hash of; and it hands the
grant store a callable reference, which is data an admin surface would then be mutating into
executable behaviour. Policies-as-code, grants-as-data draws the line the other way round.
