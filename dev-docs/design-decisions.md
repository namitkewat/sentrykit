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
**Alternatives.** An ad-hoc mini-syntax (`"limit<=100,region in eu|us"`) is already a language:
comparison, membership and alternation operators, and no escaping story. One annotation per
rule (`@sk_arg_limit_maximum("100")`) dies on Cedar's duplicate-annotation-key error the moment
two rules share a prefix. The existing `@obligations` encoding survives only because its
grammar is "split on comma, yield opaque labels" — no operator, no nesting, no
interpretation — and it should be treated as the maximum ad-hoc encoding this project ever
ships. The design rule for the JSON is: **no string in the blob is ever re-interpreted as an
expression.** `{"maximum": "principal.tier_cap"}`, a `$ref`, or a `"when"` key would cross that
line.
