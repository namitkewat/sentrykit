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
**Why.** `cedarpy` wraps Cedar's stable API and does not expose partial evaluation. Attribute-
driven filtering works today and is maintainable.
**Future.** True residual-derived filtering (type-aware partial evaluation) is the elegant
path and can come via a dedicated maturin binding that enables the `tpe`/`partial-eval`
features. Formal policy *validation/analysis* may likewise require the Cedar CLI or Rust
side — verify what the installed `cedarpy` exposes before promising formal guarantees.

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
**Why.** Reproducible multi-extra dev environments and a clean, standard package. Confirm the
current pixi manifest schema against the installed pixi version in Phase 1.

## ADR-011 — Commit messages carry no tooling attribution
**Decision.** Conventional Commits, enforced by `scripts/check_commit_msg.py` as a
`commit-msg` hook; no references to AI assistants/models or "generated with/by" trailers.
**Why.** Project requirement; enforced mechanically so it cannot be forgotten.
