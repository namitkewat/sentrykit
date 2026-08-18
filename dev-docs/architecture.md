# Architecture

## 1. One idea: a pure core, and thin providers around it

sentrykit is a small decision core wrapped by swappable adapters. The core operates on a
**normalized invocation** and knows nothing about how it was produced:

- `principal` — who is acting (from web auth, or the human an agent acts for)
- `action` — what operation (derived from the protected callable, or explicit)
- `resource` — on what (explicit or derived)
- `args` — the *proposed* arguments (from the call site or the LLM's tool call)
- `environment` — `now`, `channel` (`http|agent|internal`), request id, auth strength,
  delegation chain, break-the-glass flag

The `@protect` decorator supplies `action` + `args` (from the callable). A **context
provider** supplies `principal` + `environment` (from the framework). This split is why the
same decorator guards a Flask view, a background function, and a FastMCP tool unchanged.

```
your app / agent ──► @protect (action, args) ──► Governor ──► Cedar decision
   context provider ─────────────────────────────┘             │
   (principal, env)                                             ▼
                                       filter args ─► inject defaults ─► pydantic validate
                                                             │
                                              invoke callable ─► response envelope
                                                             │
                                                    AuthzSink (append-only, masked)
```

## 2. The request lifecycle inside the Governor

1. Resolve `principal` (ambient or explicit), `resource`, and build `environment`.
2. **Coarse gate** — Cedar `is_authorized`. Deny ⇒ `AuthzDenied` carrying the determining
   policies. Cedar is a boolean engine; enforcement is ours.
3. **Argument constraints** — resolve per-(principal, action) rules (allow-set / deny-set /
   pattern / range / default) from entity attributes; **filter** into kept vs rejected.
4. **Defaults** — inject per-principal defaults for omitted (or dropped) args.
5. Edge cases: all supplied args invalid ⇒ `NoValidArguments` (report the allowed set);
   nothing supplied ⇒ run on defaults; missing required default ⇒ `DefaultUnavailable`.
6. **Validate** the final dict against the callable's pydantic model; `ValidationFailed`
   surfaces the structured field errors.
7. **Invoke**; wrap the result in the `_authz` envelope; emit one audit record.

`arg_handling` (`lenient` drops invalid / `strict` hard-fails) and `fail_mode`
(`closed`/`open`) are global config with per-action override.

## 3. Ambient context for arbitrary callables

A protected callable rarely receives the principal as an argument. sentrykit uses
`contextvars.ContextVar`: the provider calls `establish(principal, **env)` at the boundary;
the decorator reads it wherever the function lives. Rules:

- Explicit `_as=` on the call beats ambient.
- No ambient principal ⇒ **deny** (fail closed).
- `ContextVar` propagates across `await` automatically, and across `asyncio.to_thread`, but
  **not** across a bare `ThreadPoolExecutor.submit` / `run_in_executor` — those need
  `contextvars.copy_context()`. sentrykit ships a `copy_context`-aware helper for offload.

## 4. Three stores (never one)

- **PolicySource** — Cedar policies + templates + schema. Authored and reviewed in **git**;
  distributed at runtime from a **versioned S3 prefix** (or filesystem for local). Read-
  mostly. Multiple sources compose by **union** (namespaced ids, provenance per policy).
- **GrantStore / EntityStore** — principals, roles, group edges, per-user argument
  constraints, grant expiries. **Mutable**; the admin surface's only write target. Multiple
  stores **merge by precedence** or **route by namespace**.
- **AuditSink** — the decision + admin-mutation log. **Append-only / tamper-evident**.
  Multiple sinks **fan out** (`primary-durable` or `all-or-nothing`).

All three are `Protocol`s with reference implementations; backends are addressed by DSN and
discovered via entry points.

## 5. Policies-as-code, grants-as-data

Cedar cleanly separates *policies* (logic) from *entities* (data). We exploit that:

- Policy **logic** lives in files, changes via review — git history is change-control
  evidence.
- **Grants** are entities: a role is a parent edge (`User in Role`), a constraint is an
  attribute, a time-boxed grant is an attribute + a `context.now` condition (or a
  template-linked policy). "Add role" = CRUD on the entity store; reviewed policy logic never
  changes at runtime.

The admin surface is therefore just governed CRUD over the grant store — and because
`Action::"grant_role"` is an ordinary Cedar action, the admin surface is **self-governed**
(authorized by the same engine) and **self-logged** (into the same sink).

## 6. Audit pipeline

One `AuthzAuditRecord` per decision (and per admin mutation): a snapshot of the principal's
*effective* attributes at decision time, `proposed/processed/rejected` args, defaults,
obligations discharged, the `policy_set_hash` (so a decision replays deterministically),
per-policy **provenance** (git commit / S3 version / store id), and a `prev_hash`/`record_hash`
chain for tamper-evidence. Sensitive values are **masked before the write** (redact /
partial / HMAC / tokenize); reversible token maps stay out of the immutable store. Iceberg-
on-S3 or S3 Object Lock are the durable backends; a period query over the sink *is* the
yearly audit report.

## 7. Plugin model (uniform across the whole library)

Stores, sinks, policy sources, and framework context providers all use the same mechanism:
a `Protocol` contract, a name/DSN registry, an in-process `register_*` decorator, and
`importlib.metadata` **entry points** (`sentrykit.policy_sources`, `sentrykit.grant_stores`,
`sentrykit.audit_sinks`, `sentrykit.context_providers`) so a third-party `sentrykit-<x>`
package self-registers on install. Multiplicity is a **composite** that satisfies the same
Protocol, so the core always talks to exactly one instance. Adding a framework and adding an
audit sink are the same shape of task, and the core never imports either.

## 8. Positioning

sentrykit is **action-layer / pre-action authorization**: it refuses the side effect before
it happens, unlike output validators that run after the model finishes. Its niche is the
combination — self-hosted pip library, framework-agnostic across web *and* agents, Cedar-
based, audit-first, one decorator. The defining value is **relationship resolution offloaded
to policy**: multi-hop, nested authorization relationships are resolved deterministically by
Cedar's entity hierarchy and policy evaluation, never inferred by a model.
