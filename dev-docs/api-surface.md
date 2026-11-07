# The public API surface

Every name exported from `sentrykit`, `sentrykit.policy`, `sentrykit.stores` and
`sentrykit.cli`, with a verdict. This exists because "the public API" is what the version
number makes a promise about (`packaging-standards.md`: pre-1.0, SemVer, breaking changes go in
`CHANGELOG.md`) — and a promise nobody has written down is a promise nobody can keep.

All four modules declare `__all__`, so the surface is explicit rather than accidental. What
follows is an audit of whether each name *should* be in it.

**Public** — a name a user is expected to import and use, or to name in a type annotation.
Removing or changing it is a breaking change.
**Internal** — reachable, but not part of the promise.

Usage counts below are references across `tests/`, `examples/`, `docs/` and `README.md`
(external to `src/`), measured over the tree. They are evidence, not the verdict: a return type
that nobody spells is still public, because the function that returns it is.

---

## `sentrykit` — the top-level surface (77 names)

This is the import people write. Everything in it is **public**.

### The decorator and the pipeline

| name | verdict | why |
| --- | --- | --- |
| `protect` | public | The decorator. The library's entire premise is one of these. |
| `is_protected` | public | Ask whether a callable is guarded — the check an integration makes before wrapping. |
| `protected_meta` | public | Read back what `@protect` recorded; how the tool-manifest filter learns a tool's action. |
| `ProtectedMeta` | public | The type `protected_meta` returns. Unnameable if withdrawn, in a library that ships `py.typed`. |
| `Governor` | public | The pipeline itself. Constructed directly whenever a caller wants more than one. |
| `install` | public | The one-call wiring most applications use. |
| `get_governor` / `current_governor` / `set_governor` / `use_governor` | public | Process-default lifecycle: fetch, peek, replace, scope. Tests and multi-tenant hosts need all four. |
| `Plan` | public | A decided-but-not-performed invocation — the seam for anyone who wants the decision without the call. |
| `ArgumentSpec` | public | How the engine describes a protected callable's arguments; part of the `Governor` signature. |

### Context

| name | verdict | why |
| --- | --- | --- |
| `Principal` | public | Who is acting. Every provider constructs one. |
| `establish` / `principal_context` / `clear_context` | public | The provider boundary: establish on the way in, release on the way out. |
| `ContextScope` | public | What `establish` returns, so a provider can hold and close it. |
| `current_principal` / `current_environment` | public | Read ambient state without asserting it exists. |
| `require_principal` | public | Read it and fail closed if absent — the deny-by-default read. |
| `bind_context` | public | The `copy_context`-aware offload helper; ambient context does not cross a bare `ThreadPoolExecutor.submit` without it. |
| `Invocation` | public | The normalized call the core operates on, independent of how it arrived. |

### Cedar

| name | verdict | why |
| --- | --- | --- |
| `PolicyEngine` | public | A parsed, reusable policy set plus its base entity graph. |
| `CedarRequest` / `CedarDecision` | public | One authorization question and its normalized answer; what a custom engine wrapper speaks. |
| `Entity` / `EntityRef` | public | The entity graph is data the caller supplies. The two most-used names in the whole surface after `protect`. |

### Constraints

| name | verdict | why |
| --- | --- | --- |
| `ArgumentConstraint` | public | One argument's rules: allow-set, pattern, range, default. |
| `ConstraintSet` | public | Every constraint for one principal and action. |
| `FilterResult` | public | What `ConstraintSet.filter` decided. Return type of a public method; not spelled elsewhere in-repo, which is expected for a result object. |
| `RejectedArgument` | public | One argument the policy refused, and why — carried on the error a caller catches. |

### Configuration

| name | verdict | why |
| --- | --- | --- |
| `Settings` | public | Process-wide configuration, as a model. |
| `configure` / `get_settings` / `reset_settings` | public | Set, read, reset. `reset_settings` matters most to tests, which is a real audience. |
| `override_action` / `settings_for` / `clear_action_overrides` | public | Per-action override of `arg_handling` and `fail_mode`, and the resolver that applies it. |

### Errors

| name | verdict | why |
| --- | --- | --- |
| `SentrykitError` | public | The base to catch when you want all of them. |
| `AuthzDenied` | public | The gate refused. The single most-caught name in the library. |
| `ArgumentRejected` | public | Strict mode: a supplied argument violated its constraint. |
| `NoValidArguments` | public | Every supplied argument was rejected — distinct from a denial, and reported differently. |
| `DefaultUnavailable` | public | A required argument was dropped and policy supplies no default. |
| `ValidationFailed` | public | The final argument dict failed the callable's pydantic model. |
| `NoContext` | public | No resolvable principal. The fail-closed refusal. |
| `ReservedKey` | public | Supplied data spelled one of Cedar's reserved `__` escape keys. Distinct from `AuthzDenied` because it is not a policy verdict — the request was refused before the policy set was consulted. |
| `AuditUnavailable` | public | The sink refused a write on an allow path, so the call is refused. |
| `ConfigurationError` | public | Misconfiguration: bad DSN, missing backend, unusable settings. |

Six of these are one exception each for the six refusal outcomes the audit trail classifies.
Collapsing any of them would make a caller re-parse a message to learn something the type
already says.

### Envelope and audit

| name | verdict | why |
| --- | --- | --- |
| `AuthzEnvelope` | public | The caller-facing `_authz` report attached to a result. Carries the *exceptions* (`rejected`, `defaults_applied`) and, since the narrowing-outcome change, the *outcome* (`narrowed`, `narrowed_arguments`, `guidance`). |
| `last_envelope` | public | Read the envelope for the most recent decision in this context. |
| `narrowing_guidance` — in `sentrykit.envelope`, not re-exported | public in effect, **wording not stable** | Composes `AuthzEnvelope.guidance`. Named and exported rather than underscored because a host rendering its own response may want the same sentence, and because the behaviour it encodes is measured rather than assumed — `research/snippets/sentrykit/06_ab_narrow_vs_refuse.py` is its acceptance test. Deliberately **not** lifted into the package namespace: the function is contract, the exact prose is not, and tuning the prose against that harness must not be a breaking change. |
| `AuditTrail` | public | The only object that writes to a sink, and the one that masks on the way in. |
| `AuthzAuditRecord` | public | One record. Anyone writing a sink deserializes these. |
| `verify_chain` / `ChainVerdict` | public | Tamper detection, and its result. `SECURITY.md` names `verify_chain` as the integrity check. |
| `Masker` | public | Applies the masking policy for one decision. |
| `Sensitive` | public | Marks a parameter sensitive in the protected callable's signature — the annotation that makes masking happen at all. |

### Stores, registry and policy re-exports

| name | verdict | why |
| --- | --- | --- |
| `PolicySource` / `GrantStore` / `AuditSink` | public | The three Protocols. The extension contract. |
| `PolicyBundle` | public | What a `PolicySource` load produced; a third-party source must return one. |
| `GrantSpec` / `GrantRecord` | public | A grant to make, and a grant as stored. |
| `AuditWindow` | public | The query half of "the report is a query". |
| `build_policy_source` / `build_grant_store` / `build_audit_sink` | public | DSN → backend, including the composite when given several. |
| `register_policy_source` / `register_grant_store` / `register_audit_sink` / `register_context_provider` | public | In-process registration. Four legs of one symmetric contract — see the flags below. |
| `available` | public | List the backend names an install can actually resolve, entry points included. |
| `PackPolicySource` / `LinkedPolicySource` / `load_pack` / `link_template` / `TemplateLink` | public | The shipped pack and template linking, re-exported so the common case is one import. |
| `__version__` | public | Kept in step with the distribution metadata by `[tool.hatch.version]`. |

---

## `sentrykit.policy` (13 names)

| name | verdict | why |
| --- | --- | --- |
| `PackPolicySource` | public | The shipped pack as a `PolicySource`; what `pack://` resolves to. |
| `LinkedPolicySource` | public | Linked templates as a source that composes like any other. |
| `load_pack` | public | Load the pack without going through a DSN. |
| `link_template` / `TemplateLink` | public | Link a template into a concrete policy *and* the grant that records it as revocable data. Both halves are the point. |
| `PATTERNS` | public | The eight shipped patterns, keyed by name (`rbac` … `jit-elevation`). Read by the docs, the CLI and the scenario tests. |
| `PackPattern` | public | One pattern's description: file, purpose, what it declares. |
| `pack_root` / `pack_schema` / `pack_template` | public | Where the pack lives, its schema text, one template's text — everything needed to copy a pattern into your own directory. |
| `PACK_NAME` (`"pack"`) | public | The source name the pack namespaces its policy ids under; a determining-policy id is unreadable without it. |
| `SCHEMA_FILE` (`"pack.cedarschema"`) | public | The schema filename, so a caller can find or override it. |
| `TEMPLATE_SUFFIX` (`".cedartemplate"`) | public | Why templates sit outside the `*.cedar` glob: an unlinked template in a policy set is inert, and a filesystem source that loaded one would carry something that can never permit anything. A host writing its own templates needs this exact suffix. |

---

## `sentrykit.stores` (21 names)

| name | verdict | why |
| --- | --- | --- |
| `PolicySource` / `GrantStore` / `AuditSink` / `ContextProvider` | public | The four Protocols every plugin implements. `ContextProvider` is the framework seam. |
| `SupportsClose` | public | The optional half of a backend's lifecycle — declared so a backend can opt in without inheriting anything. |
| `PolicyBundle` / `PolicyProvenance` | public | A load's result, and where each policy in it came from. Provenance is what pins an audit record to the exact policy text; a third-party source must supply it, so it cannot be internal. |
| `CONSTRAINTS_ANNOTATION` (`constraints`) / `OBLIGATIONS_ANNOTATION` (`obligations`) — in `sentrykit.stores.base`, not re-exported | public in effect | The two annotation keys sentrykit reads out of policy text: an argument ceiling and the obligations a permit carries. A host spells them in Cedar text rather than importing them, which is why they were never lifted into the package namespace — but the *strings* are contract, and the policies page is where they are documented. |
| `GrantSpec` / `GrantRecord` / `GrantKind` | public | A grant to make, a grant as stored, and the four kinds it can be (`role`, `parent`, `attribute`, `constraint`). `GrantKind` appears in `GrantSpec`'s public signature. |
| `AuditWindow` | public | The period filter a sink reads back through. |
| `FilesystemPolicySource` | public | `file://` — the reference policy source. |
| `InMemoryGrantStore` / `JsonFileGrantStore` | public | `memory://` and `jsonfile://`. The CLI needs a store that survives a process exit, which is why the second one exists. |
| `InMemoryAuditSink` / `JsonlAuditSink` / `NullAuditSink` | public | `memory://`, `jsonl://`, and the discard sink that is the default when none is configured. |
| `InMemoryTokenVault` | public | The reversible mapping behind `tokenize` masking — deliberately a separate object, because a reversible map must not live in the immutable audit store. |
| `CompositePolicySource` / `CompositeGrantStore` / `CompositeAuditSink` | public | Multiplicity. Each satisfies the same Protocol, so the core still talks to exactly one instance. |

---

## `sentrykit.cli` (8 names)

The console script is the product here; the module's exports are the parts worth reaching for
programmatically.

| name | verdict | why |
| --- | --- | --- |
| `main` | public | The `sentrykit` entry point. Also the honest way to test the CLI: drive the real argv path. |
| `build_parser` | public | The parser, separately, so `--help` output and flag requirements can be asserted without executing a command. |
| `build_report` / `AuditReport` / `render_markdown` | public | Aggregate a window into a report, and render it. Exposed because the yearly audit report is a query someone will want to run from their own code rather than through the CLI. `AuditReport` is unspelled outside `src/` only because callers name the function, not its return type. |
| `GRANT_ACTION` (`Action::"admin.grant"`) / `REVOKE_ACTION` (`Action::"admin.revoke"`) / `ADMIN_RESOURCE` (`Resource::"admin.grants"`) | public | The admin surface is self-governed, and the shipped pack deliberately contains **no permit for it** — so a host must author that policy, and these three strings are exactly what that policy has to name. They are the contract, not implementation detail. |

---

## Findings

### Nothing is withdrawn

Nine exported names have zero references outside `src/`: `AuditReport`, `FilterResult`,
`GRANT_ACTION`, `GrantKind`, `PolicyProvenance`, `ProtectedMeta`, `REVOKE_ACTION`,
`TEMPLATE_SUFFIX`, `register_policy_source`. Each was examined, and none should be underscored
or removed:

- `AuditReport`, `FilterResult`, `ProtectedMeta` are **return types of heavily used public
  functions** (`build_report` — 48 external references, `ConstraintSet.filter`,
  `protected_meta` — 8). Withdrawing them would leave a `py.typed` library whose functions
  return unnameable objects. Low in-repo usage is the normal signature of a result type.
- `GrantKind` and `PolicyProvenance` **appear in public signatures** (`GrantSpec.kind`,
  `PolicyBundle`). A third-party `PolicySource` cannot be written without naming
  `PolicyProvenance`.
- `GRANT_ACTION`, `REVOKE_ACTION` and `TEMPLATE_SUFFIX` are **contract constants for work the
  library deliberately leaves to the host** — writing the admin permit the pack omits, and
  authoring templates outside the `*.cedar` glob. Their in-repo usage is low precisely because
  the repo is not the host.
- `register_policy_source` is **one leg of a four-way symmetric contract**. Its three siblings
  are used; breaking the symmetry would make the plugin model teach a rule with an exception.

### Flags

Two of the three gaps recorded here have since been closed; neither needed a behaviour change.

1. ~~**`register_policy_source` has no test and no documented example.**~~ **Closed.**
   `tests/unit/test_registry.py` now registers a policy source in-process and drives its DSN
   through to a loaded bundle, mirroring the audit-sink test beside it, and `docs/plugins.md`
   shows the same registration with the three members a source owes: `name`, `load()` and
   `current_hash()`. It was the one registration decorator nothing exercised — and the kind a
   host is most likely to add, which is why it went to the front of the queue.
2. ~~**`GRANT_ACTION` / `REVOKE_ACTION` / `ADMIN_RESOURCE` are undocumented in `docs/`.**~~
   **Closed.** `docs/policies.md` tabulates all three with their exact values next to the
   worked permit, states that they are importable from `sentrykit.cli`, and says which part of
   the permit is a host's choice and which part is fixed. A doc-example test pins the table to
   the constants and the constants to the permit the page prints, so the three cannot drift
   apart silently — a permit naming anything else authorizes nothing at all.
3. **`sentrykit.cli` is on the public list but is not re-exported from `sentrykit`.** Still
   open, and deliberately: the CLI should not be imported by an application. It means the
   module's `__all__` is the only statement of its surface. The API reference renders it,
   which is enough; noted so a future loop does not "fix" it by re-exporting.

No entry in the tables above changed. Closing the first two added a test and documentation for
names that were already public, which is what they needed.
