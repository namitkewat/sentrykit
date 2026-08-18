# Phase 1 — research notes

Findings verified against the **actually installed** `default` pixi environment on
2026-08-18. Everything below was confirmed by running code, not read from documentation.

## 1. Installed versions

| Package | Version |
| --- | --- |
| Python | 3.13.15 (conda-forge) |
| cedarpy | 4.8.7 |
| pydantic | 2.13.4 |
| pydantic-settings | 2.15.0 |
| typing-extensions | 4.16.0 |
| pytest | 9.1.1 |
| pytest-asyncio | 1.4.0 |
| pytest-cov | 7.1.0 |
| hypothesis | 6.165.10 |
| freezegun | 1.5.5 |
| mypy | 2.3.1 |
| ruff | 0.16.3 |
| pixi | 0.70.2 |

`pixi` 0.70.2 accepts the `[workspace]` manifest form already in `pixi.toml` — ADR-010's
open question is closed, no change needed. The `clean` task's `rm -rf` is *not*
cross-platform and fails on Windows; it is replaced with a Python one-liner in this phase.

## 2. cedarpy 4.8.7 — the real surface

Public names: `is_authorized`, `is_authorized_batch`, `is_authorized_partial`,
`validate_policies`, `format_policies`, `policies_to_json_str`, `policies_from_json_str`,
`PolicySet`, `Schema`, `Entities`, `AuthzResult`, `PartialAuthzResult`, `Decision`,
`Diagnostics`, `PartialDiagnostics`, `ValidationResult`, `ValidationError`.

### 2.1 Pre-parsed handles exist and are reusable — use them

```python
ps = PolicySet.from_str(policy_text)      # eager ValueError on parse failure
ents = Entities.from_json_str(json_text)  # eager ValueError on bad entities
sch = Schema.from_str(cedar_schema_text)  # optional
res = is_authorized(request, ps, ents, sch)
```

- `PolicySet.from_str` raises `ValueError` **eagerly**. Passing raw policy *text* to
  `is_authorized` instead folds the parse error into the result as `Decision.NoDecision`
  plus `diagnostics.errors == ["policy parse errors:\n..."]`. We therefore parse eagerly at
  build time so misconfiguration surfaces as `ConfigurationError` rather than as a silent
  runtime deny.
- `PolicySet.with_added_str(text)` and `Entities.with_added_json_str(delta)` return **new**
  handles; the base is immutable. That is the right shape for Phase 2's composite sources
  and for a "stable base + per-request delta" entity pattern.
- `PolicySet` also exposes `templates()`, `with_linked()`, `with_linked_batch()` and
  `without_linked()` — relevant to Phase 5's template-linked, time-boxed grants.

### 2.2 Request shape

```python
{
  "principal": {"type": "User", "id": "alice"},   # or the surface string 'User::"alice"'
  "action": {"type": "Action", "id": "tool.search_orders"},
  "resource": {"type": "Tool", "id": "orders"},
  "context": {...},                # dict preferred; cedarpy JSON-encodes it internally
  "correlation_id": "req-123",     # optional, echoed back on the result
}
```

Both the dict (`{"type", "id"}`) and the Cedar surface-string form work. **We use the dict
form**: it sidesteps Cedar's surface-syntax normalization rules for ids containing awkward
characters, which matters because resource ids can come from untrusted callers.

`correlation_id` round-trips onto `AuthzResult.correlation_id`, so we feed it the invocation
id and operational logs, the Cedar result, and the audit record all share one key.

### 2.3 Entities shape

A JSON array of `{"uid": {"type", "id"}, "attrs": {...}, "parents": [{"type", "id"}, ...]}`.
Role membership is a parent edge, exactly as architecture §5 assumes.

### 2.4 Result object — `AuthzResult`

| Member | Type | Meaning |
| --- | --- | --- |
| `.decision` | `Decision` enum | `Allow` / `Deny` / `NoDecision` |
| `.allowed` | `bool` | `decision is Decision.Allow` |
| `.diagnostics.reasons` | `list[str]` | **determining policy ids** — this is what ADR-002 calls "determining policies" |
| `.diagnostics.id_annotations_by_reason` | `dict[str, str]` | determining id to that policy's `@id("...")` annotation, when it declares one |
| `.diagnostics.errors` | `list[str]` | evaluation and parse errors, as plain strings |
| `.correlation_id` | `str \| None` | echoed from the request |
| `.metrics` | `dict` | timings plus `*_pre_parsed` flags |

Observed behaviour:

- Ids in `reasons` are **parser-generated** (`policy0`, `policy1`, ...) when the set is
  parsed from Cedar text. The human-meaningful name comes from `@id("...")` via
  `id_annotations_by_reason`. `cedar.py` therefore surfaces the annotation where one exists
  and falls back to the generated id, so `AuthzDenied.determining_policies` stays readable.
- No matching policy at all gives `Decision.Deny` with `reasons == []` — Cedar's default deny.
- An evaluation error (for example `principal.nope` on an entity lacking that attribute)
  gives `Decision.Deny` with a populated `errors` list. **Errors never raise.**
- `Decision.NoDecision` is produced only by bad input (unparseable policies) and by partial
  evaluation. We map it to **deny**, and treat a populated `errors` list as a
  `ConfigurationError`-grade operational signal.

### 2.5 Cedar's type system rejects `float` and `null` — a real constraint

Confirmed by experiment:

| Value in `context` | Result |
| --- | --- |
| `int`, `bool`, `str`, list, nested dict, `{"__entity": {...}}` | `Decision.Allow` — fine |
| `float` | `Decision.NoDecision`, `errors == ["failed to parse schema from request"]` |
| `None` | `Decision.NoDecision`, the same error |

The same values in **entity attributes** are worse: `Entities.from_json_str` raises
`ValueError: error during entity deserialization`.

This is not covered by ADR-002 and it is the biggest footgun for this phase — a
caller-supplied `None` or float anywhere in the environment would silently turn every
decision into a deny. `cedar.py` therefore owns a **coercion step** applied to context and
entity attributes before anything reaches Cedar: `None` entries are dropped, `bool`/`int`/
`str` pass through, `datetime` becomes an epoch `int`, `float`/`Decimal` are rendered as
strings (Cedar has no floating-point type — a policy that needs numeric comparison should
receive an integer in minor units), mappings and sequences recurse, and anything else is
`str()`-ified.

### 2.6 ADR-002 revisited — partial evaluation *is* exposed

ADR-002 states that cedarpy "does not expose partial evaluation". That is **no longer true**
at 4.8.7: `is_authorized_partial` and `PartialAuthzResult` are public, carrying `residuals`,
`must_be_determining`, `may_be_determining`, `nontrivial_residuals` and `unknown_entities`.

We nonetheless **keep ADR-002's decision unchanged for Phase 1** — a boolean gate plus
Python-side, attribute-driven argument filtering — for three reasons:

1. cedarpy's own docstring warns explicitly that partial results **must not** be used as a
   final authorization decision; a residual-driven filter would still need a full
   `is_authorized` re-run per candidate argument set.
2. `residuals` are raw simplified policy ASTs. Turning an AST into an allow-set, range or
   pattern constraint is a compiler, not a Phase 1 module.
3. Attribute-driven filtering is what the audit record can actually explain to an auditor.

ADR-002's "Future" paragraph should be amended in the Phase 5 docs pass to say the binding is
already present and the blocker is residual *interpretation*, not availability.

`validate_policies(policies, schema)` **is** available and returns a structured
`ValidationResult`, so Phase 5's `sentrykit policy validate` does not need to shell out to
the Cedar CLI. Recorded here so that phase does not re-derive it.

## 3. pydantic v2 / pydantic-settings patterns confirmed

- `BaseSettings` with `SettingsConfigDict(env_prefix="SENTRYKIT_", frozen=True,
  extra="ignore")` reads `SENTRYKIT_VERBOSITY`, `SENTRYKIT_REDACTION`, ... and coerces
  `"false"` to `False`.
- `Literal[...]` fields give a clean `literal_error` with `loc == ("fail_mode",)` on a bad
  env value; we wrap that into `ConfigurationError`.
- **Per-action override** is `settings.model_copy(update={...})` on a frozen model: it
  returns a new instance and leaves the global untouched. Confirmed.
- **Argument model from a callable**: `inspect.signature` plus
  `typing.get_type_hints(include_extras=True)` plus `pydantic.create_model(name,
  __config__=ConfigDict(arbitrary_types_allowed=True), **{name: (annotation, default)})`.
  - Unannotated parameters fall back to `Any`.
  - `*args` / `**kwargs` parameters are skipped.
  - `ValidationError.errors(include_url=False)` yields the structured
    `[{"type", "loc", "msg", "input"}]` list that `ValidationFailed` carries.
  - The model is built once per protected callable and cached on the wrapper.
  - `extra="forbid"` is deliberately **not** used: the engine has already filtered the
    argument dict down to the callable's own parameter names, and forbidding extras would
    turn a policy-injected default for a `**kwargs`-only callable into a hard failure.

## 4. `contextvars` behaviour relied on

Standard-library semantics, matching architecture §3, with no surprises: values set with
`ContextVar.set()` propagate into awaited coroutines and into `asyncio.to_thread`, but
**not** into `ThreadPoolExecutor.submit`. `context.py` therefore ships
`run_with_context()` and `offload_callable()` built on `contextvars.copy_context()` for the
executor case.

## 5. Decisions taken for Phase 1 as a consequence

1. `cedar.py` builds and caches a `PolicySet` plus `Entities` handle pair, re-parsing only
   when the underlying payload changes.
2. `Decision` is normalized into our own frozen `CedarDecision` dataclass, so nothing outside
   `cedar.py` imports `cedarpy`. The rest of the core stays engine-agnostic and unit-testable
   without a policy set.
3. `NoDecision`, and any populated `errors` list, means **deny** (fail closed), with the
   errors preserved on the decision object for the envelope and the audit trail.
4. Phase 1 wires a **minimal in-memory** policy set and entity source directly. The pluggable
   `PolicySource` / `GrantStore` Protocols and entry-point discovery are deliberately Phase 2
   and are not stubbed here.
