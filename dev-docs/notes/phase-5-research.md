# Phase 5 — research notes

Findings verified against the **actually installed** `all` pixi environment on 2026-08-18, by
running code rather than by reading documentation. Phases 1–4 are in `phase-1-research.md` …
`phase-4-research.md` and are not repeated.

| Package | Version |
| --- | --- |
| Python | 3.13.15 (conda-forge) |
| **cedarpy** | **4.8.7** |
| freezegun | 1.5.5 |
| mcp / pydantic-ai | 2.0.0 / 1.47.0 |

---

## 1. `validate_policies` — what the CLI can actually report

ADR-002's amendment said the CLI needs no external Cedar binary. Confirmed, and the *shape of
a failure* is now pinned by experiment, because that shape is the entire output of
`sentrykit policy validate`.

`sentrykit.cedar.validate_policies(policies, schema) -> PolicyValidation` already normalizes
cedarpy's result. Measured:

| input | `passed` | what `errors` carries |
| --- | --- | --- |
| valid policies + valid schema | `True` | `()` — and `describe()` is `""` |
| a policy naming an undeclared action | `False` | **two** entries, both `cedar_id="policy1"`, `policy_id="bad"` (the `@id`): ``unrecognized action `Action::"nope"` `` and ``unable to find an applicable action given the policy scope constraints`` |
| unparseable policy text | `False` | one entry, `cedar_id=""`, `policy_id="<parse>"`, ``Policy parse error: unexpected token `cedar` `` |
| unparseable schema | `False` | one entry, `policy_id="<parse>"`, `Schema parse error: …` |

Three consequences for the command:

1. **One policy produces several errors.** `PolicyValidation.grouped()` already keys them by
   `policy_id`, so the report is grouped by policy and not a flat list of near-duplicates.
2. **A parse failure is not attributable to a policy** — it arrives under the sentinel
   `<parse>` with an empty `cedar_id`. The CLI prints it as a file-level error, because
   telling an operator that policy `<parse>` failed is telling them nothing.
3. **It never raises.** Exit status has to come from `passed`, not from an exception.

`cedarpy.format_policies(text) -> str` also exists and round-trips (`permit(principal,action,
resource);` → `permit (principal, action, resource);\n`). That is the *lint* half of
`policy validate`: a file that does not equal its formatting is reported as a warning, never
as a failure, and never rewritten in place — reviewed policy text is not something a
validation command edits.

## 2. `AuditSink.query` — the window is the whole report

`AuditWindow` (phase 2) is the aggregation input; nothing new is needed. Measured against
`InMemoryAuditSink` with five records on consecutive days:

* Time bounds are **half-open** — `start` inclusive, `end` exclusive — so adjacent windows
  tile a log with no record counted twice. A `--from`/`--to` pair that an operator reads as
  "January" is `start=2026-01-01, end=2026-02-01`, and the CLI has to add the day to `--to`
  itself or silently drop the last day's records.
* `limit` truncates *after* matching, oldest-first.
* `decision` (`allow`/`deny`) and `kind` (`decision`/`mutation`) filter as declared.
* Naive datetimes on either side are read as UTC (`_as_utc`), so a `--from 2026-01-01`
  parsed with `date.fromisoformat` needs no timezone juggling in the CLI.

The **outcome vocabulary** is what the report aggregates over, and it is finer than
allow/deny — `typing.get_args(AuditOutcome)` returns:

```
allowed, denied, engine-error, arguments-rejected, no-valid-arguments,
default-unavailable, validation-failed, granted, revoked
```

The last two are the admin mutations. A report that grouped only by `decision` would show
every grant and every revocation as an "allow", which is exactly the collapse ADR-006 exists
to prevent — so the report groups by `outcome`, and reports mutations as their own section.

## 3. The CLI is argparse, and the console script was never wired

* **argparse only.** No `click`, no `typer`. Three command groups over a stdlib parser is
  perhaps 40 lines of wiring; a dependency for that would be paid by every install of a
  library whose whole pitch is that it is thin.
* **Correction to the brief.** `[project.scripts]` in `pyproject.toml` does *not* declare the
  console script — the line is commented out, tagged `# phase 5`. Phase 5 uncomments it.
* `python -m sentrykit.cli` needs `if __name__ == "__main__": raise SystemExit(main())` at the
  bottom of the module. Both entry paths call the same `main(argv: Sequence[str] | None) -> int`.
* **The pixi tasks are aspirational and need correcting.** `policy-validate` runs
  `… policy validate policy/`, and no `policy/` directory exists at the repo root — the
  shipped pack lives at `src/sentrykit/policy/pack/`. `policy validate` therefore takes an
  **optional** directory and validates the shipped pack when given none, and the task drops
  the argument. `audit-report` names no sink, so the command falls back to
  `Settings.audit_sink` (`SENTRYKIT_AUDIT_SINK`) and fails with a message naming that variable
  when there is none.

### Report format: markdown now, PDF as future work

`--out` writes **markdown**. It is diffable, it renders in every forge, and it costs no
dependency. A PDF path would mean `reportlab` or `weasyprint` (which wants a system cairo) —
a heavy dependency for a formatting preference, added to a library that is trying to stay
thin. Recorded as future work: the markdown is the artifact, and `pandoc`/`mkdocs` turn it
into a PDF for anyone who needs one.

## 4. The pack validates, and Cedar takes every shape the patterns need

The eight candidate patterns were written as one policy set with one `.cedarschema` and
**validated clean on the first run**. What that pins:

* **An entity-valued attribute works as the right-hand side of `in`.**
  `principal in resource.required_role` type-checks and evaluates — measured: a `User` with a
  parent edge to `Role::"support"` is permitted against a resource declaring
  `required_role: Role::"support"`, and a user without the edge is denied. This is what makes
  a *domain-neutral* RBAC policy possible at all: the pack cannot name your roles, so the
  **resource** declares which role it requires and the **grant store** supplies the edge.
* **`action in principal.delegated_actions` works** with a `Set<Action>` attribute. Delegation
  scope is therefore data on the delegated principal, not a policy per delegation.
* **Transitive `in` resolves group hierarchy**: a member of `Group::"eu-west"` (child of
  `Group::"eu"`) is permitted against a resource declaring `group: Group::"eu"`.
* **Expiry is a `Long` comparison.** `sentrykit.cedar.coerce_value` renders a `datetime` as
  **epoch seconds**, and the engine injects `now` into the environment as
  `datetime.now(UTC)`. So a TTL condition is `context.now <= principal.delegation_expires`
  with both sides `Long`. It is *not* an ISO-string compare (Cedar has no ordering on
  strings) and it does not need Cedar's `datetime` extension. Schema attributes are declared
  `Long`.

Measured decision matrix for the candidates (`✔` = as intended):

```
rbac: support -> orders          allow   determining=('rbac-required-role',)      ✔
rbac: bob -> orders              deny    determining=()                           ✔
group: mo(eu-west) -> regional   allow   determining=('group-membership',)        ✔
ownership: alice -> mine         allow   determining=('ownership',)               ✔
delegation in-scope              allow   determining=('delegation-on-behalf-of',) ✔
delegation wrong action          deny                                             ✔
delegation expired               deny                                             ✔
delegation without on_behalf_of  deny                                             ✔
btg without flag                 deny    determining=('btg-forbid-without-flag',) ✔
btg with flag                    allow   determining=('btg-permit-with-flag',)    ✘  see below
sod conflicting role             deny    determining=('sod-conflicting-role',)    ✔
sod same actor                   deny    determining=('sod-same-actor-approval',) ✔
```

### The one that had to be redesigned: break-the-glass permitted *anyone*

The first draft's BTG permit was conditioned on the flag alone:

```
permit (principal, action, resource)
when { resource.emergency_only && context.break_glass };
```

Measured, that permits **any principal at all** who sets `break_glass` — including one the
rest of the pack denies, since a `permit` needs no base entitlement to fire. The emergency
flag is caller-supplied, so this is a hole a client opens for itself. The same run showed the
symptom: a JIT-elevation probe came back allowed with `determining=('btg-permit-with-flag',)`
even after its elevation window had closed.

> **Decision.** Break-the-glass is an **entitlement plus a flag plus a justification**, never
> a flag. The resource declares an `emergency_role`; the principal must be in it; the context
> must carry both `break_glass` and a non-empty `justification`. The obligation is mandatory
> and rides on the permit (ADR-012), so a call that proceeds under BTG cannot proceed
> quietly. The `forbid` half still fires whenever the flag is absent, and forbid beats every
> other permit in the pack — which is what makes an emergency-only resource emergency-only.

## 5. Templates: cedarpy has no linking API, so linking happens on our side

`dir(cedarpy)` on 4.8.7:

```
AuthzResult, Decision, Diagnostics, Entities, PartialAuthzResult, PartialDiagnostics,
PolicySet, Schema, ValidationError, ValidationResult, format_policies, is_authorized,
is_authorized_batch, is_authorized_partial, policies_from_json_str, policies_to_json_str,
validate_policies
```

There is **no** `link`, no `template`, no `PolicyTemplate`. Three measurements settle what
that means:

1. Template *syntax* validates: `permit (principal == ?principal, action == Action::"read",
   resource == ?resource);` passes `validate_policies` against a schema.
2. An **unlinked template in a policy set is inert** — the engine builds, and the request it
   textually describes is denied. So a template cannot accidentally grant anything.
3. `policy_annotations` **drops templates entirely** (a mixed set of static/template/static
   returns entries for `policy0` and `policy2` only) — but cedarpy's positional ids stay
   aligned with what `is_authorized` reports as determining. Provenance therefore survives a
   template sitting in the text.

> **Decision.** The template-linked grant helper links **textually, on our side**:
> `link_template()` substitutes `?principal`/`?resource` and emits a concrete, `@id`-annotated
> Cedar policy plus the matching `GrantSpec` carrying the expiry. Templates live in
> `policy/pack/templates/*.cedartemplate`, deliberately outside the `*.cedar` glob, so the
> filesystem source never loads an inert template as if it were policy. Point 3 means that
> even a hand-mixed directory would not corrupt provenance — but "the policy set contains
> something that can never permit anything" is not a state worth allowing by accident.

## 6. Decisions taken for Phase 5 as a consequence

1. `policy validate [DIR]` defaults to the **shipped pack**, groups errors by `@id`, reports
   `<parse>` failures at file level, and lints formatting with `format_policies` as a
   non-fatal warning (§1).
2. `audit-report` windows the sink with `AuditWindow`, treats `--to` as **inclusive of that
   day** by adding one day to the exclusive bound, aggregates by **`outcome`** rather than by
   `decision`, and reports mutations separately (§2).
3. Markdown out; no PDF dependency (§3).
4. The pack is **attribute-driven**: the resource declares what it requires, the grant store
   supplies the edges, the context supplies `now`/`break_glass`/`on_behalf_of`/`justification`.
   No pattern names a domain role (§4).
5. Break-the-glass requires an entitlement, a flag *and* a justification, and carries a
   mandatory obligation (§4).
6. Templates are linked by sentrykit, kept out of the policy glob, and produce a policy *and*
   a grant together (§5).
