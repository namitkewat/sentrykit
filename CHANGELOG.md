# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows SemVer.

## [Unreleased]

The four example apps rebuilt around one shared domain, so that each of them demonstrates the
whole library rather than a slice of it, and the same story can be read at four different
boundaries.

### Added

- **Narrowing now reaches the caller whatever the protected callable returns.** The three
  outcome fields below shipped inside the `_authz` key, and that key can only be written into a
  mapping — so a callable returning a list, a string, a model or `None` reported nothing at all.
  A web route returning a JSON array is the commonest shape there is, which made the benefit of
  having those fields conditional on a detail of the application's return type.

  `last_envelope()` is now documented as the mechanism and `_authz` as a convenience layered on
  top of it. Behind both, a boundary installs an `EnvelopeRecorder` — a mutable object reached
  *through* a context variable rather than a value stored in one, which is what makes it survive
  a decision taken inside a copied context. That distinction is the whole mechanism: a sync
  framework route runs in a worker thread holding a copy, so a plain `ContextVar` write is
  discarded before the middleware that has to write the response headers ever sees it. The
  recorder accumulates every decision in the request, because "was anything narrowed while
  serving this response" is not answerable from the most recent envelope alone.

  What each boundary now carries, with no wiring:

  * **FastAPI and Flask** — `x-sentrykit-narrowed: true` and
    `x-sentrykit-narrowed-arguments: a, b`, emitted only when something was narrowed.
    `guidance` is deliberately **not** a header: it is prose past 300 characters and its
    unsupplied-argument form contains an em dash, which an HTTP field value cannot spell.
  * **MCP** — the `sentrykit/narrowed` and `sentrykit/narrowedArguments` `_meta` keys, plus one
    **appended** text content block carrying `guidance`, because `_meta` is protocol metadata a
    client is under no obligation to show the one reader who needs it.
  * **Pydantic-AI** — a `ToolReturn` whose `metadata` carries the facts and whose `content`
    becomes a separate prompt part. Verified additive rather than assumed: `return_value` still
    reaches the model as the `ToolReturnPart`, so the data is never displaced by the note about
    it.

  Both agent adapters leave a mapping return alone, since it already carries the whole envelope
  where the model reads it. Whether that happened is a fact the recorder records rather than one
  the adapter infers from the result's shape — mcp populates `structuredContent` only when it
  has an output schema to validate against, so the envelope may be in the content text instead.

  Measured on the same seven-model harness, with a **list-returning** tool and the guidance
  delivered out of band: pooled over four samples at 28 runs per arm, it served the user real
  data in 23 of 28 runs, against 22 of 28 for the same narrowing reported in band and 14 of 28
  for the old exceptions-only envelope. So the benefit no longer depends on the return shape.

  An earlier draft of this entry put that as "5 of 7 and then 7 of 7 … against 3 of 7", and
  concluded that the separate message "appears to be at least as strong a signal as the in-band
  field." Both are withdrawn, and for the same reason: those were single samples read as
  aggregates. Pairing every run by model and sample leaves the out-of-band channel and the
  in-band field one run apart — 3 discordant pairs of 28, exact two-sided sign test
  **p = 1.000** — so no direction is measured between them, and none should have been claimed.
  `_authz` stays the channel wherever the return type allows it and the out-of-band annotation
  covers every other shape, which is what shipped. ADR-029 records the decisions and what is
  still not covered.

- **The `_authz` envelope now reports the outcome of a narrowed call, not only its exceptions.**
  Three new fields: `narrowed` (the call ran with a value the caller did not propose),
  `narrowed_arguments` (which ones) and `guidance` (one sentence on what the result means and
  what to do with it). This closes a gap that only showed up under measurement. A narrowed call
  *succeeds* — real data is returned, on values the principal is entitled to — but an envelope
  whose only narrowing fields were `rejected` and `defaults_applied` described that success in
  the vocabulary of a failure. Driven against seven language models on one over-broad request
  and pooled over four samples, roughly half the runs read that envelope, concluded the call had
  failed, and withheld the data they were already holding. Adding the three outcome fields to
  that same payload is the one contrast in the experiment that survives a paired test: of the
  eight runs where the two reportings differ, all eight favour the outcome fields — exact
  two-sided sign test **p = 0.0078**. Reporting the outcome alongside the exceptions is the fix.

  Two claims from an earlier draft of this bullet are withdrawn. "Four of them" was the same
  single sample read as an aggregate as above. And stripping the envelope altogether was said to
  score *better* on serving than the exceptions-only envelope: unpaired it does, 64% against
  50%, but paired it is 7 of 10 discordant runs at p = 0.344 — a direction worth holding onto,
  not a measured result. Both are quoted rather than deleted because the asymmetry is the
  lesson: the paired test had been applied only to the comparison expected to lose.

  `narrowed` is defined against the **proposal**, not against `rejected`, because the two differ
  in both directions: a rejection that left the argument with a surviving value of the caller's
  own is not narrowing, and a default injected for an argument the caller never mentioned is not
  either — nothing was taken away. It is omitted from the rendered envelope when false, so an
  ordinary allow stays exactly as terse as before.

  None of the three carries an argument value or a policy id, so all three are present at every
  verbosity above `off`. That is the point: a caller who may not be told *which* value was
  refused can still be told *that* the result is good.

  `guidance`'s opening sentence is conditional, and the distinction is worth knowing. When every
  narrowed argument was refilled from the principal's own entitlement it says the result is
  **valid**. When one was not — the argument was dropped and the callable's own signature default
  filled the slot — it says the result was **served** and marks that part **unverified**, because
  no constraint ever saw the value that landed there. That is the first time anything in
  sentrykit tells an operator a governed parameter took its value from outside the policy layer.

  `sentrykit.envelope.narrowing_guidance` composes the sentence and is reachable for a host that
  wants to re-render it. `Plan.narrowing()` is the seam that computes the two sets.

- **One orders-and-refunds desk, modelled identically in all four examples.** Three principals
  — `alice` (support), `bob` (auditor), `dana` (admin, reaching support through a single
  `Role::"admin" -> Role::"support"` edge rather than through a second grant on every admin) —
  seven protected operations, one entity graph and one set of grant data, shared verbatim
  between the FastAPI app, the Flask app, the MCP server and the Pydantic-AI agent. Only the
  boundary wiring differs between them, which is what makes diffing two example directories a
  useful thing to do.
- **A printed flow table in every example.** `pixi run run-fastapi`, `run-flask`, `run-mcp` and
  `run-agent` each drive 22 calls before doing anything else and print one line per call saying
  what policy did to it — allowed, narrowed with the rejection and the refill named, defaulted,
  denied, or the argument-layer error that refused it. The web apps drive their framework's own
  test client and then serve; the MCP server drives itself over an in-memory transport when a
  human runs it at a terminal and serves over stdio when its stdin is a pipe.
- **The grant data now exercises the whole constraint vocabulary** — allow-set, deny-set,
  pattern, minimum, maximum and default — with at least one flow per rule, including a pattern
  deliberately carrying no default so that `DefaultUnavailable` is reachable, and a deny-set
  whose rejection is refilled so that the export still runs.
- **An argument ceiling demonstrated end to end.** `policies/10-orders.cedar` declares
  `@constraints("{\"limit\": {\"maximum\": 100}}")` on `support-may-search`. Dana's grant sets
  no maximum of its own, so the reviewed ceiling is her only bound: she proposes `limit=500`,
  the ceiling is 100, and the call runs at 25 — her own default. The flow exists specifically
  to make reject-and-refill visible as distinct from a clamp, and each example calls it out.
  Alice's grant caps `limit` at 50, so hers is the tighter bound and her rejection names her
  grant rather than the reviewed policy.
- **Two Cedar rules that decide on more than the principal/action/resource triple.**
  `refunds-above-the-desk-limit-need-an-admin` weighs a proposed argument together with the
  principal; `no-large-cross-region-refunds` weighs two proposed arguments against each other,
  each of which is within bounds alone. Both are written over a deliberately unconditional
  permit, so that a manifest probe proposing no arguments still reaches it and the tool stays
  visible to the principals who may invoke it.
- **An optional local-model path for both agent examples** (`examples/ollama.py`, standard
  library only). Each example uses a tool-capable [Ollama](https://ollama.com) model when a
  daemon is reachable and a deterministic stand-in otherwise, and prints which is in use.
  `SENTRYKIT_OLLAMA_MODEL` pins a model; `SENTRYKIT_OLLAMA_URL` points at another daemon.
  Setting `SENTRYKIT_OLLAMA_URL` to an **empty** value turns the search off before any socket
  is opened, which is how the test suite stays hermetic. Every authorization outcome is
  identical on both paths, because a decision is made from the principal and the proposed
  arguments and never from which model proposed them.

### Changed

- **All example policy logic moved from Python strings into reviewed `.cedar` files**, loaded
  with `install(policy_source=FilesystemPolicySource(POLICY_DIR), ...)`. `policies=` and
  `policy_source=` are mutually exclusive, so the move takes *all* of it; each example still
  exports `POLICY_TEXT`, now read back from those same files. This is what puts the argument
  ceiling under review beside the `permit` it hangs on.
- **`docs/web-frameworks.md` and `docs/agents.md`** replace their short example sections with
  walkthroughs of what each flow teaches. The web page no longer describes the two web apps as
  "the same three routes"; the agents page no longer says both agent examples run with no
  network call, and no longer mentions a `SENTRYKIT_EXAMPLE_MODEL` setting that no longer
  exists.
- **`docs/agents.md` documents a boundary difference an integrator will hit.** `mcp` and
  Pydantic-AI both materialize the advertised JSON schema's defaults before dispatch, so a
  parameter carrying a Python default arrives at the decorator as a *proposed* argument and
  survives filtering. `NoValidArguments` is therefore reachable at a web boundary by proposing
  a single argument that is then rejected, and at an agent boundary only from a tool whose every
  parameter is omittable.
- **`README.md`** corrects the same two claims about the example apps.

## [0.2.0] - 2026-08-20

The argument layer, hardened and extended. A silent entity-forgery escalation is closed;
an injected default is now checked against the constraint that governs it; a constraint no
value could satisfy is refused when it is written; and a reviewed Cedar policy can declare
an argument ceiling that narrows a call rather than refusing it. The remainder is
packaging, documentation and CI.

### Security

- **Cedar's reserved `__` escape keys can no longer be spelled by a caller.**
  `coerce_value` recursed into supplied mappings without filtering them, so a dict-valued
  argument could carry `{"__entity": {"type": "Group", "id": "approved"}}` and reach the
  evaluator as a genuine `Group::"approved"`. Against the argument-aware `forbid` backstop
  the docs describe — `forbid ... when { !(context.args.region in Group::"approved") }` —
  that produced a **clean allow with no engine error**, because Cedar's `in` is reflexive
  and passing the approved group itself satisfies it. `fail_mode="closed"` could not see it:
  `CedarDecision.failed` was `False`. A Cedar schema declaring `context.args` contained the
  escalation, but `PolicyEngine`'s `schema` parameter is optional and the shipped
  `pack.cedarschema` declares no `context.args` member, so a deployment using argument-aware
  policies could not straightforwardly have one.
  - Any key beginning with `__` — the whole reserved prefix, not just the two spellings
    Cedar defines today — now raises the new `ReservedKey` error, checked before the value
    is coerced and at any nesting depth (inside a list, inside a nested record).
  - Dropping the key was rejected as a fix because it silently turns off a `forbid` that
    tests `context.args has ...`; escaping it was rejected because the forgery would then
    fail only as a Cedar *type* error, which `fail_mode="open"` tolerates. Refusing is the
    only option that holds under both fail modes, and the refusal is raised ahead of the
    gate so there is no engine failure for `open` to arbitrate.
  - The refusal is audited as an ordinary denial, so a forged request leaves a record.
  - `EntityRef` is unaffected: it has its own trusted path to the `{"__entity": ...}` form,
    and remains the only way to hand Cedar an entity reference.
  - **Scope, stated precisely, because the first wording of this entry over-claimed.** The
    check closes the *spelling*: a supplied mapping can never promote itself into an entity.
    It does not decide who chooses an entity's **type**. `isinstance(value, EntityRef)` is a
    type check, not a provenance check, and every integration validates a caller's JSON
    against the protected callable's annotations *before* the decorator runs — the wrapper is
    signature-preserving so that framework introspection sees the original function. A
    parameter annotated `EntityRef` is therefore a caller-chosen entity, type included, and
    Cedar's reflexive `in` makes `!(context.args.region in Group::"approved")` satisfiable by
    passing the approved group itself. Reproduced over real HTTP and a real MCP round trip;
    on MCP, `tools/list` also advertises the shape to the model. Three defenses close it and
    are now documented where the annotation is described: pin the type with Cedar's `is`,
    bound the argument with a constraint or a ceiling, or declare `context.args` in a Cedar
    schema. The behaviour is unchanged — promoting an `EntityRef` is what the type is for —
    but `docs/concepts.md`, `SECURITY.md` and the `coerce_value` docstring no longer claim
    otherwise, and `tests/integration/test_entity_valued_arguments.py` pins both the exposure
    and each defense.
  - The sibling `__extn` form is closed by the same check. It was the less severe of the two
    — it produced an engine error, so `fail_mode="closed"` already refused it — and was a
    live bypass only under `fail_mode="open"`.

### Added

- **Argument ceilings: a reviewed Cedar policy can now declare what any principal may pass.**
  A `@constraints` annotation carries a compact JSON object of `{argument: {rule: value}}`,
  and the declared bounds reach sentrykit's narrow-and-continue path — the one thing Cedar's
  gate structurally cannot express, because a `forbid` can only refuse the call. "You asked
  for 500, you may not have that — here is the call at what you may have" is now expressible in
  version-controlled, hash-covered policy text rather than only in mutable grant data. The
  mechanism is the existing reject-and-refill, not clamping: a value above the bound is
  rejected and the principal's own default fills the hole.

  ```
  @id("support-may-search")
  @constraints("{\"limit\": {\"maximum\": 100}, \"region\": {\"allow\": [\"eu\", \"us\"]}}")
  permit (principal in Role::"support", action == Action::"tool.search", resource == Tool::"orders");
  ```

  - **Ceilings only.** A ceiling may set `allow`, `deny`, `pattern`, `minimum`, `maximum` and
    `required`. It may **not** set a `default`: a default is a value, often a per-principal
    one, and the caller-facing error already treats default values as grant data by telling a
    caller one exists without telling them what it is.
  - **Intersecting, never widening.** Policy-declared ceilings and grant-held constraints
    intersect — allow-sets intersect, deny-sets union, bounds move inward, `required` is
    sticky, two patterns must both match in full. Two determining permits intersect too,
    which is inverted relative to Cedar's disjunctive permits and is the security-correct
    direction. New: `ArgumentConstraint.intersected_with` and
    `ConstraintSet.intersected_with`, the counterparts to the overriding `merged_with`.
  - **Everything is checked at load.** Cedar's validator ignores unknown annotations
    entirely, so a nonsense declaration would otherwise sit in a validated policy set
    enforcing nothing. `PolicyBundle.from_text` raises `ConfigurationError` on a value that is
    not a JSON object of objects, a rule a ceiling may not set, a value of the wrong type, a
    constraint no value could satisfy, a pattern that will not compile or that carries a
    backreference, an empty declaration, and a ceiling attached to a `forbid` — which could
    never apply, since a determining `forbid` has already refused the call.
    `sentrykit policy validate` runs the same load and fails on a broken one.
  - **The fail-open path refuses when the bundle declares any ceiling.** A failed evaluation
    reports no determining policies and therefore no ceilings, so the call would proceed
    unbounded at exactly the moment the engine is least trustworthy. The check lives on the
    fail-open path rather than at wiring, because `fail_mode` is overridable per action on
    every call.
  - Rejections keep per-layer provenance: filtering runs layer by layer, so a rejection names
    the reviewed policy or the grant that produced it, while the intersected set decides
    defaults, required arguments and the "here is what you may pass" half of an error.
  - New: `PolicyProvenance.ceiling`, `PolicyBundle.ceilings_for`,
    `PolicyBundle.declares_ceilings`, `CONSTRAINTS_ANNOTATION`, `CEILING_RULES`,
    `parse_ceiling`.
  - One thing sentrykit cannot check, stated in the docs rather than engineered away: a
    misspelled argument name in a declaration is inert. `policy validate` reads a directory of
    policy files and never imports the application, so there is no signature to compare
    against.
- **`ArgumentConstraint.inconsistencies()` and `ConstraintSet.inconsistencies()`** — the
  write-time self-consistency check, returning one sentence per problem. Four checks: the
  `pattern` compiles, `minimum` is not above `maximum`, every `allow` member satisfies the
  constraint's other rules, and a configured `default` satisfies the constraint. The last two
  delegate to `check()`, so what a grant promises at the write and what the filter enforces at
  the call cannot drift apart. A structural fault (bad pattern, inverted bounds) short-circuits
  the value-level probes, which would otherwise restate it once per value.
  - `GrantStore.grant()` runs it and raises `ConfigurationError`, so a constraint no value
    could satisfy cannot be stored. Both shipped stores inherit the check.
  - It is **not** a validator on the model. A store also reads constraints, and refusing at
    construction would make one bad row already on disk fail the load of every principal in
    the file. The call path is fail-closed per argument regardless.
  - `required=True` combined with a `default` is deliberately *not* reported. It looks like a
    contradiction and is not: `inject_defaults` skips any name the callable does not accept,
    so a required, defaulted constraint naming a parameter that is not in the signature still
    raises `DefaultUnavailable` legitimately.

- **A Sphinx documentation system** replacing mkdocs, producing four artifacts from the
  Markdown pages that already existed: HTML (furo), a PDF, `llms.txt` and `llms-full.txt`.
  The repository is private, so there is nowhere to host a site — documentation ships as
  release assets instead, and `dev-docs/documentation-standards.md` now governs it.
  - `docs/conf.py` computes `autodoc_mock_imports` from whichever framework packages are
    absent, so the same page set builds `-W`-clean in all four pixi environments rather than
    only in `all`.
  - The API reference is generated by `autodoc` from the docstrings, which makes a docstring
    a published page.
  - PDF via **rinohtype** rather than `latexpdf`: pure Python, no LaTeX toolchain, so it
    builds identically on a laptop and a runner. It is a `dev`-only build tool and never
    reaches the wheel.
  - `llms-full.txt` is built from `sphinx-build -b markdown`, so the API reference is
    expanded into real signatures rather than left as a directive — the file is meant to be
    sufficient to implement against on its own.
  - New tasks: `docs-html`, `docs-pdf`, `docs-markdown`, `docs-llms`, `docs`, `docs-serve`,
    `docs-clean`. `check` now builds the HTML under `-W`, so a documentation warning fails
    the gate.
- **`SECURITY.md`** — a disclosure contact, and an explicit account of what sentrykit defends
  and what it does not: it does not sandbox a tool body, it does not authenticate, and
  without a durable write-once sink it detects tampering rather than preventing it.
- **A CI matrix** over Python 3.11/3.12/3.13 × the four feature sets — twelve jobs, each
  running `pixi run -e <env> check` against the version-pinned pixi environments — plus one
  job proving the built wheel installs with each of the seven extras.
- **A release workflow** on a `v*` tag (with `workflow_dispatch` as a dry run) that verifies
  the tag matches the package version, builds everything, and attaches six assets: the wheel,
  the sdist, the zipped HTML, the PDF, `llms.txt` and `llms-full.txt`.
- **`dev-docs/api-surface.md`** — every exported name marked public or internal with a
  reason. Nothing was withdrawn; two documentation gaps were recorded instead.
- Twelve version-pinned pixi environments (`py311-default` … `py313-all`, `linux-64` only) so
  a CI job and a contributor reproducing it locally run the identical resolved dependency set.

### Changed

- **`DefaultsResult` carries a third field, `withheld`.** Attribute access is unaffected;
  code that unpacked the result into exactly two names needs a third.

- **`--policy` is now required on `sentrykit grant` and `sentrykit revoke`.** It previously
  defaulted to `pack://`, and the shipped pack deliberately contains no permit for the admin
  actions — so the default made every mutation refuse, and an operator read a message about
  their own entitlement when the truth was that no policy source had been named. A missing
  `--policy` is a usage error now, raised before a store or a sink is opened.
- Shipped docstrings, comments and documentation pages were rewritten as present-tense,
  self-contained statements. References to how the code was built — phase numbers, ADR
  citations, pointers into `dev-docs/notes/` — are gone from `src/`, `tests/`, `docs/`,
  `examples/` and the README, because a reader who installs the wheel has none of those. The
  reasoning they carried was inlined rather than deleted. `dev-docs/` and this changelog keep
  the history; they are the historical record on purpose.
- Real project metadata now ships in the distribution: author name and email, and the
  Homepage / Source / Documentation / Changelog URLs.
- The registry snapshot-and-restore fixture is now one `clean_registry` in `tests/conftest.py`
  instead of two copies, with isolation unchanged.

### Fixed
- **The declared `cedarpy` floor was `>=4.1`, which does not have the API the engine calls.**
  `sentrykit.cedar` parses the policy set, the entity graph and the schema once at wiring time
  through `PolicySet`, `Entities` and `Schema`, reuses those handles per decision, and
  type-checks policy with `validate_policies`. cedarpy 4.1 exposes none of those four names —
  measured against the 4.1.0 wheel, where `is_authorized` takes policy text and entity JSON on
  every call instead — so a resolver free to pick it installed cleanly and then raised
  `AttributeError` the first time a governor was built. The requirement is now
  `cedarpy>=4.8,<5` in both `pyproject.toml` and `pixi.toml`: 4.8 is the lowest release
  confirmed to carry the whole surface, and the upper bound keeps a Cedar major an explicit
  decision rather than a silent resolve. **`pixi.lock` has to be regenerated on Linux** — the
  twelve `linux-64`-only environments make `pixi lock` unsolvable from `win-64`, and the lock
  records the old requirement string in the editable package's `requires_dist`.

- **An injected default is now checked against its own constraint.** The filter checked a
  *supplied* value and default injection checked nothing, so the way to defeat a constraint
  was to stop proposing a value: `ArgumentConstraint(minimum=100, maximum=10, default=500)`
  rejected a proposed `500` and then injected `500`, and
  `ArgumentConstraint(allow=("eu", "uk"), default="us")` injected `"us"`. Under the default
  `arg_handling="lenient"` this fired on the ordinary path, because a rejected value is
  dropped and the default substituted.
  `ConstraintSet.inject_defaults` now runs the same `check()` the filter runs and **withholds**
  a default that fails it, reporting the fact instead of resolving it in the caller's favour.
  A withheld default appears on the `_authz` envelope and in the audit record alongside the
  caller's own rejections, and the argument then falls to `DefaultUnavailable` if the
  constraint requires it and to the callable's own default if it does not. It is deliberately
  not routed through `arg_handling="strict"`: that setting arbitrates the caller's proposal,
  and an unusable default is not theirs.
- **An unsatisfiable constraint is refused at the write rather than discovered at the call.**
  `minimum=100, maximum=10` constructed without complaint and surfaced later as a refusal of
  everything, found by whoever called next.

- **Signatures in the generated Markdown lost their `*` and `/` separators.** Sphinx renders
  a keyword-only or positional-only marker as an `abbreviation` node, and the Markdown
  writer's fallback discarded it along with its text — leaving `install(policies=None, ,
  entities=...)` in `llms-full.txt`, across 62 signatures. `docs/conf.py` now gives that node
  a pass-through visit, so the marker comes from the doctree Sphinx built out of the real
  signature and is correct in every position; `scripts/build_llms_txt.py` refuses to write the
  corpus if a scarred signature reappears. HTML and the PDF were never affected.
- **The `Settings` reference documented pydantic-settings instead of sentrykit.** As a
  `BaseSettings` subclass it inherited an `__init__` carrying twenty-nine `_env_*` / `_cli_*`
  machinery parameters — one defaulting to a `WindowsPath`, so the reference leaked the
  platform it was built on — ahead of the eight fields the class offers. The signature is now
  rebuilt from the model's own fields, in declaration order with the source spelling of each
  type: 37 parameters became 8.

### Documented
- **The positioning now leads with the argument layer.** `README.md`, `docs/index.md`,
  `docs/concepts.md`, `SECURITY.md` and the guide pages open on what sentrykit decides about a
  call's *arguments* — per-`(principal, action)` constraints, narrow-and-continue, defaults,
  write-time validation and the masked hash-chained record — with multi-hop relationship
  resolution kept as a supported capability that composes with Cedar rather than as the
  headline. Where a reader needs to know the niche, other projects are described by capability
  and never by verdict: general-purpose policy engines and relationship systems answer a
  boolean question at the gate, and sentrykit adds the layer above that answer.
- **`SECURITY.md` now states what sentrykit inherits and what it does not claim.** Cedar's
  evaluator and validator carry a formal model and proofs, and the implementation is checked
  against it by differential testing; sentrykit's own layer — filtering, narrowing, default
  injection, intersection, masking, the hash chain — is ordinary Python backed by tests and
  review. "Built on a formally verified engine" is a fact about Cedar rather than a property of
  this library, and the two layers should be weighed separately. The hardening checklist gained
  the two items this release implies: put a bound that must not be raised by mistake in a
  ceiling rather than only in a grant, and pin the type of an entity-valued argument in policy.

- The three constants a host must name to write the admin permit the shipped pack omits —
  `GRANT_ACTION`, `REVOKE_ACTION`, `ADMIN_RESOURCE` — are tabulated on the policies page next
  to the worked permit, with a doc-example test pinning the table to the constants and the
  constants to the permit. A permit naming anything else authorizes nothing.
- Registering a policy source, which was the one registration decorator with neither a test
  nor a documented example. `docs/plugins.md` shows the three members a source owes, and a
  unit test drives a registered source's DSN through to a loaded bundle.

### Removed

- mkdocs, mkdocs-material and mkdocstrings, and `mkdocs.yml`.

## [0.1.0] - 2026-08-18

First release. The library is complete against the plan in `dev-docs/implementation.md`:
one decorator, two worlds (web and agents), a shipped policy pack, a tamper-evident audit
trail, a maintenance CLI, and a plugin seam for every backend.

### Added
- The shipped Cedar policy pack and its loader (phase 5).
  - `policy/pack/` — eight domain-neutral patterns: `rbac`, `groups`, `ownership`,
    `delegation`, `expiry`, `break-glass`, `separation-of-duties`, `jit-elevation`. No
    shipped policy names a role, a resource type or an action; the resource declares what it
    requires, the grant store supplies the principal's edges, and the context supplies `now`,
    `break_glass`, `on_behalf_of` and `justification` (ADR-021).
  - `policy/loader.py` — the pack reaches a governor as an ordinary `PolicySource` under a
    `pack://` DSN, so it unions with a user's own directory through the existing composite
    and its ids namespace as `pack/<id>`. `pack://rbac,ownership` takes a subset. It is data,
    not a second policy mechanism (ADR-020).
  - `link_template` / `LinkedPolicySource` — time-boxed grants from a Cedar template, linked
    on sentrykit's side because `cedarpy` exposes no linking API, and returning the concrete
    policy together with the `GrantSpec` that makes it listable, auditable and revocable
    (ADR-023).
- The `sentrykit` command line (phase 5), over `argparse` and no new dependency.
  - `policy validate [DIR]` — type-checks a directory (the shipped pack by default) against
    its schema, groups errors by `@id`, reports parse failures at file level, and warns about
    formatting drift without rewriting anything. Non-zero exit on failure, so it belongs in CI.
  - `grant` / `revoke` / `grants` — the admin surface, governed by the same engine it
    administers. The `GrantSpec` is built from the policy-processed arguments rather than from
    `argv`, so an argument constraint decides *which* grants an operator may make (ADR-024).
  - `audit-report --from --to --out` — windows the sink and writes markdown, aggregating by
    **outcome** rather than by allow/deny, with a separate mutations section and a tamper
    evidence verdict.
- `JsonFileGrantStore` (`jsonfile://`) — a durable grant store, so the admin surface has
  something to write to outside a single process (ADR-025).
- `sentrykit policy` is exported from the package root: `PackPolicySource`, `load_pack`,
  `link_template`, `TemplateLink`, `LinkedPolicySource`.
- `cedar.format_policies`, the lint half of `policy validate`, kept in `cedar.py` so the
  one-module-imports-`cedarpy` invariant stays true.
- `docs/policies.md` and `docs/audit.md` gained the pack, the admin surface and the report;
  `docs/index.md` and `docs/quickstart.md` were refreshed for the finished library. Every
  example and CLI invocation on those pages is pinned by a test.
- `scripts/release_check.py` and a `release-check` task: builds the wheel and sdist, then
  installs the wheel with each extra into a throwaway venv and imports it. The offline half —
  that the wheel actually contains the policy pack, the schema, the entity graph, the
  templates, `py.typed`, the console script and every entry-point group — is a test.

### Changed
- The registry builders (`build_policy_source`, `build_grant_store`, `build_audit_sink`,
  `build_context_provider`) now accept an already-built backend *inside* a sequence, not only
  a DSN string, so `install(policy_source=["pack://", LinkedPolicySource(links)])` composes. A
  union closed to anything unspellable as a DSN would have put an in-memory or
  credential-holding backend out of reach. Every previous spelling is unchanged.

### Notes
- **The pack ships no permit for the admin actions**, deliberately: a library does not get to
  ship the rule that hands out authority. `sentrykit grant` under the default `--policy
  pack://` therefore refuses until a host writes one, and says so. The first operator is
  seeded in provisioning code — a bootstrap flag that skipped the gate would be a back door
  that never closes (ADR-024).
- **Break-the-glass takes an entitlement, a flag and a justification.** The obvious draft —
  permit when the emergency flag is set — was measured to authorize anyone at all, because
  the flag is caller-supplied and a Cedar `permit` needs no base entitlement to fire
  (ADR-022).
- **The pack's schema is opt-in** (`pack://?schema=true`). A composite concatenates its
  members' schemas and an engine built with one validates every *request* against it, so a
  pack contributing a schema by default would break requests naming actions it never heard
  of. Decisions are identical either way (ADR-020).
- `cedarpy` 4.8.7 exposes no policy-template linking API at all. An unlinked template in a
  policy set is inert, and `policy_annotations` drops it — though positional ids stay aligned,
  so provenance survives one. See `dev-docs/notes/phase-5-research.md`.
- Cedar has no ordering on strings, so every timestamp the pack compares is epoch seconds.
  `coerce_value` already rendered `datetime` that way; the pack's schema declares them `Long`.
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
