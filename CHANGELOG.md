# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows SemVer.

## [Unreleased]

<!-- Add an entry in the *fix & document* step of each loop iteration. -->

## [0.1.1] - 2026-11-09

The first stable release, and the whole library.

sentrykit is a self-hosted, framework-agnostic authorization layer for Python, built on
[AWS Cedar](https://www.cedarpolicy.com/). Clip one `@protect` decorator onto any callable — a
web route, a plain function, an agent tool — and it decides, per call, whether the principal may
invoke it, **which arguments they may pass**, and **which defaults to inject when they pass
none**, then writes a masked, hash-chained record of what it decided. The caller proposes; the
policy decides, and what it decides includes the arguments, not only the call.

`0.1.0rc1` published this same library, to prove the release chain end to end; nothing under
`src/` changed between it and this release. `0.1.0` is skipped rather than released — a wheel
under that filename was built on a developer machine and uploaded to the test index while the
chain was being proved, and since the chain verifies that an index serves the exact artifact the
run just built, a number whose test-index copy came from somewhere else can never pass it.
Version numbers below `0.1.0rc1` belong to the development history and were never published.

### Added

- **`@protect`, and one pipeline behind it.** The decorator guards any sync or async callable and
  runs gate, filter the proposed arguments, inject the defaults policy supplies, validate,
  invoke, report. One module imports `cedarpy`, parsing the policy set, the entity graph and an
  optional schema at wiring time and reusing those handles per decision. The core imports no web
  framework and no agent SDK, so the decision path is identical wherever it runs.
- **Ambient context, fail-closed.** `establish()` binds the principal, the channel and the facts
  a policy may read — `now`, `break_glass`, `on_behalf_of`, `justification`; `bind_context()`
  carries the scope across a thread-pool offload. With no principal established the call is
  refused rather than run unguarded, so forgetting to wire a boundary denies instead of opening.
- **Per-(principal, action) argument constraints.** Allow-sets, deny-sets, patterns, numeric
  bounds, `required` and a per-principal `default`, resolved for the principal and the action and
  decided one argument at a time. A deny-set is matched against what a value *contains* as well
  as against the value itself, so wrapping a forbidden value in a list does not get it past.
- **Narrow-and-continue instead of refuse.** A proposed value the principal may not have is
  rejected and their own default fills the gap, so the call proceeds. It is reject-and-refill
  rather than a clamp: the bound a value breached is never substituted for it. With no default
  the argument is dropped, and if nothing the caller supplied survives the call is refused with
  `NoValidArguments` — narrowing refines a proposal, it does not invent one.
- **Policy-supplied defaults, checked like everything else.** A default fills an argument the
  caller omitted *and* one that was just dropped, and is itself checked against the constraint
  governing it and withheld if it fails, so omitting an argument is not a way around its rule. A
  constraint nothing could satisfy — an uncompilable pattern, a minimum above a maximum, an
  allow-set member the other rules reject, a default the constraint would refuse — is refused at
  the grant write rather than found by whoever calls next.
- **A governed parameter cannot quietly take its value from the function definition.** Where a
  parameter has no surviving value, Python would fill the slot from the callable's own signature,
  which no constraint ever saw. One that satisfies its constraint is named in
  `signature_defaults`; one that does not refuses the call with `SignatureDefaultRejected`, whose
  `declared` flag says whether the rule was reviewed policy or the principal's own grant.
- **Argument ceilings, declared in reviewed policy text.** A `@constraints` annotation on a Cedar
  `permit` carries `{argument: {rule: value}}` and says what *anybody* may pass for that action.
  Ceilings and grants intersect and can only narrow — allow-sets intersect, deny-sets union,
  bounds move inward, `required` is sticky, two patterns must both match — and a ceiling may not
  set a `default`, because per-principal values stay in the store. Declarations are checked at
  load, since Cedar does not type-check annotation values, and a policy set declaring any ceiling
  refuses an engine failure rather than proceeding unbounded. A ceiling is the one declaration a
  policy can make that reaches narrow-and-continue rather than the gate.
- **An envelope that reports the outcome, not only the exceptions.** Every decision reports what
  was processed, rejected, defaulted and withheld, trimmed by `verbosity`, plus `narrowed`,
  `narrowed_arguments` and `guidance` — a narrowed call *succeeds*, on values the principal is
  entitled to, and reporting only its exceptions describes that success in the vocabulary of a
  failure. Those three name no value and no policy id, so a caller who may not be told *what* was
  narrowed is still told *that* the result is good. It arrives as the `_authz` key on a mapping
  return, via `last_envelope()` for any other return type, and out of band per boundary:
  `x-sentrykit-narrowed` response headers, MCP `_meta` keys with an appended text block, and a
  Pydantic-AI `ToolReturn` that displaces no data.
- **A refusal says which kind it is**: `AuthzDenied` for a policy denial, `NoContext` for no
  principal, and `NoValidArguments`, `DefaultUnavailable`, `ArgumentRejected`,
  `SignatureDefaultRejected`, `ReservedKey` and `ValidationFailed` for the argument layer.
  `fail_mode` arbitrates engine failure alone: a denial and a missing principal deny either way.
- **Relationships resolved by Cedar's entity hierarchy.** Nested relationships spanning entities
  — user → team → division → project → resource, delegation, on-behalf-of, expiry,
  break-the-glass — resolve deterministically rather than through a ladder of application `if`
  statements, so a policy names only the far end of a chain and severing one edge ends the access.
- **A masked, hash-chained audit trail.** One record per decision and per admin mutation: the
  principal's effective attributes at decision time, the arguments proposed, processed, rejected
  and defaulted, the policies that decided, and a `policy_set_hash` pinning the record to the
  exact policy text. Sensitive values are masked *before* the append-only write, never at report
  time — `redact`, `partial`, `hmac` or `tokenize`, chosen by a Cedar obligation, an
  `Annotated[..., Sensitive(...)]` marker or the configured default, with keyed HMAC the default
  because it alone lets an auditor correlate records without the store holding the value; a
  principal's own allow-set, deny-set and pattern are masked the same way. Each record's hash
  covers its predecessor's, so `verify_chain` catches an edited record and a deleted one, and a
  record a sink refused is admitted by the next that lands, so an outage cannot read as an intact
  window. Tampering is detected, not prevented.
- **Four context providers, each one extra line of wiring.** `FastAPIProvider` (pure-ASGI
  middleware, an `async` context dependency, error handlers, `protect_app`), `FlaskProvider`
  (`before_request` / `teardown_request`, `protect_app`, `protect_blueprint`), `MCPProvider`
  (middleware around `tools/call`, `governed_tool`, `protect_server`) and `PydanticAIProvider`
  (`RunContext.deps` bridged to ambient context, `governed_tool`, `tool_adapter`, `tool_prepare`,
  `tool_filter`). Each establishes the principal at the boundary and renders a refusal in that
  boundary's vocabulary; one built with no `identify=` warns once, because its own fallback ends
  at something the request supplies.
- **Per-caller tool manifests, filtered by the decision that enforces the call.** A tool is
  hidden from a principal if and only if invoking it would be refused. Hiding is a courtesy to
  the model and never the control: a client that skips the manifest and calls a hidden tool by
  name is refused the same. Arguments policy supplies are re-advertised as optional, so a model
  can omit them and receive its own defaults.
- **A Cedar policy pack, shipped as data.** Eight domain-neutral patterns — `rbac`, `groups`,
  `ownership`, `delegation`, `expiry`, `break-glass`, `separation-of-duties`, `jit-elevation` —
  under a `pack://` DSN, composed through the same union as your own directory. None names a
  role, a resource type or an action: the resource declares what it requires and the grant store
  supplies the principal's edges. Half the pack **forbids**, and that half is what contains
  rather than permits — reopening an emergency-only resource demands an entitlement, the flag
  *and* a justification, because a permit conditioned on a caller-supplied boolean alone
  authorizes anyone. The schema is opt-in, `link_template` makes a time-boxed grant from a Cedar
  template, and the pack ships no permit for the admin actions: a library does not get to ship
  the rule that hands out authority.
- **Four extension points, one mechanism.** Policy sources, grant stores, audit sinks and context
  providers are each a `Protocol`, a DSN, a `register_*` decorator and an entry point, so a
  third-party backend is indistinguishable from a built-in. Shipped: `file://` and `pack://`
  policy sources, `memory://` and `jsonfile://` grant stores, `memory://` and `jsonl://` audit
  sinks. Pass a list instead of one DSN and the composite satisfies the same `Protocol` — sources
  union, grant stores merge or route by namespace, sinks fan out.
- **The `sentrykit` command line**, over `argparse` and no added dependency. `policy validate`
  type-checks a directory against its schema, groups errors by `@id` and exits non-zero, so it
  belongs in CI. `grant`, `revoke` and `grants` are the admin surface, each a protected callable
  decided by the same governor the application uses — built from the policy-processed arguments
  and not from `argv`, so a policy governs who may administer grants *and which grants they may
  make*. `audit-report` windows a sink into markdown, aggregating by outcome, with a tamper
  verdict and its own mutations section.
- **Five runnable examples over one shared domain.** An orders-and-refunds desk modelled
  identically as a FastAPI app, a Flask app, an MCP tool server and a Pydantic-AI agent — the
  same protected callables, the same reviewed `.cedar` directory and the same grant data, so only
  the boundary wiring differs — each driving its flows against a seeded database and printing
  what policy did to every call. The fifth proposes nine named attacks, from exfiltration by
  `limit` and an instruction planted in a ticket thread to a destructive call whose damage sits
  in its Python default, and runs each twice over the same function bodies: once past the policy
  and once around it. Three of the nine the gate does not win, and they are in the suite on
  purpose — a layer that ships only the cases it wins describes a feature, not a boundary.
- **Python 3.11, 3.12 and 3.13**, on a typed, documented public API: `mypy --strict` over the
  package, `py.typed` in the wheel, and the docstrings the API reference is generated from. The
  extras install only what a boundary needs — `fastapi`, `flask`, `mcp`, `pydantic-ai`, `web`,
  `agents`, `all` — and the one core pin worth knowing about is `cedarpy >= 4.8, < 5`, the floor
  exposing the parse-once API the engine is built on. The documentation is published twice: as a
  browsable site tracking the current code, and attached to each release as HTML, a PDF,
  `llms.txt` and `llms-full.txt` — the last meant to be sufficient on its own — frozen at the
  version you installed.
