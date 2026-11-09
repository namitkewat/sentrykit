# CLAUDE.md — operating guide for building sentrykit

This file is the contract for any coding-agent session working in this repo. Read it
fully before doing anything. The detailed, phase-by-phase plan lives in
`dev-docs/implementation.md`; the "why" behind the shape lives in
`dev-docs/architecture.md` and `dev-docs/design-decisions.md`; the rules you code by
live in `dev-docs/*-standards.md` — including
`dev-docs/documentation-standards.md`, which governs everything you write down.

---

## 1. What sentrykit is (keep this framing in every decision)

sentrykit is a **lightweight, framework-agnostic authorization layer** for Python. It
sits at the **action layer** — *pre-action authorization* — and decides, per call,
whether a principal may invoke a protected callable, **which arguments** they may pass,
and **which defaults** to inject when they pass none. It is built on **AWS Cedar** (via
the `cedarpy` binding) and it targets two worlds with one decorator:

- **Web frameworks:** FastAPI, Flask (Django/Litestar/Starlette later).
- **Agent tooling:** MCP tool servers, Pydantic-AI (LangChain/others later).

The one idea:

> The LLM (or the caller) *proposes*; the **policy decides** — and what it decides
> includes the **arguments**, not only the call.

That second clause is the product. Cedar answers a boolean question at the gate; everything
sentrykit adds sits above that answer, and it is what a host would otherwise assemble itself:

1. **Per-(principal, action) argument constraints** — allow-sets, deny-sets, patterns and
   numeric bounds, decided per argument.
2. **Narrow-and-continue instead of refuse.** A value above what the principal may have is
   rejected and their own default fills the gap, so the call proceeds. It is
   reject-and-refill, **never a clamp to the bound** — no sentence anywhere may imply the
   resulting value equals the maximum. With no default the argument is dropped; if nothing
   the caller supplied survives, the call is refused with `NoValidArguments`.
3. **Policy-supplied default injection**, for arguments the caller omitted *and* for ones
   that were just dropped. A default is itself checked against the constraint that governs
   it, so omitting an argument is not a way around the rule on it.
4. **Grant-time constraint validation.** A constraint no value could satisfy, or whose own
   default it would reject, is refused when a store writes it rather than discovered by
   whoever calls next.
5. **A masked, hash-chained audit trail** — one record per decision and per admin mutation,
   masked before the append-only write and pinned to a hash of the exact policy text.

Sitting across the first four: an **argument ceiling** declared in reviewed `.cedar` text
says what *anybody* may pass for an action and intersects with the store's per-principal
grants, so the reviewed file states the maximum and can only narrow. A ceiling is the one
declaration that reaches narrow-and-continue at all, because Cedar's effect vocabulary is
permit/forbid (ADR-028).

**Relationship resolution is a supported capability that composes, not the headline.**
Complex, nested authorization relationships that span multiple calls and entities — user →
team → project → resource, delegation chains, on-behalf-of, expiry, break-the-glass — are
resolved **deterministically by Cedar's entity hierarchy**, never inferred by a model or
scattered across `if` statements. That is Cedar's strength and sentrykit inherits it: the
foundation the argument layer stands on, rather than the thing that distinguishes sentrykit
from the engine underneath (ADR-008, amended).

Positioning we are committed to: **self-hosted, framework-agnostic (web *and* agents),
Cedar-based, audit-first, one decorator.** We are not a content filter and not an output
validator. We refuse the *side effect* before it happens. Where a comparison genuinely helps
a reader, name another project's **capability** and never a verdict — general-purpose policy
engines and relationship systems answer allow/deny at the gate, and sentrykit adds the layer
above that answer. No comparison tables, no scorecards, no "unlike".

---

## 2. Hard rules (non-negotiable)

1. **Commit messages contain NO agentic-tool references.** No mention of any AI assistant,
   model, or "generated with / by" attribution, no `Co-Authored-By` trailers naming a
   tool, no emoji robots. Use **Conventional Commits** only:
   `type(scope): subject` where type ∈ {build, chore, ci, docs, feat, fix, perf, refactor,
   revert, style, test}. This is enforced mechanically by `scripts/check_commit_msg.py`
   (wired as a `commit-msg` hook). Do not bypass hooks. Write commit messages as a human
   engineer would.
2. **The core imports no web framework and no agent SDK.** `sentrykit.engine`,
   `sentrykit.decorator`, `sentrykit.context`, `sentrykit.cedar`, `sentrykit.constraints`,
   `sentrykit.envelope`, `sentrykit.errors`, `sentrykit.config` must have zero imports of
   fastapi/flask/starlette/mcp/pydantic_ai. Those only appear under
   `sentrykit/integrations/*` and `examples/*`, behind optional extras.
3. **Everything pluggable is a plugin.** Stores, sinks, policy sources, and framework
   context providers are discovered via `importlib.metadata.entry_points` and addressed by
   name/DSN. Built-ins and third-party packages must be indistinguishable to the core.
4. **Policies-as-code, grants-as-data.** Cedar *policy logic* is authored in files and
   reviewed via version control. *Grants/assignments* (roles, memberships, per-user
   argument constraints, expiries) are mutable data in a store. The admin surface only ever
   mutates data; it never rewrites reviewed policy logic at runtime.
5. **Fail closed.** No principal / no matching policy / unavailable audit sink (when
   configured strict) ⇒ deny. Default deny is Cedar's model and ours.
6. **Mask upstream of the immutable write.** Sensitive values are masked *before* they are
   handed to an append-only audit sink — never at read/report time. Reversible mappings
   (tokenization) never live in the audit store.
7. **Typed and documented.** Public API is fully type-annotated (mypy strict) and carries
   docstrings. No `Any` on public signatures without justification.

---

## 3. Environment: pixi (assume it is installed)

All environments and helper commands are defined in `pixi.toml`. Do **not** create ad-hoc
venvs or call `pip install` directly; add dependencies through pixi so they are locked.

```bash
pixi install                 # solve + create the default env
pixi run setup               # install pre-commit hooks (incl. the commit-msg gate)
pixi run -e all check        # full gate: format-check, lint, typecheck, tests+cov, docs
```

Environments: `default` (core+dev), `web` (adds FastAPI/Flask), `agent` (adds
mcp/Pydantic-AI), `all` (everything). Run integration work in the environment that has
the relevant extra, e.g. `pixi run -e web test-integration`.

Key tasks (see `pixi.toml` for the full list): `fmt`, `lint`, `typecheck`, `test`,
`test-cov`, `test-unit`, `test-integration`, `test-scenarios`, `run-fastapi`, `run-flask`,
`run-mcp`, `run-agent`, `policy-validate`, `audit-report`, `docs`, `docs-serve`, `check`,
`ci`, `build`, `clean`.

---

## 4. The implementation loop (apply per phase, repeat 2–3×)

Every phase in `dev-docs/implementation.md` is executed with this loop. Do not skip a step.

1. **Research** — read the relevant sections of `dev-docs/architecture.md` and
   `dev-docs/design-decisions.md`; confirm current library APIs (cedarpy, mcp v2,
   pydantic-ai, pixi schema) against what is actually installed before coding. Note findings
   in the phase's working notes.
2. **Build / implement** — write the modules for the phase, following
   `dev-docs/coding-standards.md`.
3. **Test** — write and run tests in `tests/` (`unit/`, `integration/`, `scenarios/`) per
   `dev-docs/testing-standards.md`, and build/refresh the minimal example apps under
   `examples/` for the frameworks in scope so behavior is exercised end-to-end.
4. **Review** — check the work against the original goal in §1 and the phase's acceptance
   criteria. Ask explicitly: does this preserve the positioning, the plugin boundaries, and
   the audit invariants? Record gaps.
5. **Fix & document** — apply fixes, then update docs in the same pass, per
   `dev-docs/documentation-standards.md`: user docs in `docs/`, the docstrings the API
   reference is generated from, internal docs in `dev-docs/`, `README.md` and `CHANGELOG.md`.
   Then **rebuild the docs** — `pixi run docs` — so the HTML, the PDF and both `llms.txt`
   files reflect what just changed; regenerating `llms.txt` is part of documenting, not a
   release chore, because it is generated *from* the docs and stale output disagrees with the
   pages it came from. Shipped text describes the present: no phase numbers, ADR citations or
   references to how the code was built (`dev-docs/` and `CHANGELOG.md` hold that history).
   Docs are part of "done," not a follow-up.
6. **Repeat** — run the loop again (2–3 iterations total per phase) until acceptance
   criteria pass and `pixi run check` is green.

Commit at meaningful checkpoints within a phase (after each green loop iteration is a good
cadence), following the commit rule in §2.

---

## 5. Sub-agent orchestration (keep the main session lean)

The main session is the **orchestrator**. It holds the plan and the integration state, not
the line-by-line implementation. For each phase:

- Decompose the phase into 2–4 **independent workstreams** (they are listed per phase in
  `dev-docs/implementation.md`). Typical split: one workstream per module cluster or per
  framework adapter, plus one for tests/examples.
- Dispatch each workstream to a **sub-agent** with a tight brief: the exact files it owns,
  the interfaces it must implement or consume (copied verbatim so it needs no extra
  context), the tests it must make pass, and the acceptance criteria. Sub-agents should not
  touch files outside their ownership set.
- Sub-agents return a **short summary** (what changed, key decisions, any interface
  deviations). The main session integrates, runs `pixi run check`, performs the review
  step, and keeps only the distilled result in context — not the full transcripts.
- Only the main session commits, so commit messages stay consistent and rule-compliant.

This keeps the main session's context small enough to carry all phases in one session.

---

## 6. Definition of done (per phase and overall)

A phase is done when: its acceptance criteria (in `dev-docs/implementation.md`) pass;
`pixi run check` is green in every relevant environment (it builds the HTML docs under `-W`,
so a documentation warning fails the gate); new/changed public API is typed and documented;
`docs/`, `dev-docs/`, and `README.md` reflect the change and satisfy
`dev-docs/documentation-standards.md`; `pixi run docs` produces HTML, PDF, `llms.txt` and
`llms-full.txt` cleanly, with `llms-full.txt` still sufficient to implement against on its
own; and the example apps for in-scope frameworks run.

The project is done when all phases are done, the four example apps (FastAPI, Flask, MCP
server, Pydantic-AI) each demonstrate gate + argument filtering + default injection + a
denial + the audit envelope, the attack/defence suite under `examples/scenarios/` runs every
scenario through both arms with the three it does not win still in it, the shipped Cedar policy
pack's patterns each have a passing scenario test, and `pixi run build` produces installable
artifacts with working extras.

---

## 7. Repo map

```
CLAUDE.md                     ← you are here
README.md                     ← user-facing overview (auto-maintained)
CHANGELOG.md                  ← keep-a-changelog
pixi.toml                     ← environments + governance tasks
pyproject.toml                ← packaging, extras, entry-point groups, tool config
.pre-commit-config.yaml       ← ruff, mypy, commit-message gate
scripts/check_commit_msg.py   ← mechanical commit-rule enforcement
SECURITY.md                   ← disclosure contact + what sentrykit does and does not defend
dev-docs/                     ← internal: architecture, decisions, standards, the plan
docs/                         ← user docs (Sphinx + MyST → HTML, PDF, llms.txt, llms-full.txt)
brand/                        ← social-preview cards + the palette (dev-only, `pixi run -e art brand`)
src/sentrykit/                ← the library (core has NO framework imports)
  stores/                     ← PolicySource / GrantStore / AuditSink + reference impls
  policy/pack/                ← shipped Cedar policy pack + schema (data)
  integrations/               ← fastapi, flask, mcp, pydantic_ai (behind extras)
tests/{unit,integration,scenarios}/
examples/desk/                ← the seeded SQLite orders desk the examples query
examples/{fastapi_app,flask_app,mcp_server,pydantic_ai_agent}/
examples/scenarios/           ← nine attacks, each run governed and ungoverned
```

When in doubt, prefer the smaller, more deletable change; prefer clarity over cleverness;
and keep the thin core thin.
