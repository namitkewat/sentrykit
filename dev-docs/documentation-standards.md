# Documentation standards

Documentation is part of "done", never a follow-up. This file says what "documented" means
here, and it is deliberately narrow: two rules about *what* the text says, and one build that
produces *what a reader receives*.

---

## 1. The split: shipped text describes the present, dev-docs holds the history

This is the rule that gets violated most easily, because it feels helpful to write "the
delegation pattern added in phase 4" or "see ADR-019". It is not helpful to the person it
reaches.

**Shipped text** — every docstring and comment in `src/`, every comment in the policy pack's
`*.cedar` files, every page under `docs/`, `README.md`, `SECURITY.md`, and the example apps —
**describes the current state of the code in the present tense, self-contained.** A reader who
`pip install`s the wheel has none of this repository: no `dev-docs/`, no ADR list, no phase
plan, no commit history. A pointer to any of those is a dangling reference to them.

Concretely, none of these belong in shipped text:

- `phase N` / `Phase N` in any casing — including "the phase 2 docs", "built in phase 4".
- `ADR-0NN` citations.
- Sub-agent labels (`SA-A`, `SA-B`, …), "the frozen contract", "the brief", "the plan".
- Pointers to `dev-docs/notes/*.md`.
- Anything else that describes *how the code came to be* rather than what it does.

**`dev-docs/` and `CHANGELOG.md` are the historical record and are exempt.** They are where
"we tried the obvious thing and measured that it permitted anyone" is *supposed* to live. Never
gut an ADR or a phase note to satisfy this rule — the rule is about audience, not about
deleting history.

### What replaces a stripped reference

Not nothing. The reason a citation existed is usually a real reason, and it has to survive as a
statement:

| Instead of | Write |
| --- | --- |
| `...carries its refusal out in an MCPError (ADR-019).` | `...carries its refusal out in an MCPError, the one exception type mcp re-raises rather than swallowing.` |
| `See ADR-017.` | The one-line claim ADR-017 makes, stated here. |
| `The examples the Phase 2 docs added.` | `The examples in the policy, audit and plugin docs.` |

A sentence that is *only* a citation is the worst case: it costs the reader a lookup they
cannot perform and gives them nothing. Inline the claim.

### The check

```bash
grep -rniE 'phase [0-9]|ADR-[0-9]|SA-[A-D]\b|frozen contract|the brief|the plan' \
  src/ tests/ docs/ examples/ README.md
```

Nothing. `dev-docs/` and `CHANGELOG.md` are excluded on purpose.

Tests count as shipped text for this rule even though they are not installed: they are the
first thing a contributor reads to learn what a behaviour is supposed to be, and a test whose
docstring explains which phase wrote it explains nothing about the behaviour.

## Measured figures in shipped text

A number is a citation too, and it fails the same way. `research/` is gitignored and is not in
the distribution, so a precise experimental figure in `src/`, `docs/`, `examples/`, `tests/` or
`README.md` points a reader at a harness they do not have. They cannot check it, cannot re-run
it, and cannot tell when it has gone stale.

**In shipped text, state the magnitude in words and keep the direction. Put the figure in
`CHANGELOG.md`, `dev-docs/` or `research/out/`, where the harness is named.**

| Instead of | Write |
| --- | --- |
| `that happened in four of seven narrowed calls` | `that happened in roughly half of narrowed calls` |
| `served data in 22 of 28 runs against 14 of 28` | `served the result markedly more often than the exceptions-only envelope did` |
| `0 of 28 models retried in bounds` | `no model in the panel relayed the data it retrieved` |

Two failures this rule exists to prevent, both of which happened:

1. **A single sample read as an aggregate.** `four of seven` was one run of seven models. The
   pooled figure over four samples is near enough one in two, so the shipped sentence was both
   unverifiable and wrong, in three shipped files and the generated `llms-full.txt`.
2. **A direction asserted without the test that was applied elsewhere.** Prose carries a claim
   with no digits in it — *"does worse still"*, *"at least as strong a signal"* — and such a
   sentence survives a grep for numbers. If a comparison is worth stating, it is worth testing;
   if it has not been tested, say *appears to* and nothing stronger.

### The check

```bash
# 1. a measurement is being announced -- read the whole paragraph it opens
grep -rniE 'measured (across|on|against)|in (live|real) runs|does worse|at least as strong|\
strongest signal|net negative' src/ tests/ docs/ examples/ README.md
# 2. a ratio of model runs, including spelled-out ones
grep -rniE '[0-9]+ ?/ ?[0-9]+ (runs|calls|models|samples)|[0-9]+ of [0-9]+ (runs|calls|models|samples)|\
(two|three|four|five|six|seven|eight) (language )?models' src/ tests/ docs/ examples/ README.md
```

**Grep 1 is the one that works, and it has no numbers in it.** Both real escapes —
*"does worse still"* and *"at least as strong a signal"* — carried a withdrawn comparison with
no digit anywhere in the sentence, so any number-shaped pattern runs clean over them.
`measured across` is the tell: it is how a sentence announces a measurement and then declines to
let you check it. Read the paragraph each hit opens, not the line.

Grep 2 is the backstop and needs judgement, not a zero exit. It must stay anchored to run/model
nouns: unanchored, `[0-9]+ of [0-9]+` and `four of them` match ordinary prose across the source
tree — `maximum of 750` in an example payload, `two of them share a name` in a store docstring,
`7 of 7` in the audit docs (a hash-chain result the library computes itself). Those are data and
behaviour, not measurements of a model. What you are hunting is a figure whose only provenance
is the gitignored harness.

---

## 2. Comments and docstrings explain *why*

Unchanged from `coding-standards.md`, restated because it is half of what makes rule 1 work:
document the reasoning, not the mechanics the code already states. Google-style docstrings on
every public module, class and function. If a stripped history reference leaves a sentence
saying nothing, the fix is to write down the reasoning it was standing in for — not to delete
the sentence.

---

## 3. The docs are Sphinx, and they produce four artifacts

The repository is private, so there is nowhere to host a documentation *site*. Documentation
is therefore a set of **files attached to each release**, and the toolchain is chosen for that:

| what | how | why |
| --- | --- | --- |
| HTML | `sphinx-build -W -b html` + furo | the browsable form |
| PDF | `sphinx-build -b rinoh` (rinohtype) | one file, offline, no LaTeX toolchain on any platform |
| `llms.txt` | `scripts/build_llms_txt.py` | the curated map, per the llms.txt spec |
| `llms-full.txt` | same script, over `sphinx-build -b markdown` | the entire corpus in one file |

Source is the Markdown already under `docs/`, read by MyST-Parser. The API reference is
generated by `autodoc`/`autosummary` from the docstrings — which is the second reason rule 1
matters: **a docstring is a documentation page.** A phase reference in a docstring is a phase
reference on a published page.

Why the reasoning behind each tool choice is what it is — including why the maintained
`sphinx-llms-txt` extension is *not* used — is recorded in
`dev-docs/notes/release-hardening-research.md`.

### Tasks and output layout (stable; other things attach to these paths)

| task | writes |
| --- | --- |
| `pixi run docs-html` | `dist/docs/html/` |
| `pixi run docs-pdf` | `dist/docs/pdf/sentrykit.pdf` |
| `pixi run docs-markdown` | `dist/docs/markdown/` (intermediate) |
| `pixi run docs-llms` | `dist/docs/llms.txt`, `dist/docs/llms-full.txt` |
| `pixi run docs` | all of the above |
| `pixi run docs-serve` | live-reload preview |
| `pixi run docs-clean` | removes `dist/docs` |

### `check` builds the HTML under `-W`

`pixi run check` depends on `docs-html`, which runs with `-W`, so **a documentation warning
fails the gate** exactly like a lint error. That is deliberate: a broken cross-reference or a
page missing from the toctree is a defect, and the only reliable moment to catch it is the
moment it is introduced.

It also has to hold in **all four environments**. `check` runs in `default`, `web`, `agent` and
`all`, and three of them deliberately lack some framework package — so `conf.py` computes
`autodoc_mock_imports` from what is actually missing. If the docs only build in `all`, they
break in the environment nobody looks at.

`docs-pdf` is **not** in `check`: it is the slowest step by a wide margin, and a PDF that will
not render blocks a release rather than a commit.

---

## 4. `llms-full.txt` must be sufficient on its own

The bar is specific, and it is worth being literal about: **someone implementing against
sentrykit with that single file and no other access must be able to do it.** That means it
carries, at minimum:

- the concepts — the pipeline, fail-closed, the two kinds of failure;
- the quickstart, end to end;
- the public API with real signatures and real docstrings, autodoc-expanded (not a directive
  standing in for them);
- the shipped policy pack's patterns;
- context-provider usage for **both** the web and the agent side.

Check it by reading it, not by checking it exists. The failure mode is a file that is large and
complete-looking and silently missing the API reference.

---

## 5. Documenting is part of the loop, and part of a release

**Every loop iteration's "fix & document" step ends with:** the affected pages under `docs/`
updated, the affected docstrings updated, `README.md` updated if the public story changed,
`CHANGELOG.md` updated, and **`pixi run docs` re-run** so the HTML, the PDF and both llms.txt
files reflect what just changed. Regenerating llms.txt is part of documenting, not a release
chore — it is generated from the docs, so docs that changed without it are docs that disagree
with themselves.

**Every release attaches** the wheel, the sdist, the zipped HTML, the PDF, `llms.txt` and
`llms-full.txt`. The list lives in `packaging-standards.md`; the point here is that
documentation is a *release artifact* in this project, so "the docs build is broken" is a
release blocker with the same weight as "the tests fail".
