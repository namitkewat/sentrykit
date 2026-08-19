# Release-hardening working notes — the documentation system

Measured against the installed environment on 2026-08-19 (pixi 0.70.2, CPython 3.13,
`sentrykit` 0.1.0). Every version and every behaviour below was executed, not recalled: the
probe was a throwaway venv built from the pixi interpreter, plus a two-page Sphinx project
containing a MyST page, a toctree and an `autofunction` directive.

The question this note answers is narrow. The library is finished; what is not finished is
the thing a reader receives. `mkdocs-material` builds a *site*, and a private repository has
nowhere to host one — so the docs have to become **files that ride along with the release**:
HTML, a PDF, and the two llms.txt artifacts. That reframing is what picks every tool below.

---

## 1. Sphinx over the Markdown that already exists

`docs/` holds eight hand-written Markdown pages. Rewriting them as reStructuredText would be
a large edit that improves nothing, so the requirement is a Markdown-native Sphinx.

**Measured resolution** (one `pip install` of the whole set, no conflicts, no backtracking):

| package | version | notes |
| --- | --- | --- |
| `sphinx` | 9.1.0 | `requires_python >=3.12` — see §5, this is the one version constraint that matters |
| `myst-parser` | 5.1.0 | pins `sphinx>=8,<10`, `docutils>=0.20,<0.23` |
| `furo` | 2025.12.19 | pins `sphinx>=7,<10` |
| `sphinx-markdown-builder` | 0.6.11 | MIT, `sphinx>=5.1` |
| `rinohtype` | 0.5.6 | AGPL-3.0-only, `docutils>=0.18` |
| `sphinx-autobuild` | 2025.8.25 | live-reload for `docs-serve` |
| `docutils` | 0.22.4 | resolved once, satisfies both pins |

Every one of them ships a `py3-none-any` wheel, so the four platforms in `pixi.toml`
(`linux-64`, `osx-arm64`, `osx-64`, `win-64`) get identical bits and nothing needs a compiler.

**Theme: furo.** Chosen over `pydata-sphinx-theme` for the reason that decides most theme
questions — furo is a single-project theme with no configuration surface to get wrong, while
the pydata theme's navbar and sidebar machinery is aimed at multi-package scientific docs we
do not have. Both build clean; furo is the smaller thing to keep working.

**A measured `-W` build succeeded** with `myst_parser` + `autodoc` + `autosummary` +
`napoleon` + `viewcode` on Sphinx 9.1. `-W` is therefore usable as a gate rather than an
aspiration.

### The one hazard `-W` introduces: autodoc in an environment without the extras

`pixi run check` runs in four environments, and three of them deliberately lack some of the
framework packages. `autodoc` on `sentrykit.integrations.fastapi` in the `default`
environment raises `ImportError`, which Sphinx reports as a **warning**, which `-W` turns
into a failed gate — so the docs would only build in `all`, which is exactly the environment
where a docs break is least likely to be noticed.

The fix is `autodoc_mock_imports`, computed rather than hard-coded:

```python
autodoc_mock_imports = [
    name for name in ("fastapi", "flask", "starlette", "werkzeug", "mcp", "pydantic_ai")
    if importlib.util.find_spec(name) is None
]
```

Mocking only what is genuinely absent means the `all` environment — the one the release is
built from — documents real signatures, while the other three still build the same page set
clean. Mocking unconditionally would degrade the released HTML to satisfy a check.

---

## 2. PDF: rinohtype, not `latexpdf`

Both were assessed against one criterion: *does it build unattended, on every platform in the
manifest, without a second package manager?*

**`sphinx-build -M latexpdf` needs a LaTeX toolchain.** On Ubuntu CI that is an
`apt-get install texlive-latex-recommended texlive-latex-extra texlive-fonts-recommended
latexmk` — roughly a gigabyte and several minutes, cached badly, and entirely outside pixi.
On `win-64` — which is in the platform list and is where this repository is developed —
conda-forge has no full TeX Live, so `pixi run docs-pdf` would simply not exist for the
maintainer. A release asset that only a specific CI runner can produce is an asset that
silently stops being produced.

**`sphinx-build -b rinoh` needs nothing.** rinohtype is pure Python with bundled fonts.

**Measured, on Windows, in the probe project:**

```
$ sphinx-build -b rinoh probe/src probe/out/pdf
rinohtype 0.5.6 (2026-05-15)
rendering... (two passes, converged)
Writing output: probe/out/pdf/sentrykit.pdf
build succeeded.
```

697 KB for three pages — most of that is embedded TeX Gyre / DejaVu font subsets, so it is a
fixed cost the real document amortises rather than a per-page one.

> **Decision.** `rinohtype`. The tradeoff is real and worth stating plainly: LaTeX output is
> typographically better, and rinohtype prints three cosmetic font-fallback notices
> ("TeX Gyre Pagella does not include a normal medium upright font") on every run. Those go to
> stdout, not through Sphinx's warning machinery, so they cannot affect `-W`. Paying that for
> a builder that runs identically on a laptop and on a runner is the right trade for a
> documentation asset; if the PDF ever becomes a typeset deliverable rather than a reference
> dump, revisit it.
>
> **License note:** rinohtype is **AGPL-3.0-only**. It is a build tool that is never imported
> by, linked into, or shipped inside the wheel — the same relationship the project has with
> `ruff` or `mypy` — so it does not reach sentrykit's Apache-2.0 licensing. It is therefore a
> `dev` feature dependency only, and must never appear in `[project.optional-dependencies]`.

`docs-pdf` stays **out of the `check` gate** and lives in the release flow: it is the slowest
step by a wide margin, and a PDF that fails to render is a release-blocking problem, not a
commit-blocking one.

---

## 3. llms.txt: a post-build script, because the maintained extension emits the wrong thing

`sphinx-llms-txt` 0.7.1 exists, is maintained, and installs cleanly. It was measured, and it
is **not** usable here.

It emits both files during the HTML build, correctly shaped:

```
# sentrykit

> A lightweight authorization layer.

## Docs

- [sentrykit](/_sources/index.md.txt)
- [Page two](/_sources/page2.md.txt)
```

But it builds `llms-full.txt` by concatenating **`_sources`** — the raw MyST input — so the
probe's output contained the literal, unrendered text of a `toctree` directive and of an
`autofunction` directive rather than the module documentation that directive stands for.

That is the requirement inverted. `llms-full.txt` has to be *self-sufficient for someone
implementing against sentrykit from that file alone*, and the single most important thing in
it is the API reference — which in a `_sources` concatenation is an unexpanded directive.
The link targets are also site-absolute (`/_sources/...`), which presumes a hosted site this
private repository does not have.

**The alternative, measured.** `sphinx-markdown-builder` 0.6.11 renders the *resolved
doctree* to Markdown, so autodoc is expanded — the same probe produced a real
`### json.dumps(obj, *, skipkeys=False, ...)` heading with the full docstring under it,
where the extension produced the raw directive.

Clean Markdown, real signatures, real docstrings. It emitted one warning on the probe
(`unknown node type: <abbreviation>`), which is why the markdown build runs **without** `-W`
— only the HTML build gates.

> **Decision.** `sphinx-build -b markdown` into an intermediate directory, then
> `scripts/build_llms_txt.py` concatenates it. Owning the concatenation is what buys the two
> things the extension cannot give: control of page **order** (concepts before API reference,
> not alphabetical), and link targets that name the sibling release asset rather than a URL
> on a site that does not exist.

### The spec the script implements

`llms.txt` is a file at a known location that gives an LLM a curated, plain-Markdown map of a
project instead of leaving it to scrape rendered HTML. Its structure is fixed:

1. An **H1** — the project name. Required, and the only required element.
2. A **blockquote** immediately after it — a short summary carrying enough context to
   understand the rest of the file.
3. Optional prose (no headings) elaborating.
4. Zero or more **H2 sections**, each containing a Markdown list of
   `[name](url): optional description` links. A section named `## Optional` is the one with
   defined semantics: its links may be skipped when a shorter context is needed.

`llms-full.txt` is the companion convention rather than part of the spec proper: the entire
documentation corpus flattened into one clean-Markdown file, so an agent can read the whole
thing in a single fetch with no navigation at all. Ours is the eight prose pages plus the
generated API reference, in reading order.

---

## 4. Removing mkdocs is clean

`mkdocs`, `mkdocs-material` and `mkdocstrings` appear in exactly two places —
`[feature.dev.pypi-dependencies]` in `pixi.toml` and the `docs` / `docs-serve` tasks — plus
`mkdocs.yml` and the gitignored `site/` output. Nothing in `src/`, `tests/` or `examples/`
imports or references them; no docstring is written to a mkdocstrings-specific syntax (the
pages are plain Markdown with fenced code, which MyST reads unchanged). `scripts/clean.py`
already removes `site/`, and keeps doing so harmlessly.

The one substantive difference in the source pages: **every page must be reachable from a
toctree**, or Sphinx warns and `-W` fails. The mkdocs `nav:` key was optional; a Sphinx
toctree is not. That is a change to `docs/index.md` only.

---

## 5. The Python-version matrix, and why `sphinx>=9` is the pin

The CI matrix runs 3.11, 3.12 and 3.13. The Sphinx floor moved mid-series:

| Sphinx | requires_python |
| --- | --- |
| 8.1.3 | `>=3.10` |
| 8.2.0 – 9.0.4 | `>=3.11` |
| **9.1.0** | **`>=3.12`** |

So a 3.11 environment resolves **Sphinx 9.0.4** and a 3.12/3.13 environment resolves
**9.1.0**. Both are Sphinx 9 — same extension API, same builder names, same `-W` semantics —
so a single `sphinx>=9,<10` pin gives one configuration that works across the whole matrix,
and no version-conditional code in `conf.py`. `myst-parser` 5.1.0 (`>=3.11`) and every other
package in §1 clear 3.11 comfortably.

Varying the interpreter *inside* pixi needs the version to be a feature: `py311`/`py312`/
`py313` features pinning `python`, crossed with the four existing feature sets to give twelve
named environments (`py311-default` … `py313-all`) alongside the four unversioned ones a
developer actually types. The alternative — running the matrix outside pixi with bare venvs —
would test a dependency set that is not the one the lock file describes, which is most of the
value of having a lock file.

---

## 6. Decisions taken, in one place

1. **Sphinx 9 + MyST-Parser + furo**, consuming `docs/*.md` unchanged; `autodoc` +
   `autosummary` + `napoleon` generate the API reference from the docstrings that already
   exist (§1).
2. **`autodoc_mock_imports` is computed from what is missing**, so the same page set builds
   `-W`-clean in all four pixi environments (§1).
3. **rinohtype for the PDF** — pure Python, every platform, no LaTeX; AGPL is confined to the
   dev environment and never reaches the wheel; kept out of `check` (§2).
4. **llms.txt and llms-full.txt come from `sphinx-build -b markdown` plus
   `scripts/build_llms_txt.py`**, not from `sphinx-llms-txt`, because the extension
   concatenates unrendered sources and the API reference must be expanded (§3).
5. **mkdocs is removed outright** — deps, tasks and `mkdocs.yml`; the only source change it
   forces is a complete toctree in `docs/index.md` (§4).
6. **`sphinx>=9,<10`**, which is the one pin that spans 3.11–3.13 without conditionals (§5).

## 7. Frozen: task names and output layout

Sub-agents build against these; they are the coordination point and do not change.

| task | command | writes |
| --- | --- | --- |
| `docs-html` | `sphinx-build -W -b html -d dist/docs/.doctrees/html docs dist/docs/html` | `dist/docs/html/` |
| `docs-pdf` | `sphinx-build -b rinoh -d dist/docs/.doctrees/pdf docs dist/docs/pdf` | `dist/docs/pdf/sentrykit.pdf` |
| `docs-markdown` | `sphinx-build -b markdown -d dist/docs/.doctrees/markdown docs dist/docs/markdown` | `dist/docs/markdown/` (intermediate) |
| `docs-llms` | `python scripts/build_llms_txt.py` (after `docs-markdown`) | `dist/docs/llms.txt`, `dist/docs/llms-full.txt` |
| `docs` | aggregate of `docs-html`, `docs-pdf`, `docs-llms` | all of the above |
| `docs-serve` | `sphinx-autobuild docs dist/docs/html` | live-reload preview |
| `docs-clean` | `python scripts/clean.py --docs` | removes `dist/docs` |

The `-d` flags were added after the first full build measured the result: Sphinx defaults its
doctree cache to `<outdir>/.doctrees`, which put 7.8 MB of pickled parse state inside the
12.4 MB HTML tree the release zips and hands to a reader. Moved out, the site is 4.6 MB.

Two build by-products are left where they land, deliberately. rinohtype writes a 17 MB
`sentrykit.stylelog` and a `sentrykit.rtc` next to the PDF; both are under `dist/`, both go
with `docs-clean`, and the release attaches `sentrykit.pdf` by name rather than zipping the
directory — so the cost is disk on a build machine and nothing else.

`check` depends on `docs-html` (not `docs`), so documentation breakage fails the gate without
paying for a PDF on every commit.

**Release assets**, by path:

```
dist/sentrykit-<version>-py3-none-any.whl
dist/sentrykit-<version>.tar.gz
dist/docs/sentrykit-docs-html-<version>.zip   (zipped from dist/docs/html/)
dist/docs/pdf/sentrykit.pdf
dist/docs/llms.txt
dist/docs/llms-full.txt
```
