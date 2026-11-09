# Packaging standards

## Layout & build
- **src layout** (`src/sentrykit/`), build backend **hatchling**, metadata via **PEP 621** in
  `pyproject.toml`. License **Apache-2.0**. Ship `py.typed`.
- `pixi.toml` owns dev environments and governance tasks; `pyproject.toml` owns packaging.
  They intentionally list dependencies for different audiences (pip extras vs dev envs) —
  keep them consistent when versions change.

## Versioning
- **SemVer.** Pre-1.0 while the public API is unstable (`0.x`). Public API = what's exported
  from `sentrykit/__init__.py` plus the documented integration entry points. Breaking changes
  bump the appropriate component and are recorded in `CHANGELOG.md` (keep-a-changelog).

## Dependencies & extras
- **Core runtime deps are minimal:** `cedarpy`, `pydantic`, `pydantic-settings`,
  `typing-extensions`. Nothing else in the base install.
- Optional extras gate every integration and backend:
  - `sentrykit[fastapi]`, `sentrykit[flask]`, `sentrykit[mcp]`, `sentrykit[pydantic-ai]`
  - convenience: `sentrykit[web]`, `sentrykit[agents]`, `sentrykit[all]`
- A missing extra must produce a clear, actionable ImportError message (e.g. "install
  `sentrykit[fastapi]`"), never a raw `ModuleNotFoundError` from deep in the code.

## Plugin entry points (the extension contract)
Third parties extend sentrykit by publishing a `sentrykit-<name>` package that registers under
one of these groups; built-ins register the same way:
- `sentrykit.policy_sources`
- `sentrykit.grant_stores`
- `sentrykit.audit_sinks`
- `sentrykit.context_providers`

Each entry is `name = "module:Class"`. Register an entry point **when** its backend is built —
do not leave dangling references to unbuilt classes.

## Release assets
A release goes to two places. The **distribution** goes to PyPI, published by the release
workflow's own `publish` job from a `v*` tag — see ADR-037 for why that job is separate, why it
authenticates by Trusted Publishing rather than a stored token, and what has to be configured
on PyPI once for it to work. Everything a reader needs that PyPI has no place for — the HTML,
the PDF and both `llms.txt` files — is attached to the **GitHub release**, because the
repository is private and there is no hosted documentation site.

Six assets go on the release, and every one of them is attached:

| asset | produced by |
| --- | --- |
| `sentrykit-<version>-py3-none-any.whl` | `pixi run build` |
| `sentrykit-<version>.tar.gz` | `pixi run build` |
| `sentrykit-docs-html-<version>.zip` | `pixi run docs-html`, zipped from `dist/docs/html/` |
| `sentrykit.pdf` | `pixi run docs-pdf` |
| `llms.txt` | `pixi run docs-llms` |
| `llms-full.txt` | `pixi run docs-llms` |

Six assets, and the release workflow verifies each one exists before it creates the release —
a release that silently ships five of six is the failure this guards against. `pixi run docs`
produces all four documentation artifacts in one go; the layout they land in is fixed in
`documentation-standards.md` because the workflow attaches them by path.

Note on the PDF builder: rinohtype is **AGPL-3.0-only**. It is a documentation build tool, in
the `dev` feature only — never imported by, linked into, or shipped inside the wheel, exactly
like `ruff` or `mypy` — so it does not reach sentrykit's Apache-2.0 licensing. It must never
appear in `[project.optional-dependencies]`.

## Release checklist
1. `pixi run -e all check` is green — and so are `default`, `web` and `agent`.
2. Version bumped in `src/sentrykit/__init__.py`; `CHANGELOG.md` updated. The tag must match
   that version; the release workflow refuses to proceed if they disagree.
3. `pixi run docs` produces HTML, PDF and both llms.txt files cleanly; the HTML build is `-W`
   and is already part of `check`. `README.md` reflects any change to the public story.
4. Extras matrix verified — `pixi run release-check` installs the built wheel with each of the
   seven extras into a throwaway venv and imports what each one promises. It runs
   `twine check` on what it built first, so an artifact no index would accept fails here
   rather than at the upload.
5. `pixi run build` produces wheel + sdist.
6. Optionally rehearse on the test index: `pixi run publish-test`, then install the result
   back out in **two steps**, never one.

   ```bash
   pip download --index-url https://test.pypi.org/simple/ --no-deps                 --only-binary :all: -d /tmp/rehearsal "sentrykit==<version>"
   pip install "/tmp/rehearsal/sentrykit-<version>-py3-none-any.whl[all]"
   ```

   **Do not use a two-index `pip install` here, in either order.** The commonly posted form
   is `--index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/`,
   and it fails: the test index carries an abandoned placeholder `fastapi` whose sdist does
   not build, pip selects it, and `sentrykit[all]` fails for reasons that have nothing to do
   with sentrykit. Swapping the two does **not** help either — an extra index is not a
   fallback. pip unions the candidates from every index it is given and picks by version, so
   whichever copy carries the higher version wins no matter which flag named it. Both were
   tried; both failed the same way.

   The two-step form has no such ambiguity, and it tests more. The download reaches only for
   sentrykit and proves the upload is retrievable; installing the downloaded *file* resolves
   every dependency from PyPI in the ordinary way, so what is exercised is the uploaded
   artifact's own metadata rather than an index race. Worth asserting afterwards that
   `load_pack()` returns policy text — the shipped Cedar pack is package *data*, and a
   build-backend rule that ships only `*.py` is invisible until somebody calls it.

   **A version is spent on the test index as permanently as on the real one**, so a rehearsal
   that has to be repeated needs a new version — rehearse once, late, on the artifact you
   intend to ship.
7. Tag the release with a plain version tag; the release commit follows the commit rule (no
   tooling attribution). `workflow_dispatch` on the release workflow is a dry run: it builds
   and uploads every asset as a workflow artifact without creating a release, and the
   `publish` job is unreachable from it.

### What is upstream of the first release
Two things that are nobody's commit to make:

- **A Trusted Publisher on PyPI**, naming this repository, `release.yml` and the `pypi`
  environment. Until it exists the publish job fails closed with PyPI's own error, which is
  the right failure but is not a green release.
- **The project URLs resolve.** `Homepage`, `Source` and `Changelog` point into this
  repository, so while it is private every link on the PyPI project page fails for the reader
  who installed the package. Either the repository becomes public or those URLs go; it is a
  decision about the project rather than a packaging fault, which is why it is listed here
  and not fixed in `pyproject.toml`.

### Keeping the published dependency range honest
`ci.yml` runs every job `locked: true`, so CI tests the dependency set contributors have. The
combination *users* get — a fresh resolution of each range — is tested by `upstream.yml`
instead, weekly and on any pull request touching a dependency declaration. Both matter, and
neither substitutes for the other; ADR-037 records why they are separate workflows.
