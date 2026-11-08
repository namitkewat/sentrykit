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
The repository is private, so there is no PyPI publish and no hosted documentation site. A
release **is** its assets, and every one of them is attached to the GitHub release:

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
   seven extras into a throwaway venv and imports what each one promises.
5. `pixi run build` produces wheel + sdist.
6. Tag the release with a plain version tag; the release commit follows the commit rule (no
   tooling attribution). `workflow_dispatch` on the release workflow is a dry run: it builds
   and uploads every asset as a workflow artifact without creating a release.
