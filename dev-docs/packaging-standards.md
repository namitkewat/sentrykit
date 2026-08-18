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
  - `sentrykit[fastapi]`, `sentrykit[flask]`, `sentrykit[fastmcp]`, `sentrykit[pydantic-ai]`
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

## Release checklist
1. `pixi run -e all check` is green.
2. Version bumped; `CHANGELOG.md` updated.
3. `docs` build `--strict` passes; README regenerated.
4. Extras matrix verified (each extra installs and imports).
5. `pixi run build` produces wheel + sdist; `twine check` passes.
6. Tag the release with a plain version tag; the release commit follows the commit rule (no
   tooling attribution).
