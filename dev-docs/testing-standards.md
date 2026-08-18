# Testing standards

## Framework & layout
- **pytest** (+ `pytest-asyncio` in `auto` mode, `pytest-cov`, `hypothesis`, `freezegun`).
- Three suites:
  - `tests/unit/` — fast, isolated, **no network, no real frameworks**. The whole core is
    covered here.
  - `tests/integration/` — exercise a real adapter (FastAPI/Flask/FastMCP/Pydantic-AI) via
    its test client or a simulated tool-call. Run in the matching pixi env
    (`pixi run -e web test-integration`, `pixi run -e agent test-integration`).
  - `tests/scenarios/` — end-to-end policy-pattern scenarios (RBAC, ownership, delegation,
    expiry, break-the-glass, SoD, JIT) proving the shipped policy pack behaves.
- Mark tests with `unit` / `integration` / `scenario` markers (declared in `pyproject.toml`).

## Coverage & determinism
- Core coverage target ≥ **90%** (repo gate `fail_under = 85`). Cover the edge cases
  explicitly: deny, all-args-invalid, missing default, validation failure, no-principal,
  strict vs lenient, fail closed vs open.
- Tests are **deterministic**: freeze time (`freezegun`) for anything touching `now`
  (expiry, TTL, JIT). No reliance on wall-clock, ordering of dict iteration, or network.
- Use `hypothesis` for the argument filter / constraint resolver (property: kept args always
  satisfy the constraint; rejected args always violate it; defaults never override a supplied
  valid value).

## What every phase must test
- **Phase 1:** gate, filter, defaults, envelope verbosity, `ContextVar` propagation, explicit
  override, fail-closed.
- **Phase 2:** composite semantics (union/merge/fan-out), forbid-overrides preserved,
  masking-before-write (assert raw values never reach the sink), hash-chain tamper detection,
  entry-point discovery of a dummy plugin.
- **Phase 3:** allowed/denied routes, arg filtering over HTTP, defaults, a protected
  non-route function governed by ambient context.
- **Phase 4:** entitled/unentitled tool calls, `list_tools` filtering per principal, the
  multi-hop relationship scenario, on-behalf-of principal.
- **Phase 5:** each policy-pack pattern as a scenario; audit-report aggregates over a seeded
  log; CLI grant/revoke emits audit records.

## Example apps as tests
The minimal apps under `examples/` are part of the test surface: integration tests import and
drive them. Keep them tiny and current — if an adapter changes, its example and its test
change in the same commit.

## Hygiene
- No hidden state between tests (fresh in-memory stores per test via fixtures). No asserting
  on private internals when a public behavior assertion is possible. Name tests for the
  behavior, not the function.
