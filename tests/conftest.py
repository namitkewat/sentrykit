"""Shared pytest fixtures.

Everything here exists so a test starts from a known-empty world. sentrykit keeps
process-wide state — the cached :class:`~sentrykit.config.Settings`, per-action overrides,
the ambient principal and environment, and the installed governor — and a test that inherits
any of it from whichever test ran before it is exactly the hygiene failure this fixture
exists to prevent. The reset is autouse so nobody has to remember it.

The Cedar policy set below is deliberately small and every policy carries an ``@id``
annotation, because "the determining policy is reported by its annotation, not by Cedar's
generated ``policy0``" is itself part of the contract under test.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from sentrykit.cedar import Entity, EntityRef, PolicyEngine
from sentrykit.config import ENV_PREFIX, reset_settings
from sentrykit.constraints import ArgumentConstraint, ConstraintSet
from sentrykit.context import Principal, clear_context
from sentrykit.engine import Governor, set_governor
from sentrykit.registry import ENTRY_POINT_GROUPS, clear_registry, registrations, remember

SEARCH_ACTION = EntityRef("Action", "tool.search_orders")
"""Permitted for anyone in ``Role::"support"`` on ``Tool::"orders"``."""

EXPORT_ACTION = EntityRef("Action", "tool.export_orders")
"""Permitted for support too; used for the required-argument cases."""

AUDIT_EXPORT_ACTION = EntityRef("Action", "tool.audit_export")
"""Guarded by a policy that reads an attribute the principal may not have."""

PING_ACTION = EntityRef("Action", "tool.ping")
"""Permitted against *any* resource, so a callable declaring none can still be planned."""

ORDERS_TOOL = EntityRef("Tool", "orders")
SUPPORT_ROLE = EntityRef("Role", "support")

POLICY_TEXT = """
@id("support-may-search")
permit (
  principal in Role::"support",
  action == Action::"tool.search_orders",
  resource == Tool::"orders"
);

@id("support-may-export")
permit (
  principal in Role::"support",
  action == Action::"tool.export_orders",
  resource == Tool::"orders"
);

@id("support-may-ping")
permit (
  principal in Role::"support",
  action == Action::"tool.ping",
  resource
);

@id("suspended-principals-are-forbidden")
forbid (
  principal,
  action,
  resource
)
when { principal has suspended && principal.suspended };

@id("audit-export-needs-clearance")
permit (
  principal in Role::"support",
  action == Action::"tool.audit_export",
  resource == Tool::"orders"
)
when { principal.clearance == "high" };
"""
"""A permit for a role, a forbid on an attribute, and a policy that reads an attribute a
principal may be missing — which Cedar reports as an *engine error* rather than a denial."""


@pytest.fixture
def seeded_desk() -> Iterator[None]:
    """Drop and reseed the example apps' database, so a test can assert a row or a count.

    Deliberately **not** autouse. The desk lives in memory for the whole process and the
    governed callables that write to it really write: issuing a refund inserts a row and
    allocates the next id in sequence, so a test that asserts ``rf-0015`` or a live
    ``pending_refunds`` count depends on which tests ran before it in the same process.
    Reseeding is cheap but not free -- a few tenths of a second -- and most tests here assert
    an authorization *outcome*, which no amount of written data can move. Paying that cost on
    every test in the suite to serve the handful that pin a printed body would be several
    wasted minutes an hour.

    So the rule is: ask for this fixture when the assertion names a row, an allocated id or a
    count, and leave it alone when the assertion is about the decision. Where a stable field
    will do -- ``fmt`` after a refill, ``status`` after an approval -- prefer asserting that
    and skip the reseed entirely.

    Yields:
        Nothing; the value of this fixture is the state it leaves behind.
    """
    from examples.desk import reset_desk

    reset_desk()
    yield


@pytest.fixture(autouse=True)
def clean_process_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Give every test an empty environment, no settings, no principal, and no governor."""
    for name in [name for name in os.environ if name.startswith(ENV_PREFIX)]:
        monkeypatch.delenv(name, raising=False)
    # Empty, and never merely absent. `examples.ollama` treats an unset URL as "look on
    # localhost" and an empty one as "do not look", so deleting the variable along with every
    # other `SENTRYKIT_*` one is what would send the agent examples at whatever daemon happens
    # to be listening on the machine running the suite. An example's behaviour must not depend
    # on that, and a test that reached for a live model would be asserting against a different
    # model on every laptop. Setting it here rather than in the agent suite's own conftest
    # because the reach is an *import* away from any test: anything that calls `default_model()`
    # or `create_server()` probes, and nobody should have to remember which of those it touched.
    monkeypatch.setenv("SENTRYKIT_OLLAMA_URL", "")
    # The same switch for the frontier tier, and it needs its own line because the sweep above
    # cannot reach what guards it. `OPENROUTER_API_KEY` carries no `SENTRYKIT_` prefix, so it
    # survives the loop -- and `examples.models` reads it from `.env` at the repo root when the
    # environment does not carry it, which is exactly where a developer keeps one. Deleting
    # `SENTRYKIT_OPENROUTER_URL` along with every other prefixed variable therefore restores
    # its *default*, which means the tier is on. The consequence is worse than a daemon on a
    # laptop: the suite would send real, billable requests to a third party, and assert against
    # a different model on every machine and every week.
    monkeypatch.setenv("SENTRYKIT_OPENROUTER_URL", "")
    _reset()
    yield
    _reset()


def _reset() -> None:
    reset_settings()
    clear_context()  # also drops the last decision envelope
    set_governor(None)


@pytest.fixture
def clean_registry() -> Iterator[None]:
    """Let a test register, clear and rebuild the plugin registry without leaking.

    ``register_*`` writes into a process-wide dict, and built-ins reach it by importing their
    module — so a test that calls :func:`~sentrykit.registry.clear_registry` and then returns
    would leave every later test without ``jsonl``, because re-importing an already-imported
    module re-runs no decorator. This snapshots the registrations and puts them back through
    the public :func:`~sentrykit.registry.remember`, which also preserves each backend's
    ``builtin`` provenance rather than letting it be rediscovered as an entry point.

    It lives here rather than in a suite's own conftest because three suites need the same
    guarantee — the registry tests, the CLI tests and the scenarios all register a backend
    under a scheme that must not outlive them — and three copies of a teardown is three places
    for one of them to drift into leaking.

    Not autouse: most tests never touch the registry, and a snapshot per test would be work
    done to protect against something that did not happen. A test that registers anything
    depends on this explicitly.

    Yields:
        Nothing; the value of this fixture is its teardown.
    """
    saved = {kind: dict(registrations(kind)) for kind in ENTRY_POINT_GROUPS}
    try:
        yield
    finally:
        clear_registry()
        for plugins in saved.values():
            for plugin in plugins.values():
                remember(plugin)


@pytest.fixture
def policy_text() -> str:
    """The Cedar policy text every governed test decides against."""
    return POLICY_TEXT


@pytest.fixture
def base_entities() -> tuple[Entity, ...]:
    """The stable half of the entity graph: roles and resources, never principals."""
    return (
        Entity(EntityRef("Role", "support")),
        Entity(EntityRef("Role", "guest")),
        Entity(ORDERS_TOOL),
        Entity(EntityRef("Resource", "tool.ping")),
    )


@pytest.fixture
def policy_engine(policy_text: str, base_entities: tuple[Entity, ...]) -> PolicyEngine:
    """A parsed engine over :data:`POLICY_TEXT`."""
    return PolicyEngine(policy_text, base_entities)


@pytest.fixture
def governor(policy_engine: PolicyEngine) -> Iterator[Governor]:
    """A governor over the fixture policy set, installed as the process default."""
    installed = Governor(policy_engine)
    set_governor(installed)
    yield installed
    set_governor(None)


@pytest.fixture
def entitled_principal() -> Principal:
    """In ``Role::"support"``, so the search/export/ping permits apply. No constraints."""
    return Principal(id="alice", roles=("support",))


@pytest.fixture
def unentitled_principal() -> Principal:
    """In no role any policy mentions, so every action is a default deny."""
    return Principal(id="mallory", roles=("guest",))


@pytest.fixture
def suspended_principal() -> Principal:
    """Entitled by role but caught by the named ``forbid``, so the denial has a policy id."""
    return Principal(id="sam", roles=("support",), attributes={"suspended": True})


@pytest.fixture
def constrained_principal() -> Principal:
    """Entitled, and carrying every constraint shape the filter has to enforce.

    ``tool.search_orders`` gets an allow-set with a default, a pattern with a default, and a
    range with *no* default — the last one so "every supplied argument was rejected and no
    default can complete the call" is reachable. ``tool.export_orders`` gets the required
    argument, kept on a separate action so it does not make every search deny.
    """
    return Principal(
        id="casey",
        roles=("support",),
        constraints={
            'Action::"tool.search_orders"': ConstraintSet(
                arguments={
                    "customer_id": ArgumentConstraint(
                        allow=("c-1", "c-2"),
                        default="c-1",
                        policy="grant-orders-customers",
                    ),
                    "region": ArgumentConstraint(
                        pattern=r"[a-z]{2}-[a-z]+",
                        default="eu-west",
                        policy="grant-orders-region",
                    ),
                    "limit": ArgumentConstraint(
                        minimum=1,
                        maximum=50,
                        policy="grant-orders-limit",
                    ),
                }
            ),
            'Action::"tool.export_orders"': ConstraintSet(
                arguments={
                    "tenant": ArgumentConstraint(required=True, policy="grant-export-tenant"),
                    "fmt": ArgumentConstraint(
                        allow=("csv", "json"),
                        default="csv",
                        policy="grant-export-format",
                    ),
                }
            ),
        },
    )
