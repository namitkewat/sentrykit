"""Shared pytest fixtures.

Everything here exists so a test starts from a known-empty world. sentrykit keeps
process-wide state — the cached :class:`~sentrykit.config.Settings`, per-action overrides,
the ambient principal and environment, and the installed governor — and a test that inherits
any of it from whichever test ran before it is exactly the hygiene failure
``dev-docs/testing-standards.md`` names. The reset is autouse so nobody has to remember it.

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


@pytest.fixture(autouse=True)
def clean_process_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Give every test an empty environment, no settings, no principal, and no governor."""
    for name in [name for name in os.environ if name.startswith(ENV_PREFIX)]:
        monkeypatch.delenv(name, raising=False)
    _reset()
    yield
    _reset()


def _reset() -> None:
    reset_settings()
    clear_context()  # also drops the last decision envelope
    set_governor(None)


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
