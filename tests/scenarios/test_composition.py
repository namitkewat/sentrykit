"""The pack alongside a host's own policies — one governor, two artifacts, attributable.

Nothing about the pack is privileged: it is a DSN in a list, unioned by the same composite that
unions two of your own directories. What the union has to preserve is *attribution*. A decision
the pack made must name the pack, and a decision your own directory made must name your
directory, or the audit trail cannot answer "which artifact, at which version, produced this"
— which is the whole of ADR-006.

The two spellings are both asserted here because they are genuinely different things. Cedar
reports the ``@id`` as declared, because namespacing is applied to sentrykit's provenance index
rather than to the policy text; the namespaced ``pack/<id>`` and ``house/<id>`` live on the
record's provenance, next to the source that contributed them.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from sentrykit.cedar import Entity, EntityRef
from sentrykit.context import Principal, establish
from sentrykit.decorator import protect
from sentrykit.errors import AuthzDenied

if TYPE_CHECKING:  # pragma: no cover - annotations only; pytest supplies the fixtures
    from conftest import AuditLog, Install

SUPPORT = EntityRef("Role", "support")
ORDERS = EntityRef("Resource", "orders")
WEATHER = EntityRef("Resource", "weather")

HOUSE_POLICY = """
@id("anyone-may-read-the-weather")
permit (
  principal,
  action == Action::"weather.read",
  resource == Resource::"weather"
);
"""
"""A policy the pack could never have shipped: it names a host's own action and resource."""


@protect(action='Action::"orders.search"', resource='Resource::"orders"')
def search_orders() -> dict[str, object]:
    """Decided by the pack's attribute-driven RBAC."""
    return {"rows": 1}


@protect(action='Action::"weather.read"', resource='Resource::"weather"')
def read_weather() -> dict[str, object]:
    """Decided by the host's own directory."""
    return {"forecast": "rain"}


@pytest.fixture
def house(tmp_path: Path) -> Path:
    """A host's own policy directory.

    Named ``house`` deliberately: a ``file://`` source takes its name from the directory, and
    that name is the namespace its policy ids appear under.
    """
    directory = tmp_path / "house"
    directory.mkdir()
    (directory / "weather.cedar").write_text(HOUSE_POLICY, encoding="utf-8")
    return directory


@pytest.mark.scenario
def test_the_hosts_own_policy_decides_the_hosts_own_action(
    govern: Install, log: AuditLog, house: Path
) -> None:
    govern(
        Entity(WEATHER),
        policy_source=["pack://", f"file://{house.as_posix()}"],
    )

    with establish(Principal(id="anyone")):
        result = read_weather()

    assert result["forecast"] == "rain"
    assert log.determining() == ("anyone-may-read-the-weather",)
    assert log.provenance() == [("house", "house/anyone-may-read-the-weather")]
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_the_pack_still_decides_the_packs_patterns(
    govern: Install, log: AuditLog, house: Path
) -> None:
    govern(
        Entity(SUPPORT),
        Entity(ORDERS, {"required_role": SUPPORT}),
        policy_source=["pack://", f"file://{house.as_posix()}"],
    )

    with establish(Principal(id="alice", roles=("support",))):
        search_orders()

    assert log.determining() == ("rbac-required-role",)
    assert log.provenance() == [("pack", "pack/rbac-required-role")]
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_the_union_records_every_policy_under_its_own_sources_namespace(
    govern: Install, house: Path
) -> None:
    governor = govern(
        Entity(SUPPORT),
        Entity(ORDERS, {"required_role": SUPPORT}),
        policy_source=["pack://", f"file://{house.as_posix()}"],
    )

    bundle = governor.bundle
    assert bundle is not None
    ids = [entry.policy_id for entry in bundle.provenance]
    assert "pack/rbac-required-role" in ids
    assert "pack/break-the-glass" in ids
    assert "house/anyone-may-read-the-weather" in ids
    # Every id is namespaced by exactly one of the two members, and no id is bare.
    assert all(name.startswith(("pack/", "house/")) for name in ids)


@pytest.mark.scenario
def test_the_packs_forbids_still_reach_the_hosts_own_action(
    govern: Install, log: AuditLog, house: Path
) -> None:
    # A forbid from one member of the union outranks a permit from the other — which is the
    # reason the union is a concatenation rather than a precedence chain. The host's policy
    # permits `weather.read` unconditionally; the pack's suspension-style forbid still wins.
    govern(
        Entity(WEATHER, {"emergency_only": True}),
        policy_source=["pack://", f"file://{house.as_posix()}"],
    )

    with establish(Principal(id="anyone")), pytest.raises(AuthzDenied) as refusal:
        read_weather()

    assert refusal.value.determining_policies == ["emergency-resource-forbidden-without-flag"]
    assert log.provenance() == [
        ("pack", "pack/emergency-resource-forbidden-without-flag"),
    ]
    assert log.outcomes == [("decision", "denied")]
