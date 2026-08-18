"""The three patterns a host adopts first: a role, a membership, and an owner.

All three are the same claim in three shapes — *the relationship decides, not the caller*. The
resource declares what it requires, the principal arrives carrying edges, and Cedar resolves
the distance between them. The group scenario is the one that proves it properly: its principal
is two hops from the group the resource names, and no policy mentions either hop.
"""

from __future__ import annotations

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

WORLD = EntityRef("Group", "world")
EU = EntityRef("Group", "eu")
EU_WEST = EntityRef("Group", "eu-west")
LEDGER = EntityRef("Resource", "eu-ledger")

ALICE = EntityRef("User", "alice")
NOTE = EntityRef("Resource", "note")


@protect(action='Action::"orders.search"', resource='Resource::"orders"')
def search_orders(customer_id: str = "") -> dict[str, object]:
    """A plain governed callable; the pack decides who reaches it."""
    return {"customer_id": customer_id}


@protect(action='Action::"ledger.read"', resource='Resource::"eu-ledger"')
def read_ledger() -> dict[str, object]:
    """Governed by group membership rather than by a role."""
    return {"rows": 2}


@protect(action='Action::"note.read"', resource='Resource::"note"')
def read_note() -> dict[str, object]:
    """Governed by ownership."""
    return {"body": "…"}


# --- rbac --------------------------------------------------------------------------------


@pytest.mark.scenario
def test_a_principal_in_the_role_the_resource_requires_is_permitted(
    govern: Install, log: AuditLog
) -> None:
    govern(Entity(SUPPORT), Entity(ORDERS, {"required_role": SUPPORT}))

    with establish(Principal(id="alice", roles=("support",))):
        result = search_orders(customer_id="c-1")

    assert result["customer_id"] == "c-1"
    assert log.determining() == ("rbac-required-role",)
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_a_principal_without_the_required_role_is_refused_by_default_deny(
    govern: Install, log: AuditLog
) -> None:
    govern(Entity(SUPPORT), Entity(ORDERS, {"required_role": SUPPORT}))

    with establish(Principal(id="bob")), pytest.raises(AuthzDenied) as refusal:
        search_orders(customer_id="c-1")

    # No policy matched at all, which is what an empty determining list *means*.
    assert refusal.value.determining_policies == []
    assert log.determining() == ()
    assert log.outcomes == [("decision", "denied")]


# --- groups ------------------------------------------------------------------------------


@pytest.mark.scenario
def test_membership_two_hops_below_the_group_the_resource_names_is_permitted(
    govern: Install, log: AuditLog
) -> None:
    govern(
        Entity(WORLD),
        Entity(EU, parents=(WORLD,)),
        Entity(EU_WEST, parents=(EU,)),
        Entity(LEDGER, {"group": EU}),
    )

    # The principal is in `eu-west`; the resource names `eu`. Nothing in the policy, the
    # decorator or the call site mentions the hop between them — Cedar's parent closure is
    # what turns "member of a sub-team" into "may act on the team's resource".
    with establish(Principal(id="mo", parents=(EU_WEST,))):
        result = read_ledger()

    assert result["rows"] == 2
    assert log.determining() == ("group-membership",)
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_a_principal_outside_the_hierarchy_is_refused(govern: Install, log: AuditLog) -> None:
    govern(
        Entity(WORLD),
        Entity(EU, parents=(WORLD,)),
        Entity(EU_WEST, parents=(EU,)),
        Entity(EntityRef("Group", "us-east"), parents=(WORLD,)),
        Entity(LEDGER, {"group": EU}),
    )

    # A sibling group under the same root: reachable from `world`, never from `eu`.
    with (
        establish(Principal(id="nia", parents=(EntityRef("Group", "us-east"),))),
        pytest.raises(AuthzDenied),
    ):
        read_ledger()

    assert log.determining() == ()
    assert log.outcomes == [("decision", "denied")]


# --- ownership ---------------------------------------------------------------------------


@pytest.mark.scenario
def test_the_owner_of_a_resource_is_permitted(govern: Install, log: AuditLog) -> None:
    govern(Entity(NOTE, {"owner": ALICE}))

    with establish(Principal(id="alice")):
        read_note()

    assert log.determining() == ("resource-owner",)
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_ownership_is_not_inherited_through_a_group(govern: Install, log: AuditLog) -> None:
    # Equality, not `in`: sharing a group with the owner does not make you one.
    govern(Entity(EU), Entity(NOTE, {"owner": ALICE}))

    with establish(Principal(id="bob", parents=(EU,))), pytest.raises(AuthzDenied):
        read_note()

    assert log.determining() == ()
    assert log.outcomes == [("decision", "denied")]
