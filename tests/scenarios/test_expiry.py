"""Entitlements that stop on their own — asserted at both of the two places they can stop.

A time-boxed grant is enforced twice on purpose, and the two halves fail differently:

* the **grant store** drops an expired grant when it materializes a principal, so the decision
  never sees the role at all and the refusal is an ordinary default deny;
* the **pack** forbids on an ``entitlement_expires`` attribute, which is the belt to that
  store's braces — a principal assembled by a host's own directory, or one carrying its window
  as a plain attribute, still stops being entitled at the declared moment, and the refusal
  names the policy.

Both are asserted here, because a suite that only tested the store would pass against a pack
whose expiry policies did nothing at all.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from freezegun import freeze_time

from sentrykit.cedar import Entity, EntityRef
from sentrykit.context import Principal, establish
from sentrykit.decorator import protect
from sentrykit.errors import AuthzDenied
from sentrykit.stores.base import GrantSpec

if TYPE_CHECKING:  # pragma: no cover - annotations only; pytest supplies the fixtures
    from conftest import AuditLog, Install
    from sentrykit.stores.memory import InMemoryGrantStore

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
"""When the grant is made, and when the "still valid" half of each scenario is decided."""

EXPIRES = NOW + timedelta(hours=8)
"""End of the shift the grant is time-boxed to."""

SUPPORT = EntityRef("Role", "support")
ORDERS = EntityRef("Resource", "orders")
ANA = EntityRef("User", "ana")

WORLD = (Entity(SUPPORT), Entity(ORDERS, {"required_role": SUPPORT}))


@protect(action='Action::"orders.search"', resource='Resource::"orders"')
def search_orders() -> dict[str, object]:
    """The call the entitlement window opens and closes."""
    return {"rows": 1}


def seed_shift_grant(store: InMemoryGrantStore) -> None:
    """Give Ana the support role until :data:`EXPIRES`, as an admin surface would.

    Args:
        store: The store to write to.
    """
    store.grant(
        GrantSpec(
            principal=ANA,
            kind="role",
            subject="support",
            expires_at=EXPIRES,
            granted_by='User::"root"',
            reason="on-call shift",
        )
    )


# --- the store half ------------------------------------------------------------------------


@pytest.mark.scenario
def test_a_time_boxed_grant_materializes_inside_its_window(
    govern: Install, log: AuditLog, store: InMemoryGrantStore
) -> None:
    govern(*WORLD, grant_store=store)

    with freeze_time(NOW):
        seed_shift_grant(store)
        principal = store.get_principal(ANA)
        assert principal is not None
        assert principal.roles == ("support",)
        with establish(principal):
            search_orders()

    assert log.determining() == ("rbac-required-role",)
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_a_time_boxed_grant_stops_materializing_at_its_expiry(
    govern: Install, log: AuditLog, store: InMemoryGrantStore
) -> None:
    govern(*WORLD, grant_store=store)

    with freeze_time(NOW):
        seed_shift_grant(store)

    # Exactly the expiry instant: `GrantRecord.is_active` is `expires_at > now`, so the grant
    # is already gone. The principal still exists — the store knows them — but carries no role,
    # and the refusal is therefore a default deny with no policy to name.
    with freeze_time(EXPIRES):
        principal = store.get_principal(ANA)
        assert principal is not None
        assert principal.roles == ()
        with establish(principal), pytest.raises(AuthzDenied) as refusal:
            search_orders()

    assert refusal.value.determining_policies == []
    assert log.determining() == ()
    assert log.outcomes == [("decision", "denied")]


# --- the policy half -----------------------------------------------------------------------


@pytest.mark.scenario
def test_an_expired_entitlement_attribute_is_forbidden(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    entitled_until_yesterday = Principal(
        id="ana",
        roles=("support",),
        attributes={"entitlement_expires": NOW - timedelta(days=1)},
    )

    with (
        freeze_time(NOW),
        establish(entitled_until_yesterday),
        pytest.raises(AuthzDenied) as refusal,
    ):
        search_orders()

    # The role is still on the principal — RBAC would permit. The forbid is what stops it.
    assert refusal.value.determining_policies == ["entitlement-expired-forbidden"]
    assert log.determining() == ("entitlement-expired-forbidden",)
    assert log.outcomes == [("decision", "denied")]


@pytest.mark.scenario
def test_an_entitlement_still_inside_its_window_is_permitted(
    govern: Install, log: AuditLog
) -> None:
    govern(*WORLD)

    with (
        freeze_time(NOW),
        establish(
            Principal(id="ana", roles=("support",), attributes={"entitlement_expires": EXPIRES})
        ),
    ):
        search_orders()

    assert log.determining() == ("rbac-required-role",)
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_an_entitlement_that_has_not_started_is_forbidden(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    with (
        freeze_time(NOW - timedelta(seconds=1)),
        establish(Principal(id="ana", roles=("support",), attributes={"entitlement_starts": NOW})),
        pytest.raises(AuthzDenied) as refusal,
    ):
        search_orders()

    assert refusal.value.determining_policies == ["entitlement-not-yet-valid-forbidden"]
    assert log.determining() == ("entitlement-not-yet-valid-forbidden",)
    assert log.outcomes == [("decision", "denied")]


@pytest.mark.scenario
def test_an_entitlement_is_valid_from_the_instant_it_starts(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    # The boundary itself. `entitlement-not-yet-valid-forbidden` is `context.now < starts`, so
    # the entitlement is live at the start instant rather than one tick after it — the reading
    # an operator writing `starts=09:00` expects.
    with (
        freeze_time(NOW),
        establish(Principal(id="ana", roles=("support",), attributes={"entitlement_starts": NOW})),
    ):
        search_orders()

    assert log.determining() == ("rbac-required-role",)
    assert log.outcomes == [("decision", "allowed")]
