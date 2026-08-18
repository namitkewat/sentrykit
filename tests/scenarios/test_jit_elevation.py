"""Just-in-time elevation: a role held for a window, and only for that window.

Two attributes on the principal — which role, and until when — so granting an elevation is a
store write rather than a policy change. The permit matches the elevated role against what the
resource *requires*, which is what keeps an elevation from becoming a blanket escalation, and
the forbid closes the window from the other side so a lapsed elevation stops mattering rather
than merely stopping matching.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from freezegun import freeze_time

from sentrykit.cedar import Entity, EntityRef
from sentrykit.context import Principal, establish
from sentrykit.decorator import protect
from sentrykit.envelope import last_envelope
from sentrykit.errors import AuthzDenied

if TYPE_CHECKING:  # pragma: no cover - annotations only; pytest supplies the fixtures
    from conftest import AuditLog, Install

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
"""The instant every scenario in this module is frozen at."""

UNTIL = NOW + timedelta(minutes=30)
"""The end of the elevation window."""

DEPLOYER = EntityRef("Role", "deployer")
REVIEWER = EntityRef("Role", "reviewer")
PROD = EntityRef("Resource", "prod")

WORLD = (Entity(DEPLOYER), Entity(REVIEWER), Entity(PROD, {"required_role": DEPLOYER}))


@protect(action='Action::"deploy.run"', resource='Resource::"prod"')
def run_deploy() -> dict[str, object]:
    """The thing an operator is elevated *to*, for half an hour."""
    return {"deployed": True}


def elevated(*, to: EntityRef, until: datetime) -> Principal:
    """Build a principal whose only entitlement is an elevation.

    No standing role at all, so nothing but ``jit-elevation`` can permit the call and the
    scenario cannot pass for the wrong reason.

    Args:
        to: The role being elevated to.
        until: When the elevation lapses.

    Returns:
        The principal.
    """
    return Principal(id="jo", attributes={"elevation_role": to, "elevation_until": until})


@pytest.mark.scenario
def test_an_elevation_inside_its_window_is_permitted(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    with freeze_time(NOW), establish(elevated(to=DEPLOYER, until=UNTIL)):
        result = run_deploy()

    assert result["deployed"] is True
    assert log.determining() == ("jit-elevation",)
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_an_elevated_call_carries_the_notification_obligation(
    govern: Install, log: AuditLog
) -> None:
    govern(*WORLD)

    with freeze_time(NOW), establish(elevated(to=DEPLOYER, until=UNTIL)):
        run_deploy()

    envelope = last_envelope()
    assert envelope is not None
    assert envelope.obligations == ("notify:secops",)
    assert log.obligations() == ("notify:secops",)
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_an_elevation_past_its_window_is_forbidden(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    with (
        freeze_time(UNTIL + timedelta(seconds=1)),
        establish(elevated(to=DEPLOYER, until=UNTIL)),
        pytest.raises(AuthzDenied) as refusal,
    ):
        run_deploy()

    assert refusal.value.determining_policies == ["jit-elevation-expired-forbidden"]
    assert log.determining() == ("jit-elevation-expired-forbidden",)
    assert log.outcomes == [("decision", "denied")]


@pytest.mark.scenario
def test_an_elevation_to_another_role_does_not_reach_this_resource(
    govern: Install, log: AuditLog
) -> None:
    govern(*WORLD)

    # Live elevation, wrong role. Elevation is not a blanket escalation: the permit compares
    # the elevated role against what the resource declares, and these do not match.
    with (
        freeze_time(NOW),
        establish(elevated(to=REVIEWER, until=UNTIL)),
        pytest.raises(AuthzDenied) as refusal,
    ):
        run_deploy()

    assert refusal.value.determining_policies == []
    assert log.determining() == ()
    assert log.outcomes == [("decision", "denied")]
