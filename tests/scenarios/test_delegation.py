"""Delegation: acting for someone else, inside a scope that *binds* rather than adds.

The scope is the whole point, and the second scenario is what proves it is a boundary. A
delegated agent that holds the role a resource requires would reach the plain RBAC permit and
take any action at all — a Cedar permit needs no other permit's agreement, only the absence of
a forbid. So the out-of-scope test asserts two things about *the same principal*: with the
delegation attributes it is refused, and without them it is permitted. The forbid is doing the
work, not a missing entitlement.
"""

from __future__ import annotations

from datetime import UTC, datetime
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

WITHIN = datetime(2026, 6, 1, 18, 0, tzinfo=UTC)
"""Six hours after :data:`NOW` — a delegation still inside its window."""

LAPSED = datetime(2026, 5, 31, 18, 0, tzinfo=UTC)
"""Eighteen hours before :data:`NOW` — a delegation that has run out."""

SUPPORT = EntityRef("Role", "support")
ORDERS = EntityRef("Resource", "orders")
ANA = EntityRef("User", "ana")
REFUND = EntityRef("Action", "orders.refund")

WORLD = (Entity(SUPPORT), Entity(ORDERS, {"required_role": SUPPORT}))
"""One resource requiring one role: enough for RBAC to permit anything the scope allows."""


@protect(action='Action::"orders.refund"', resource='Resource::"orders"')
def refund_order(order_id: str = "") -> dict[str, object]:
    """Inside the agent's delegated scope."""
    return {"refunded": order_id}


@protect(action='Action::"orders.export"', resource='Resource::"orders"')
def export_orders() -> dict[str, object]:
    """Outside it — and permitted by plain RBAC, which is what makes the forbid load-bearing."""
    return {"rows": 3}


def delegated(*, expires: datetime) -> Principal:
    """Build the agent: in the role, delegated by Ana, scoped to refunds, until ``expires``.

    Args:
        expires: When the delegation lapses.

    Returns:
        The principal, as a grant store would materialize it.
    """
    return Principal(
        id="agent-7",
        roles=("support",),
        attributes={
            "delegated_by": ANA,
            "delegated_actions": [REFUND],
            "delegation_expires": expires,
        },
    )


@pytest.mark.scenario
def test_an_agent_acting_in_scope_for_a_declared_delegator_is_permitted(
    govern: Install, log: AuditLog
) -> None:
    govern(*WORLD)

    with freeze_time(NOW), establish(delegated(expires=WITHIN), on_behalf_of=ANA):
        result = refund_order(order_id="o-9")

    assert result["refunded"] == "o-9"
    # Two permits fire — the agent's own role and the delegation — and Cedar reports the
    # determining set unordered, so this is sorted rather than positional.
    assert sorted(log.determining()) == ["delegation-on-behalf-of", "rbac-required-role"]
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_a_delegated_call_carries_the_on_behalf_of_obligation(
    govern: Install, log: AuditLog
) -> None:
    govern(*WORLD)

    with freeze_time(NOW), establish(delegated(expires=WITHIN), on_behalf_of=ANA):
        refund_order(order_id="o-9")

    envelope = last_envelope()
    assert envelope is not None
    assert envelope.obligations == ("record:on_behalf_of",)
    assert log.obligations() == ("record:on_behalf_of",)
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_an_action_outside_the_delegated_scope_is_forbidden(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    with (
        freeze_time(NOW),
        establish(delegated(expires=WITHIN), on_behalf_of=ANA),
        pytest.raises(AuthzDenied) as refusal,
    ):
        export_orders()

    assert refusal.value.determining_policies == ["delegation-outside-scope-forbidden"]
    assert log.determining() == ("delegation-outside-scope-forbidden",)
    assert log.outcomes == [("decision", "denied")]


@pytest.mark.scenario
def test_the_same_principal_without_the_delegation_is_permitted_that_action(
    govern: Install, log: AuditLog
) -> None:
    govern(*WORLD)

    # Same id, same role, same resource, same action. The only difference from the test above
    # is the three delegation attributes, so the refusal there is the scope and nothing else.
    with freeze_time(NOW), establish(Principal(id="agent-7", roles=("support",))):
        export_orders()

    assert log.determining() == ("rbac-required-role",)
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_a_delegation_past_its_expiry_is_forbidden(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    with (
        freeze_time(NOW),
        establish(delegated(expires=LAPSED), on_behalf_of=ANA),
        pytest.raises(AuthzDenied) as refusal,
    ):
        refund_order(order_id="o-9")

    assert refusal.value.determining_policies == ["delegation-expired-forbidden"]
    assert log.determining() == ("delegation-expired-forbidden",)
    assert log.outcomes == [("decision", "denied")]


@pytest.mark.scenario
def test_a_delegated_identity_is_never_used_silently(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    # In scope and unexpired, but the caller never declared the delegation in the context. The
    # delegation permit does not fire; RBAC still does, so this is an ordinary allow made on
    # the agent's *own* entitlement and recorded without the on-behalf-of obligation.
    with freeze_time(NOW), establish(delegated(expires=WITHIN)):
        refund_order(order_id="o-9")

    assert log.determining() == ("rbac-required-role",)
    assert log.obligations() == ()
    assert log.outcomes == [("decision", "allowed")]
