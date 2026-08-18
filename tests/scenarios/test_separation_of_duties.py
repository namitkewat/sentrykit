"""Separation of duties: two things that must not land on one person.

Static incompatibility first — the resource names the role that must *not* hold it, so "nobody
in the audit role touches settlement" is a resource attribute rather than a cross-product of
policies. Then the four-eyes rule, which needs the approval action to be identifiable: the pack
ships ``Action::"approve"`` in its entity graph precisely so a host maps its own action into it
with a parent edge and the forbid applies without anyone editing reviewed policy logic.
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

SETTLEMENT_CLERK = EntityRef("Role", "settlement-clerk")
AUDITOR = EntityRef("Role", "auditor")

SETTLEMENT = EntityRef("Resource", "settlement")
INVOICE = EntityRef("Resource", "invoice")

APPROVE = EntityRef("Action", "approve")
"""The pack's own action group, contributed by its ``entities.json``."""

INVOICE_APPROVE = EntityRef("Action", "invoice.approve")
PAT = EntityRef("User", "pat")

WORLD = (
    Entity(SETTLEMENT_CLERK),
    Entity(AUDITOR),
    # The host's own action, mapped into the pack's group. This edge is the entire adoption
    # cost of the four-eyes rule.
    Entity(INVOICE_APPROVE, parents=(APPROVE,)),
    Entity(
        SETTLEMENT,
        {"required_role": SETTLEMENT_CLERK, "conflicting_role": AUDITOR},
    ),
    Entity(INVOICE, {"required_role": SETTLEMENT_CLERK, "prepared_by": PAT}),
)


@protect(action='Action::"settlement.post"', resource='Resource::"settlement"')
def post_settlement() -> dict[str, object]:
    """Entitled by the clerk role, and forbidden to anyone who also audits."""
    return {"posted": True}


@protect(action='Action::"invoice.approve"', resource='Resource::"invoice"')
def approve_invoice() -> dict[str, object]:
    """In the pack's ``Action::"approve"`` group, so the four-eyes forbid reaches it."""
    return {"approved": True}


@pytest.mark.scenario
def test_a_principal_holding_the_conflicting_role_is_refused(
    govern: Install, log: AuditLog
) -> None:
    govern(*WORLD)

    with (
        establish(Principal(id="quinn", roles=("settlement-clerk", "auditor"))),
        pytest.raises(AuthzDenied) as refusal,
    ):
        post_settlement()

    # Entitled by the clerk role and refused anyway: the forbid outranks the permit that would
    # otherwise have carried the call.
    assert refusal.value.determining_policies == ["sod-conflicting-role"]
    assert log.determining() == ("sod-conflicting-role",)
    assert log.outcomes == [("decision", "denied")]


@pytest.mark.scenario
def test_the_same_principal_without_the_conflicting_role_is_permitted(
    govern: Install, log: AuditLog
) -> None:
    govern(*WORLD)

    with establish(Principal(id="quinn", roles=("settlement-clerk",))):
        result = post_settlement()

    assert result["posted"] is True
    assert log.determining() == ("rbac-required-role",)
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_the_preparer_of_a_resource_may_not_approve_it(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    with (
        establish(Principal(id="pat", roles=("settlement-clerk",))),
        pytest.raises(AuthzDenied) as refusal,
    ):
        approve_invoice()

    assert refusal.value.determining_policies == ["sod-same-actor-approval"]
    assert log.determining() == ("sod-same-actor-approval",)
    assert log.outcomes == [("decision", "denied")]


@pytest.mark.scenario
def test_a_second_pair_of_eyes_may_approve_it(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    with establish(Principal(id="rae", roles=("settlement-clerk",))):
        approve_invoice()

    assert log.determining() == ("rbac-required-role",)
    assert log.outcomes == [("decision", "allowed")]
