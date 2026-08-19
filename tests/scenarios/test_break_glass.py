"""Break-the-glass: an entitlement, a flag *and* a justification — never a flag alone.

The middle test is the one this file exists for. The obvious draft of this pattern — a permit
conditioned on ``context.break_glass`` — authorizes literally anyone, because the flag is
caller-supplied and a Cedar permit needs no base entitlement to fire. So the last scenario
here sets the flag from a principal who holds no emergency role and asserts the refusal. If
that ever starts passing as an allow, the pack has grown the hole back.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from sentrykit.cedar import Entity, EntityRef
from sentrykit.context import Principal, establish
from sentrykit.decorator import protect
from sentrykit.envelope import last_envelope
from sentrykit.errors import AuthzDenied

if TYPE_CHECKING:  # pragma: no cover - annotations only; pytest supplies the fixtures
    from conftest import AuditLog, Install

COMMANDER = EntityRef("Role", "incident-commander")
SUPPORT = EntityRef("Role", "support")
VAULT = EntityRef("Resource", "vault")

JUSTIFICATION = "SEV-1 #4412: customer data unreadable"

WORLD = (
    Entity(COMMANDER),
    Entity(SUPPORT),
    Entity(VAULT, {"emergency_only": True, "emergency_role": COMMANDER}),
)
"""An emergency-only resource, and the role that may open it under the glass."""


@protect(action='Action::"vault.open"', resource='Resource::"vault"')
def open_vault() -> dict[str, object]:
    """The side effect break-the-glass exists to make deliberate."""
    return {"opened": True}


@pytest.mark.scenario
def test_the_emergency_role_with_the_flag_and_a_justification_is_permitted(
    govern: Install, log: AuditLog
) -> None:
    govern(*WORLD)

    with establish(
        Principal(id="ivy", roles=("incident-commander",)),
        break_glass=True,
        justification=JUSTIFICATION,
    ):
        result = open_vault()

    assert result["opened"] is True
    assert log.determining() == ("break-the-glass",)
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_a_break_glass_call_carries_both_obligations(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    with establish(
        Principal(id="ivy", roles=("incident-commander",)),
        break_glass=True,
        justification=JUSTIFICATION,
    ):
        open_vault()

    # The obligation rides on the permit, so a call that proceeded under the glass
    # cannot proceed quietly — both the caller-facing envelope and the immutable record say so.
    envelope = last_envelope()
    assert envelope is not None
    assert envelope.obligations == ("notify:secops", "record:justification")
    assert log.obligations() == ("notify:secops", "record:justification")
    assert log.outcomes == [("decision", "allowed")]


@pytest.mark.scenario
def test_an_emergency_only_resource_is_forbidden_without_the_flag(
    govern: Install, log: AuditLog
) -> None:
    govern(*WORLD)

    # The role and the justification are both in place. The flag is what is missing, and the
    # forbid beats every permit in the pack — which is what makes emergency-only mean anything.
    with (
        establish(Principal(id="ivy", roles=("incident-commander",)), justification=JUSTIFICATION),
        pytest.raises(AuthzDenied) as refusal,
    ):
        open_vault()

    assert refusal.value.determining_policies == ["emergency-resource-forbidden-without-flag"]
    assert log.determining() == ("emergency-resource-forbidden-without-flag",)
    assert log.outcomes == [("decision", "denied")]


@pytest.mark.scenario
def test_the_flag_alone_authorizes_nobody(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    # `sam` is a real, entitled principal elsewhere in the system — just not an incident
    # commander. Setting the flag is something any caller can do; being in the emergency role
    # is not, and the pack refuses the difference.
    with (
        establish(
            Principal(id="sam", roles=("support",)),
            break_glass=True,
            justification=JUSTIFICATION,
        ),
        pytest.raises(AuthzDenied) as refusal,
    ):
        open_vault()

    assert refusal.value.determining_policies == []
    assert log.determining() == ()
    assert log.outcomes == [("decision", "denied")]


@pytest.mark.scenario
def test_an_empty_justification_does_not_open_the_glass(govern: Install, log: AuditLog) -> None:
    govern(*WORLD)

    with (
        establish(
            Principal(id="ivy", roles=("incident-commander",)),
            break_glass=True,
            justification="",
        ),
        pytest.raises(AuthzDenied),
    ):
        open_vault()

    assert log.determining() == ()
    assert log.outcomes == [("decision", "denied")]
