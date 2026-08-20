"""Cedar's reserved ``__`` escape keys may only be spelled by sentrykit, never by a caller.

The behaviour under test is a boundary, not a feature: Cedar's request JSON promotes a record
carrying ``__entity`` into a typed entity reference, so a supplied mapping spelling that key
would be indistinguishable from an :class:`~sentrykit.cedar.EntityRef` the application built.
Against the argument-aware ``forbid`` backstop this project documents, that is an escalation
with no error attached — a clean allow — so the assertions here run the whole way through
:meth:`~sentrykit.engine.Governor.plan` rather than stopping at the coercion function.

``Group::"approved"`` is the escalation's payload because Cedar's ``in`` is reflexive: a
caller who passes the *approved group itself* as the region is trivially "in" it.
"""

from __future__ import annotations

import pytest

from sentrykit.audit import AuditTrail
from sentrykit.cedar import Entity, EntityRef, PolicyEngine, coerce_value
from sentrykit.config import configure
from sentrykit.context import Principal
from sentrykit.engine import ArgumentSpec, Governor
from sentrykit.errors import AuthzDenied, ReservedKey
from sentrykit.stores.memory import InMemoryAuditSink

SEARCH_ACTION = EntityRef("Action", "tool.search_orders")
ORDERS_TOOL = EntityRef("Tool", "orders")

BACKSTOP_POLICY = """
@id("base")
permit (principal, action, resource);

@id("region-must-be-approved")
forbid (principal, action, resource)
when { context.args has region && !(context.args.region in Group::"approved") };
"""
"""A permit plus the argument-aware ``forbid`` backstop.

The ``forbid`` is the one printed in the concepts page, verbatim, so this suite also pins
that example.
"""

FORGED_ENTITY = {"__entity": {"type": "Group", "id": "approved"}}
"""What a caller would send to promote their argument into the approved group itself."""

FORGED_EXTENSION = {"__extn": {"fn": "unknown", "arg": "limit"}}
"""The sibling escape form: an extension-value call, which Cedar cannot resolve."""


def search_orders(customer_id: str, region: object = None) -> dict[str, object]:
    """``region`` is untyped so an entity reference can legitimately reach the gate."""
    return {"customer_id": customer_id, "region": region}


@pytest.fixture
def spec() -> ArgumentSpec:
    return ArgumentSpec.from_callable(search_orders)


@pytest.fixture
def backstopped() -> Governor:
    """A governor whose policy set carries the argument-aware forbid."""
    engine = PolicyEngine(
        BACKSTOP_POLICY,
        (
            Entity(EntityRef("Group", "approved")),
            Entity(EntityRef("Region", "eu"), parents=(EntityRef("Group", "approved"),)),
            Entity(EntityRef("Region", "cn")),
            Entity(ORDERS_TOOL),
        ),
    )
    return Governor(engine)


def _plan(governor: Governor, spec: ArgumentSpec, region: object) -> object:
    return governor.plan(
        spec,
        principal=Principal(id="alice"),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1", "region": region},
    )


# --- the backstop still works on genuine values ---------------------------------------


@pytest.mark.unit
def test_an_entity_reference_the_application_built_reaches_the_gate_and_is_permitted(
    backstopped: Governor, spec: ArgumentSpec
) -> None:
    plan = _plan(backstopped, spec, EntityRef("Region", "eu"))

    assert plan.allowed is True


@pytest.mark.unit
def test_an_entity_reference_outside_the_approved_group_is_denied_by_the_backstop(
    backstopped: Governor, spec: ArgumentSpec
) -> None:
    with pytest.raises(AuthzDenied) as caught:
        _plan(backstopped, spec, EntityRef("Region", "cn"))

    assert list(caught.value.determining_policies) == ["region-must-be-approved"]


# --- the forgery -----------------------------------------------------------------------


@pytest.mark.unit
def test_a_supplied_entity_escape_is_refused_instead_of_satisfying_the_backstop(
    backstopped: Governor, spec: ArgumentSpec
) -> None:
    with pytest.raises(ReservedKey) as caught:
        _plan(backstopped, spec, FORGED_ENTITY)

    assert caught.value.key == "__entity"
    assert caught.value.path == "args.region"


@pytest.mark.unit
def test_a_supplied_extension_escape_is_refused_on_the_same_grounds(
    backstopped: Governor, spec: ArgumentSpec
) -> None:
    with pytest.raises(ReservedKey) as caught:
        _plan(backstopped, spec, FORGED_EXTENSION)

    assert caught.value.key == "__extn"


@pytest.mark.unit
def test_the_refusal_holds_under_fail_mode_open(backstopped: Governor, spec: ArgumentSpec) -> None:
    """Fail-open tolerates a broken policy set, never a forged request.

    An engine error under ``fail_mode="open"`` lets the call through by design. Routing the
    forgery through that path would turn the setting into an attacker-reachable bypass, so
    the refusal happens before Cedar is consulted and there is no engine failure to tolerate.
    """
    configure(fail_mode="open")

    with pytest.raises(ReservedKey):
        _plan(backstopped, spec, FORGED_ENTITY)


@pytest.mark.unit
def test_the_refusal_is_recorded_in_the_audit_trail(spec: ArgumentSpec) -> None:
    sink = InMemoryAuditSink()
    engine = PolicyEngine(BACKSTOP_POLICY, (Entity(EntityRef("Group", "approved")),))
    governor = Governor(engine, audit=AuditTrail(sink))

    with pytest.raises(ReservedKey):
        _plan(governor, spec, FORGED_ENTITY)

    (record,) = sink.records
    assert record.outcome == "denied"
    assert record.decision == "deny"
    assert "__entity" in (record.reason or "")


# --- the escape keys are refused wherever they appear ----------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "path"),
    [
        (FORGED_ENTITY, "args.region"),
        ({"nested": FORGED_ENTITY}, "args.region.nested"),
        ([FORGED_ENTITY], "args.region[0]"),
        (["safe", {"deeper": [FORGED_ENTITY]}], "args.region[1].deeper[0]"),
    ],
    ids=["direct", "nested-record", "in-a-list", "list-inside-a-record"],
)
def test_a_forged_escape_is_found_at_any_depth(
    backstopped: Governor, spec: ArgumentSpec, value: object, path: str
) -> None:
    with pytest.raises(ReservedKey) as caught:
        _plan(backstopped, spec, value)

    assert caught.value.path == path


@pytest.mark.unit
def test_the_whole_reserved_prefix_is_refused_not_only_the_two_cedar_defines() -> None:
    """Cedar reserves the prefix, so a third escape form would be covered without a change."""
    with pytest.raises(ReservedKey) as caught:
        coerce_value({"__something_new": 1})

    assert caught.value.key == "__something_new"


@pytest.mark.unit
def test_a_reserved_key_in_an_entity_attribute_is_refused_too() -> None:
    """Attribute values reach Cedar by the same coercion, so they get the same boundary."""
    with pytest.raises(ReservedKey):
        Entity(EntityRef("User", "alice"), attributes={"tenant": FORGED_ENTITY}).as_json()


# --- and the trusted path is untouched --------------------------------------------------


@pytest.mark.unit
def test_an_entity_reference_still_renders_as_cedars_escape_form() -> None:
    assert coerce_value(EntityRef("Region", "eu")) == {"__entity": {"type": "Region", "id": "eu"}}


@pytest.mark.unit
def test_an_entity_reference_nested_in_ordinary_data_still_round_trips() -> None:
    coerced = coerce_value({"regions": [EntityRef("Region", "eu")], "limit": 5})

    assert coerced == {"regions": [{"__entity": {"type": "Region", "id": "eu"}}], "limit": 5}


@pytest.mark.unit
def test_a_single_underscore_key_is_ordinary_data() -> None:
    assert coerce_value({"_internal": "kept"}) == {"_internal": "kept"}
