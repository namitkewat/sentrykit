"""The Cedar seam: entity references, value coercion, and normalized decisions."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from sentrykit.cedar import (
    CedarRequest,
    Entity,
    EntityRef,
    PolicyEngine,
    coerce_value,
)
from sentrykit.errors import ConfigurationError

SEARCH_ACTION = EntityRef("Action", "tool.search_orders")
AUDIT_EXPORT_ACTION = EntityRef("Action", "tool.audit_export")
ORDERS_TOOL = EntityRef("Tool", "orders")
SUPPORT_ROLE = EntityRef("Role", "support")
ALICE = EntityRef("User", "alice")


def _support_user(uid: EntityRef = ALICE, **attributes: object) -> Entity:
    """A principal snapshot in ``Role::"support"``, as the governor would build one."""
    return Entity(uid, attributes=attributes, parents=(SUPPORT_ROLE,))


def _search(principal: Entity, **context: object) -> CedarRequest:
    return CedarRequest(
        principal=principal.uid,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        context=context,
        entities=(principal,),
    )


# --- entity references ----------------------------------------------------------------


@pytest.mark.unit
def test_a_full_uid_round_trips_through_parse_and_str() -> None:
    parsed = EntityRef.parse('Tool::"orders"')

    assert parsed == EntityRef("Tool", "orders")
    assert str(parsed) == 'Tool::"orders"'


@pytest.mark.unit
def test_a_namespaced_type_is_preserved() -> None:
    assert EntityRef.parse('Sales::Order::"o-1"') == EntityRef("Sales::Order", "o-1")


@pytest.mark.unit
def test_a_bare_id_needs_a_default_type() -> None:
    assert EntityRef.parse("orders", default_type="Tool") == EntityRef("Tool", "orders")


@pytest.mark.unit
def test_a_bare_id_without_a_default_type_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError):
        EntityRef.parse("orders")


@pytest.mark.unit
@pytest.mark.parametrize("value", ["Tool::orders", 'Tool::"orders'])
def test_a_malformed_uid_is_a_configuration_error(value: str) -> None:
    with pytest.raises(ConfigurationError):
        EntityRef.parse(value, default_type="Tool")


@pytest.mark.unit
def test_parsing_an_existing_reference_returns_it_unchanged() -> None:
    ref = EntityRef("Tool", "orders")

    assert EntityRef.parse(ref) == ref


@pytest.mark.unit
def test_an_id_containing_awkward_characters_survives_the_structured_form() -> None:
    ref = EntityRef("Doc", "report 2026/Q3")

    assert ref.as_json() == {"type": "Doc", "id": "report 2026/Q3"}


# --- value coercion -------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("value", [True, False, 0, 42, "orders", ""])
def test_cedar_native_scalars_pass_through_untouched(value: object) -> None:
    assert coerce_value(value) == value


@pytest.mark.unit
def test_none_has_no_cedar_representation() -> None:
    assert coerce_value(None) is None


@pytest.mark.unit
def test_a_float_becomes_a_string_rather_than_a_truncated_integer() -> None:
    assert coerce_value(1.5) == "1.5"
    assert coerce_value(Decimal("1.50")) == "1.50"


@pytest.mark.unit
def test_a_datetime_becomes_epoch_seconds() -> None:
    moment = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)

    assert coerce_value(moment) == int(moment.timestamp())


@pytest.mark.unit
def test_an_entity_reference_becomes_cedars_entity_form() -> None:
    assert coerce_value(EntityRef("Tool", "orders")) == {
        "__entity": {"type": "Tool", "id": "orders"}
    }


@pytest.mark.unit
def test_coercion_recurses_and_drops_null_valued_keys() -> None:
    coerced = coerce_value({"kept": 1, "dropped": None, "nested": {"ratio": 0.25}})

    assert coerced == {"kept": 1, "nested": {"ratio": "0.25"}}


@pytest.mark.unit
def test_coercion_recurses_into_sequences() -> None:
    coerced = coerce_value(["a", 2, 3.5])

    assert list(coerced) == ["a", 2, "3.5"]  # type: ignore[call-overload]


# --- building an engine ---------------------------------------------------------------


@pytest.mark.unit
def test_unparseable_policies_fail_at_wiring_time_not_at_request_time() -> None:
    with pytest.raises(ConfigurationError):
        PolicyEngine("permit(principal, action")


@pytest.mark.unit
def test_the_policy_text_is_readable_back_off_the_engine(policy_engine: PolicyEngine) -> None:
    assert 'action == Action::"tool.search_orders"' in policy_engine.policies


@pytest.mark.unit
def test_the_policy_set_hash_is_stable_for_the_same_text(policy_text: str) -> None:
    first = PolicyEngine(policy_text).policy_set_hash
    second = PolicyEngine(policy_text).policy_set_hash

    assert first == second
    assert first


@pytest.mark.unit
def test_the_policy_set_hash_changes_when_the_logic_changes(policy_text: str) -> None:
    other = policy_text + '\n@id("extra") permit(principal, action, resource);\n'

    assert PolicyEngine(policy_text).policy_set_hash != PolicyEngine(other).policy_set_hash


@pytest.mark.unit
def test_with_entities_extends_a_copy_and_leaves_the_original_deciding_as_before() -> None:
    engine = PolicyEngine(
        '@id("public-folder-is-readable")\n'
        'permit(principal, action == Action::"doc.read", resource in Folder::"public");',
        [Entity(EntityRef("Folder", "public")), Entity(EntityRef("User", "reader"))],
    )
    request = CedarRequest(
        principal=EntityRef("User", "reader"),
        action=EntityRef("Action", "doc.read"),
        resource=EntityRef("Doc", "d-1"),
    )
    assert not engine.evaluate(request).allowed

    extended = engine.with_entities(
        [Entity(EntityRef("Doc", "d-1"), parents=(EntityRef("Folder", "public"),))]
    )

    assert extended.evaluate(request).allowed
    assert not engine.evaluate(request).allowed


# --- deciding -------------------------------------------------------------------------


@pytest.mark.unit
def test_a_permitted_request_is_allowed(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_search(_support_user()))

    assert decision.allowed is True
    assert decision.decision == "allow"
    assert decision.failed is False


@pytest.mark.unit
def test_the_determining_policy_is_the_id_annotation_not_cedars_generated_id(
    policy_engine: PolicyEngine,
) -> None:
    decision = policy_engine.evaluate(_search(_support_user()))

    assert decision.determining_policies == ("support-may-search",)


@pytest.mark.unit
def test_no_matching_policy_is_a_default_deny_with_nothing_determining_it(
    policy_engine: PolicyEngine,
) -> None:
    stranger = Entity(EntityRef("User", "mallory"))

    decision = policy_engine.evaluate(_search(stranger))

    assert decision.allowed is False
    assert decision.decision == "deny"
    assert decision.determining_policies == ()
    assert decision.errors == ()


@pytest.mark.unit
def test_a_forbid_names_itself_on_the_denial(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_search(_support_user(suspended=True)))

    assert decision.allowed is False
    assert decision.determining_policies == ("suspended-principals-are-forbidden",)


@pytest.mark.unit
def test_a_forbid_overrides_a_matching_permit(policy_engine: PolicyEngine) -> None:
    permitted = policy_engine.evaluate(_search(_support_user(suspended=False)))
    forbidden = policy_engine.evaluate(_search(_support_user(suspended=True)))

    assert permitted.allowed is True
    assert forbidden.allowed is False


@pytest.mark.unit
def test_reading_a_missing_attribute_is_an_engine_failure_not_a_denial(
    policy_engine: PolicyEngine,
) -> None:
    principal = _support_user()

    decision = policy_engine.evaluate(
        CedarRequest(
            principal=principal.uid,
            action=AUDIT_EXPORT_ACTION,
            resource=ORDERS_TOOL,
            entities=(principal,),
        )
    )

    assert decision.allowed is False
    assert decision.errors
    assert decision.failed is True


@pytest.mark.unit
def test_the_same_policy_decides_cleanly_once_the_attribute_is_present(
    policy_engine: PolicyEngine,
) -> None:
    principal = _support_user(clearance="high")

    decision = policy_engine.evaluate(
        CedarRequest(
            principal=principal.uid,
            action=AUDIT_EXPORT_ACTION,
            resource=ORDERS_TOOL,
            entities=(principal,),
        )
    )

    assert decision.allowed is True
    assert decision.errors == ()


@pytest.mark.unit
def test_a_context_carrying_a_float_and_a_null_still_decides_cleanly(
    policy_engine: PolicyEngine,
) -> None:
    decision = policy_engine.evaluate(
        _search(_support_user(), score=0.75, delegation=None, channel="agent")
    )

    assert decision.allowed is True
    assert decision.errors == ()
    assert decision.decision != "no-decision"


@pytest.mark.unit
def test_entity_attributes_carrying_a_float_and_a_null_still_parse(
    policy_engine: PolicyEngine,
) -> None:
    principal = _support_user(EntityRef("User", "bob"), ratio=0.25, tier=None)

    decision = policy_engine.evaluate(_search(principal))

    assert decision.allowed is True


@pytest.mark.unit
def test_the_correlation_id_is_echoed_back(policy_engine: PolicyEngine) -> None:
    principal = _support_user()

    decision = policy_engine.evaluate(
        CedarRequest(
            principal=principal.uid,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            entities=(principal,),
            correlation_id="inv-42",
        )
    )

    assert decision.correlation_id == "inv-42"


@pytest.mark.unit
def test_a_decision_records_the_policy_set_it_was_made_against(
    policy_engine: PolicyEngine,
) -> None:
    decision = policy_engine.evaluate(_search(_support_user()))

    assert decision.policy_set_hash == policy_engine.policy_set_hash


@pytest.mark.unit
def test_the_trace_is_json_ready_and_names_the_deciding_policy(
    policy_engine: PolicyEngine,
) -> None:
    trace = policy_engine.evaluate(_search(_support_user())).as_trace()

    rendered = json.dumps(trace)

    assert trace["decision"] == "allow"
    assert "support-may-search" in rendered


@pytest.mark.unit
def test_a_null_inside_a_sequence_is_dropped_rather_than_poisoning_the_list() -> None:
    """Cedar has no null, so one in a list would make the whole request undecidable."""
    assert coerce_value(["a", None, "b"]) == ["a", "b"]


@pytest.mark.unit
def test_a_null_nested_in_a_record_inside_a_sequence_is_dropped_too() -> None:
    assert coerce_value([{"kept": 1, "dropped": None}]) == [{"kept": 1}]
