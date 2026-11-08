"""The Governor pipeline: gate, filter, defaults, validate, invoke, envelope."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from freezegun import freeze_time

from sentrykit.audit import AuditTrail, AuthzAuditRecord
from sentrykit.cedar import Entity, EntityRef, PolicyEngine
from sentrykit.config import Settings, configure, override_action
from sentrykit.constraints import ArgumentConstraint, ConstraintSet
from sentrykit.context import Principal
from sentrykit.engine import (
    ArgumentSpec,
    Governor,
    current_governor,
    derive_action,
    get_governor,
    install,
    merge_environment,
    set_governor,
    use_governor,
)
from sentrykit.errors import (
    ArgumentRejected,
    AuditUnavailable,
    AuthzDenied,
    ConfigurationError,
    DefaultUnavailable,
    NoValidArguments,
    ValidationFailed,
)
from sentrykit.masking import Masker
from sentrykit.stores.base import NullAuditSink
from sentrykit.stores.memory import InMemoryAuditSink

SEARCH_ACTION = EntityRef("Action", "tool.search_orders")
EXPORT_ACTION = EntityRef("Action", "tool.export_orders")
AUDIT_EXPORT_ACTION = EntityRef("Action", "tool.audit_export")
PING_ACTION = EntityRef("Action", "tool.ping")
ORDERS_TOOL = EntityRef("Tool", "orders")

_CALLED: list[dict[str, object]] = []


def search_orders(customer_id: str, limit: int = 10, region: str = "eu-west") -> dict[str, object]:
    """The protected callable most of these tests plan against."""
    call = {"customer_id": customer_id, "limit": limit, "region": region}
    _CALLED.append(call)
    return dict(call)


def export_orders(tenant: str = "", fmt: str = "csv") -> dict[str, object]:
    """Carries the required-argument constraint."""
    call = {"tenant": tenant, "fmt": fmt}
    _CALLED.append(call)
    return dict(call)


async def asearch_orders(customer_id: str, limit: int = 10) -> dict[str, object]:
    """The async twin, so both invoke paths are exercised."""
    call = {"customer_id": customer_id, "limit": limit}
    _CALLED.append(call)
    return dict(call)


def ping() -> str:
    """Declares no resource, so the governor has to synthesize one."""
    return "pong"


@pytest.fixture(autouse=True)
def _forget_calls() -> None:
    _CALLED.clear()


@pytest.fixture
def search_spec() -> ArgumentSpec:
    return ArgumentSpec.from_callable(search_orders)


@pytest.fixture
def export_spec() -> ArgumentSpec:
    return ArgumentSpec.from_callable(export_orders)


# --- argument specs -------------------------------------------------------------------


@pytest.mark.unit
def test_a_spec_records_the_parameters_and_which_are_required(search_spec: ArgumentSpec) -> None:
    assert search_spec.parameters == ("customer_id", "limit", "region")
    assert search_spec.required == frozenset({"customer_id"})
    assert search_spec.is_async is False
    assert search_spec.accepts_var_keyword is False


@pytest.mark.unit
def test_a_coroutine_function_is_recognized_as_async() -> None:
    assert ArgumentSpec.from_callable(asearch_orders).is_async is True


@pytest.mark.unit
def test_var_keyword_callables_are_flagged() -> None:
    def sink(**kwargs: object) -> None: ...

    spec = ArgumentSpec.from_callable(sink)

    assert spec.accepts_var_keyword is True
    assert spec.parameters == ()


@pytest.mark.unit
def test_positional_arguments_are_bound_to_parameter_names(search_spec: ArgumentSpec) -> None:
    assert search_spec.bind(("c-1", 5), {}) == {"customer_id": "c-1", "limit": 5}


@pytest.mark.unit
def test_omitted_arguments_are_simply_absent_from_the_binding(search_spec: ArgumentSpec) -> None:
    assert search_spec.bind((), {"customer_id": "c-1"}) == {"customer_id": "c-1"}


@pytest.mark.unit
def test_arguments_that_cannot_be_bound_are_a_configuration_error(
    search_spec: ArgumentSpec,
) -> None:
    with pytest.raises(ConfigurationError):
        search_spec.bind((), {"nonexistent": 1})


@pytest.mark.unit
def test_positional_only_parameters_are_split_back_out_positionally() -> None:
    def positional(first: int, /, second: int = 0) -> int:
        return first + second

    spec = ArgumentSpec.from_callable(positional)

    args, kwargs = spec.split({"first": 1, "second": 2})

    assert args == [1]
    assert kwargs == {"second": 2}
    assert positional(*args, **kwargs) == 3


@pytest.mark.unit
def test_validation_coerces_what_the_annotations_call_for(search_spec: ArgumentSpec) -> None:
    validated = search_spec.validate({"customer_id": "c-1", "limit": "5"})

    assert validated["limit"] == 5


@pytest.mark.unit
def test_validation_failure_carries_pydantics_structured_detail(
    search_spec: ArgumentSpec,
) -> None:
    with pytest.raises(ValidationFailed) as caught:
        search_spec.validate({"customer_id": "c-1", "limit": "many"})

    errors = caught.value.errors
    assert len(errors) == 1
    assert {"type", "loc", "msg"} <= set(errors[0])
    assert tuple(errors[0]["loc"]) == ("limit",)
    assert isinstance(errors[0]["msg"], str)
    assert errors[0]["msg"]


@pytest.mark.unit
def test_an_unannotated_parameter_is_still_protectable() -> None:
    def untyped(anything):
        return anything

    spec = ArgumentSpec.from_callable(untyped)

    assert spec.validate({"anything": object()})


# --- the coarse gate ------------------------------------------------------------------


@pytest.mark.unit
def test_the_gate_allows_a_principal_the_policy_permits(
    governor: Governor,
    search_spec: ArgumentSpec,
    entitled_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=entitled_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    assert plan.allowed is True
    assert plan.decision.allowed is True
    assert plan.decision.determining_policies == ("support-may-search",)


@pytest.mark.unit
def test_the_gate_denies_a_principal_no_policy_permits(
    governor: Governor,
    search_spec: ArgumentSpec,
    unentitled_principal: Principal,
) -> None:
    with pytest.raises(AuthzDenied) as caught:
        governor.plan(
            search_spec,
            principal=unentitled_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"customer_id": "c-1"},
        )

    denial = caught.value
    assert "tool.search_orders" in denial.action
    assert not denial.determining_policies
    assert not denial.engine_errors


@pytest.mark.unit
def test_a_denial_names_the_policy_annotation_not_cedars_generated_id(
    governor: Governor,
    search_spec: ArgumentSpec,
    suspended_principal: Principal,
) -> None:
    with pytest.raises(AuthzDenied) as caught:
        governor.plan(
            search_spec,
            principal=suspended_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"customer_id": "c-1"},
        )

    determining = list(caught.value.determining_policies)
    assert determining == ["suspended-principals-are-forbidden"]
    assert not any(name.startswith("policy") for name in determining)


@pytest.mark.unit
def test_a_denial_reaches_the_callable_never(
    governor: Governor,
    search_spec: ArgumentSpec,
    unentitled_principal: Principal,
) -> None:
    with pytest.raises(AuthzDenied):
        governor.plan(
            search_spec,
            principal=unentitled_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
        )

    assert _CALLED == []


@pytest.mark.unit
def test_a_callable_with_no_resource_gets_one_derived_from_the_action(
    governor: Governor,
    entitled_principal: Principal,
) -> None:
    plan = governor.plan(
        ArgumentSpec.from_callable(ping),
        principal=entitled_principal,
        action=PING_ACTION,
    )

    assert plan.allowed is True
    assert plan.invocation.resource == EntityRef("Resource", "tool.ping")


@pytest.mark.unit
def test_the_invocation_id_is_carried_onto_the_decision(
    governor: Governor,
    search_spec: ArgumentSpec,
    entitled_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=entitled_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
        invocation_id="inv-1",
    )

    assert plan.invocation.id == "inv-1"
    assert plan.decision.correlation_id == "inv-1"


@pytest.mark.unit
def test_planning_decides_without_performing_the_side_effect(
    governor: Governor,
    search_spec: ArgumentSpec,
    entitled_principal: Principal,
) -> None:
    governor.plan(
        search_spec,
        principal=entitled_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    assert _CALLED == []


# --- argument filtering and defaults --------------------------------------------------


@pytest.mark.unit
def test_the_filter_keeps_valid_arguments_and_reports_the_rejected_one(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1", "region": "nowhere"},
    )

    assert plan.processed["customer_id"] == "c-1"
    assert [item.name for item in plan.rejected] == ["region"]
    assert plan.rejected[0].rule == "pattern"
    assert plan.rejected[0].reason
    assert plan.rejected[0].policy == "grant-orders-region"


@pytest.mark.unit
def test_a_dropped_argument_is_replaced_by_the_principals_default(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1", "region": "nowhere"},
    )

    assert plan.processed["region"] == "eu-west"
    assert plan.defaults_applied["region"] == "eu-west"


@pytest.mark.unit
def test_defaults_are_injected_when_the_caller_supplies_nothing(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={},
    )

    assert plan.processed["customer_id"] == "c-1"
    assert plan.processed["region"] == "eu-west"
    assert plan.defaults_applied["customer_id"] == "c-1"
    assert plan.rejected == ()


@pytest.mark.unit
def test_a_default_never_overrides_a_value_the_caller_legitimately_supplied(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-2"},
    )

    assert plan.processed["customer_id"] == "c-2"
    assert "customer_id" not in plan.defaults_applied


@pytest.mark.unit
def test_an_unconstrained_principal_keeps_every_argument_they_pass(
    governor: Governor,
    search_spec: ArgumentSpec,
    entitled_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=entitled_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "anything", "limit": 9_000},
    )

    assert plan.processed["customer_id"] == "anything"
    assert plan.processed["limit"] == 9_000
    assert plan.rejected == ()


@pytest.mark.unit
def test_every_supplied_argument_rejected_refuses_the_call(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    with pytest.raises(NoValidArguments) as caught:
        governor.plan(
            search_spec,
            principal=constrained_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"limit": 9_000},
        )

    assert "limit" in caught.value.allowed
    assert [item["name"] for item in caught.value.rejected] == ["limit"]


@pytest.mark.unit
def test_a_default_is_not_used_to_answer_a_question_the_caller_did_not_ask(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    with pytest.raises(NoValidArguments) as caught:
        governor.plan(
            search_spec,
            principal=constrained_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"customer_id": "c-999"},
        )

    assert "customer_id" in caught.value.allowed
    assert _CALLED == []


@pytest.mark.unit
def test_a_partial_rejection_narrows_the_call_rather_than_refusing_it(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-2", "limit": 9_000},
    )

    assert plan.allowed is True
    assert plan.processed["customer_id"] == "c-2"
    assert [item.name for item in plan.rejected] == ["limit"]


@pytest.mark.unit
def test_a_required_argument_with_no_value_and_no_default_refuses_the_call(
    governor: Governor,
    export_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    with pytest.raises(DefaultUnavailable) as caught:
        governor.plan(
            export_spec,
            principal=constrained_principal,
            action=EXPORT_ACTION,
            resource=ORDERS_TOOL,
            proposed={},
        )

    assert caught.value.name == "tenant"


@pytest.mark.unit
def test_the_same_call_proceeds_once_the_required_argument_is_supplied(
    governor: Governor,
    export_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    plan = governor.plan(
        export_spec,
        principal=constrained_principal,
        action=EXPORT_ACTION,
        resource=ORDERS_TOOL,
        proposed={"tenant": "acme"},
    )

    assert plan.processed["tenant"] == "acme"
    assert plan.processed["fmt"] == "csv"


@pytest.mark.unit
def test_validation_runs_on_the_final_argument_set(
    governor: Governor,
    search_spec: ArgumentSpec,
    entitled_principal: Principal,
) -> None:
    with pytest.raises(ValidationFailed) as caught:
        governor.plan(
            search_spec,
            principal=entitled_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"customer_id": "c-1", "limit": "many"},
        )

    assert tuple(caught.value.errors[0]["loc"]) == ("limit",)
    assert _CALLED == []


# --- defaults for a name the signature does not list ----------------------------------
#
# ``ArgumentSpec.parameters`` excludes ``**kwargs``, which is what stops a stale grant making
# an ordinary call fail with an unexpected keyword argument. For a callable that *declares*
# ``**kwargs`` that exclusion was the whole story, so a constraint on a kwargs-only name was a
# reject-everything rule: the proposal was filtered and the default was then skipped for not
# being a parameter. ``accepts_var_keyword`` was computed for exactly this and read nowhere.


def _flexible_grant() -> Principal:
    """Entitled to search, with a bound-and-default on a name no signature below lists."""
    return Principal(
        id="dana",
        roles=("support",),
        constraints={
            'Action::"tool.search_orders"': ConstraintSet(
                arguments={
                    "page": ArgumentConstraint(maximum=10, default=3, policy="grant-page"),
                }
            )
        },
    )


@pytest.mark.unit
def test_a_default_reaches_a_name_only_var_keyword_accepts(governor: Governor) -> None:
    def flexible_search(customer_id: str, **extra: object) -> dict[str, object]:
        return {"customer_id": customer_id, **extra}

    plan = governor.plan(
        ArgumentSpec.from_callable(flexible_search),
        principal=_flexible_grant(),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    assert plan.processed["page"] == 3
    assert plan.defaults_applied["page"] == 3
    assert governor.invoke(flexible_search, plan)["page"] == 3


@pytest.mark.unit
def test_a_rejected_var_keyword_argument_is_refilled_rather_than_dropped(
    governor: Governor,
) -> None:
    """The narrowing half: the caller proposed 99, the grant allows 10, they get their own 3."""

    def flexible_search(customer_id: str, **extra: object) -> dict[str, object]:
        return {"customer_id": customer_id, **extra}

    plan = governor.plan(
        ArgumentSpec.from_callable(flexible_search),
        principal=_flexible_grant(),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1", "page": 99},
    )

    assert [(item.name, item.rule) for item in plan.rejected] == [("page", "maximum")]
    assert plan.processed["page"] == 3
    assert plan.narrowing() == (("page",), ())


@pytest.mark.unit
def test_a_signature_without_var_keyword_still_skips_an_unlisted_default(
    governor: Governor,
    search_spec: ArgumentSpec,
) -> None:
    """The guard the exclusion exists for: ``search_orders`` has no ``**kwargs`` and no page."""
    plan = governor.plan(
        search_spec,
        principal=_flexible_grant(),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    assert "page" not in plan.processed
    assert "page" not in plan.defaults_applied


# --- arg_handling ---------------------------------------------------------------------


@pytest.mark.unit
def test_lenient_handling_drops_the_rejected_argument_and_continues(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    configure(arg_handling="lenient")

    plan = governor.plan(
        search_spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1", "region": "nowhere"},
    )

    assert plan.allowed is True
    assert governor.invoke(search_orders, plan)["region"] == "eu-west"


@pytest.mark.unit
def test_strict_handling_refuses_the_whole_call(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    configure(arg_handling="strict")

    with pytest.raises(ArgumentRejected) as caught:
        governor.plan(
            search_spec,
            principal=constrained_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"customer_id": "c-1", "region": "nowhere"},
        )

    assert caught.value.name == "region"
    assert caught.value.reason
    assert _CALLED == []


@pytest.mark.unit
def test_an_action_override_can_make_one_action_strict(
    governor: Governor,
    search_spec: ArgumentSpec,
    export_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    override_action("tool.search_orders", arg_handling="strict")

    with pytest.raises(ArgumentRejected):
        governor.plan(
            search_spec,
            principal=constrained_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"region": "nowhere"},
        )

    lenient = governor.plan(
        export_spec,
        principal=constrained_principal,
        action=EXPORT_ACTION,
        resource=ORDERS_TOOL,
        proposed={"tenant": "acme", "fmt": "xml"},
    )

    assert lenient.processed["fmt"] == "csv"


@pytest.mark.unit
def test_an_action_override_still_applies_to_a_governor_built_with_explicit_settings(
    policy_engine: PolicyEngine,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    pinned = Governor(policy_engine, Settings(arg_handling="lenient"))
    override_action("tool.search_orders", arg_handling="strict")

    with pytest.raises(ArgumentRejected):
        pinned.plan(
            search_spec,
            principal=constrained_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"region": "nowhere"},
        )


# --- fail_mode ------------------------------------------------------------------------


@pytest.mark.unit
def test_an_engine_failure_refuses_the_call_and_says_it_was_an_engine_failure(
    governor: Governor,
    search_spec: ArgumentSpec,
    entitled_principal: Principal,
) -> None:
    configure(fail_mode="closed")

    with pytest.raises(AuthzDenied) as caught:
        governor.plan(
            search_spec,
            principal=entitled_principal,
            action=AUDIT_EXPORT_ACTION,
            resource=ORDERS_TOOL,
            proposed={"customer_id": "c-1"},
        )

    assert caught.value.engine_errors


@pytest.mark.unit
def test_an_engine_failure_lets_the_call_through_under_fail_mode_open(
    governor: Governor,
    search_spec: ArgumentSpec,
    entitled_principal: Principal,
) -> None:
    configure(fail_mode="open")

    plan = governor.plan(
        search_spec,
        principal=entitled_principal,
        action=AUDIT_EXPORT_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    assert plan.allowed is True
    assert plan.decision.failed is True
    assert governor.invoke(search_orders, plan)["customer_id"] == "c-1"


@pytest.mark.unit
def test_a_policy_denial_is_not_an_engine_failure_and_denies_under_fail_mode_open(
    governor: Governor,
    search_spec: ArgumentSpec,
    unentitled_principal: Principal,
) -> None:
    configure(fail_mode="open")

    with pytest.raises(AuthzDenied) as caught:
        governor.plan(
            search_spec,
            principal=unentitled_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"customer_id": "c-1"},
        )

    assert not caught.value.engine_errors


@pytest.mark.unit
def test_a_named_forbid_still_denies_under_fail_mode_open(
    governor: Governor,
    search_spec: ArgumentSpec,
    suspended_principal: Principal,
) -> None:
    configure(fail_mode="open")

    with pytest.raises(AuthzDenied) as caught:
        governor.plan(
            search_spec,
            principal=suspended_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
        )

    assert list(caught.value.determining_policies) == ["suspended-principals-are-forbidden"]


# --- a refusal that could not be recorded ---------------------------------------------
#
# ``_audit_refusal`` swallows an ``AuditUnavailable`` deliberately: the call is already being
# refused, and raising would replace the precise ``AuthzDenied`` the caller needs with an
# operational error. What was wrong is that the *fact of the loss* then went nowhere an
# auditor could reach — the only trace was an ERROR line on the channel ``audit.py`` says
# must not be mistaken for the trail. So with the sink down, a caller can probe which actions
# exist and which argument values are accepted, and the log reads clean across the hole.


@pytest.mark.unit
def test_a_refusal_the_sink_could_not_record_says_so_on_the_error(
    policy_engine: PolicyEngine,
    unentitled_principal: Principal,
    search_spec: ArgumentSpec,
) -> None:
    class Refusing(NullAuditSink):
        name = "refusing"

        def write(self, record: AuthzAuditRecord) -> None:
            raise AuditUnavailable("refusing", "no space left on device")

    configure(fail_mode="closed")
    governor = Governor(
        policy_engine, audit=AuditTrail(Refusing(), masker=Masker(key=b"k"), strict=True)
    )

    with pytest.raises(AuthzDenied) as caught:
        governor.plan(
            search_spec,
            principal=unentitled_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"customer_id": "c-1"},
        )

    # The denial still arrives as a denial, and now carries its own missing receipt.
    assert isinstance(caught.value.audit_failure, AuditUnavailable)
    assert caught.value.audit_failure is not None
    assert "refusing" in str(caught.value.audit_failure)


@pytest.mark.unit
def test_a_refusal_a_reachable_sink_recorded_carries_no_failure(
    policy_engine: PolicyEngine,
    unentitled_principal: Principal,
    search_spec: ArgumentSpec,
) -> None:
    """The overwhelmingly common path: the record landed, so there is nothing to report."""
    governor = Governor(
        policy_engine,
        audit=AuditTrail(InMemoryAuditSink(), masker=Masker(key=b"k"), strict=True),
    )

    with pytest.raises(AuthzDenied) as caught:
        governor.plan(
            search_spec,
            principal=unentitled_principal,
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"customer_id": "c-1"},
        )

    assert caught.value.audit_failure is None


# --- invoking -------------------------------------------------------------------------


@pytest.mark.unit
def test_a_sync_callable_runs_with_the_processed_arguments(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-2", "region": "nowhere"},
    )

    result = governor.invoke(search_orders, plan)

    assert result["customer_id"] == "c-2"
    assert result["region"] == "eu-west"
    assert _CALLED == [{"customer_id": "c-2", "limit": 10, "region": "eu-west"}]


@pytest.mark.unit
async def test_an_async_callable_runs_with_the_processed_arguments(
    governor: Governor,
    constrained_principal: Principal,
) -> None:
    spec = ArgumentSpec.from_callable(asearch_orders)
    plan = governor.plan(
        spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-2"},
    )

    result = await governor.ainvoke(asearch_orders, plan)

    assert result["customer_id"] == "c-2"


@pytest.mark.unit
def test_a_mapping_result_comes_back_carrying_the_envelope(
    governor: Governor,
    search_spec: ArgumentSpec,
    entitled_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=entitled_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    result = governor.invoke(search_orders, plan)

    assert "_authz" in result


@pytest.mark.unit
def test_no_envelope_is_attached_when_the_host_turned_it_off(
    governor: Governor,
    search_spec: ArgumentSpec,
    entitled_principal: Principal,
) -> None:
    configure(envelope_on_success=False)
    plan = governor.plan(
        search_spec,
        principal=entitled_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    result = governor.invoke(search_orders, plan)

    assert "_authz" not in result


# --- the envelope a plan produces -----------------------------------------------------


@pytest.mark.unit
def test_verbosity_off_leaves_a_plan_with_no_envelope(
    governor: Governor,
    search_spec: ArgumentSpec,
    entitled_principal: Principal,
) -> None:
    configure(verbosity="off")
    plan = governor.plan(
        search_spec,
        principal=entitled_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    assert plan.envelope() is None


@pytest.mark.unit
def test_a_summary_envelope_reports_the_rejection_without_its_value(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    configure(verbosity="summary")
    plan = governor.plan(
        search_spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1", "region": "nowhere"},
    )

    envelope = plan.envelope()

    assert envelope is not None
    assert [item.name for item in envelope.rejected] == ["region"]
    assert envelope.processed == {}
    assert envelope.determining_policies == ()


@pytest.mark.unit
def test_a_debug_envelope_names_the_determining_policies_and_carries_the_trace(
    governor: Governor,
    search_spec: ArgumentSpec,
    entitled_principal: Principal,
) -> None:
    configure(verbosity="debug")
    plan = governor.plan(
        search_spec,
        principal=entitled_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    envelope = plan.envelope()

    assert envelope is not None
    assert envelope.determining_policies == ("support-may-search",)
    assert envelope.trace


# --- wiring ---------------------------------------------------------------------------


@pytest.mark.unit
def test_no_governor_is_installed_by_default() -> None:
    assert current_governor() is None


@pytest.mark.unit
def test_asking_for_a_governor_that_was_never_wired_fails_loudly() -> None:
    with pytest.raises(ConfigurationError):
        get_governor()


@pytest.mark.unit
def test_install_wires_an_in_memory_policy_set_as_the_process_default(
    policy_text: str,
    base_entities: tuple[Entity, ...],
) -> None:
    installed = install(policy_text, entities=base_entities)

    assert get_governor() is installed
    assert installed.policy.policy_set_hash


@pytest.mark.unit
def test_install_rejects_a_policy_set_that_does_not_parse() -> None:
    with pytest.raises(ConfigurationError):
        install("permit(principal, action")


@pytest.mark.unit
def test_a_governor_can_be_swapped_for_the_duration_of_a_block(
    policy_engine: PolicyEngine,
) -> None:
    first = Governor(policy_engine)
    second = Governor(policy_engine)
    set_governor(first)

    with use_governor(second) as active:
        assert active is second
        assert get_governor() is second

    assert get_governor() is first


@pytest.mark.unit
def test_clearing_the_governor_leaves_nothing_installed(policy_engine: PolicyEngine) -> None:
    set_governor(Governor(policy_engine))

    set_governor(None)

    assert current_governor() is None


# --- derived action and environment ---------------------------------------------------


@pytest.mark.unit
def test_an_action_is_derived_from_the_module_and_qualified_name() -> None:
    assert derive_action(search_orders) == EntityRef(
        "Action", f"{search_orders.__module__}.{search_orders.__qualname__}"
    )


@pytest.mark.unit
def test_the_environment_gets_a_now_and_a_channel_when_nobody_supplied_them() -> None:
    with freeze_time("2026-08-18T12:00:00+00:00"):
        merged = merge_environment({}, None)

    now = merged["now"]
    assert isinstance(now, datetime)
    assert now.replace(tzinfo=None) == datetime(2026, 8, 18, 12, 0)
    assert merged["channel"] == "internal"


@pytest.mark.unit
def test_an_explicitly_established_now_is_left_alone() -> None:
    moment = datetime(2020, 1, 1, tzinfo=UTC)

    with freeze_time("2026-08-18T12:00:00+00:00"):
        merged = merge_environment({"now": moment}, None)

    assert merged["now"] == moment


@pytest.mark.unit
def test_a_per_call_environment_layers_over_the_ambient_one() -> None:
    merged = merge_environment(
        {"channel": "http", "request_id": "r-1"},
        {"channel": "agent"},
    )

    assert merged["channel"] == "agent"
    assert merged["request_id"] == "r-1"


@pytest.mark.unit
def test_the_proposed_arguments_are_exposed_to_policy_under_args() -> None:
    merged = merge_environment({}, None, proposed={"customer_id": "c-1"})

    assert merged["args"] == {"customer_id": "c-1"}


@pytest.mark.unit
def test_the_decision_environment_reaches_the_invocation(
    governor: Governor,
    search_spec: ArgumentSpec,
    entitled_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=entitled_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
        environment={"channel": "agent", "request_id": "r-1"},
    )

    assert plan.invocation.channel == "agent"
    assert plan.invocation.environment["request_id"] == "r-1"
    assert plan.invocation.proposed == {"customer_id": "c-1"}


# --- narrowing: the outcome half of the envelope ---------------------------------------
#
# ``Plan.narrowing`` is defined against the *proposal*, not against ``rejected``, and the
# two differ in both directions. These pin that definition, because the envelope's
# ``narrowed``/``guidance`` fields are only trustworthy if it holds.


@pytest.mark.unit
def test_a_rejected_argument_refilled_from_a_default_is_narrowed(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1", "region": "nowhere"},
    )

    assert plan.processed["region"] == "eu-west"
    assert plan.narrowing() == (("region",), ())


@pytest.mark.unit
def test_a_rejected_argument_with_no_default_is_narrowed_and_unsupplied(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    """``limit`` carries a range and no default, so nothing refills the slot.

    The callable's own signature default lands there instead, which no constraint ever
    checked — so the envelope must be able to say this part of the result is unverified.
    """
    plan = governor.plan(
        search_spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1", "limit": 9999},
    )

    assert "limit" not in plan.processed
    assert plan.narrowing() == (("limit",), ("limit",))
    envelope = plan.envelope()
    assert envelope is not None
    assert "unverified" in str(envelope.guidance)


@pytest.mark.unit
def test_an_argument_that_survives_is_not_narrowed(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    plan = governor.plan(
        search_spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1", "region": "eu-west", "limit": 5},
    )

    assert plan.narrowing() == ((), ())
    envelope = plan.envelope()
    assert envelope is not None
    assert envelope.narrowed is False
    assert envelope.guidance is None


@pytest.mark.unit
def test_a_default_injected_for_an_argument_nobody_proposed_is_not_narrowing(
    governor: Governor,
    search_spec: ArgumentSpec,
    constrained_principal: Principal,
) -> None:
    """Nothing was taken away, so there is nothing to disclose as an adjustment.

    This is the case that makes ``narrowed`` worth having as a separate field:
    ``defaults_applied`` is non-empty here and the caller got exactly what they asked for.
    """
    plan = governor.plan(
        search_spec,
        principal=constrained_principal,
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    assert plan.defaults_applied
    assert plan.narrowing() == ((), ())
