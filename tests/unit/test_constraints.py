"""The argument filter: which proposed values survive, and which defaults fill the gaps."""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sentrykit.constraints import ArgumentConstraint, ConstraintSet

# The autouse reset in conftest is function-scoped; hypothesis re-runs the test body many
# times inside a single fixture setup, which is fine here because none of these tests touch
# the process-wide state the fixture guards.
_HYPOTHESIS = settings(suppress_health_check=[HealthCheck.function_scoped_fixture])


def _one(name: str, constraint: ArgumentConstraint) -> ConstraintSet:
    return ConstraintSet(arguments={name: constraint})


# --- checking a single value ----------------------------------------------------------


@pytest.mark.unit
def test_an_empty_constraint_permits_anything() -> None:
    assert ArgumentConstraint().check("customer_id", "anything") is None


@pytest.mark.unit
def test_an_allow_set_admits_a_member() -> None:
    constraint = ArgumentConstraint(allow=("c-1", "c-2"))

    assert constraint.check("customer_id", "c-2") is None


@pytest.mark.unit
def test_an_allow_set_rejects_a_non_member_and_says_why() -> None:
    constraint = ArgumentConstraint(allow=("c-1", "c-2"), policy="grant-orders-customers")

    rejection = constraint.check("customer_id", "c-9")

    assert rejection is not None
    assert rejection.name == "customer_id"
    assert rejection.rule == "allow-set"
    assert rejection.reason
    assert rejection.policy == "grant-orders-customers"
    assert rejection.value == "c-9"


@pytest.mark.unit
def test_a_deny_set_rejects_a_listed_value() -> None:
    rejection = ArgumentConstraint(deny=("c-9",)).check("customer_id", "c-9")

    assert rejection is not None
    assert rejection.rule == "deny-set"


@pytest.mark.unit
def test_a_deny_set_admits_anything_it_does_not_list() -> None:
    assert ArgumentConstraint(deny=("c-9",)).check("customer_id", "c-1") is None


@pytest.mark.unit
def test_a_pattern_must_match_the_whole_value() -> None:
    constraint = ArgumentConstraint(pattern=r"cust-\d+")

    assert constraint.check("customer_id", "cust-12") is None

    rejection = constraint.check("customer_id", "cust-12x")

    assert rejection is not None
    assert rejection.rule == "pattern"


@pytest.mark.unit
def test_a_pattern_rejects_a_non_string_rather_than_coercing_it() -> None:
    rejection = ArgumentConstraint(pattern=r"cust-\d+").check("customer_id", 12)

    assert rejection is not None
    assert rejection.rule == "not-comparable"


@pytest.mark.unit
@pytest.mark.parametrize("value", [1, 25, 50])
def test_range_bounds_are_inclusive(value: int) -> None:
    assert ArgumentConstraint(minimum=1, maximum=50).check("limit", value) is None


@pytest.mark.unit
def test_a_value_below_the_minimum_is_rejected() -> None:
    rejection = ArgumentConstraint(minimum=1, maximum=50).check("limit", 0)

    assert rejection is not None
    assert rejection.rule == "minimum"


@pytest.mark.unit
def test_a_value_above_the_maximum_is_rejected() -> None:
    rejection = ArgumentConstraint(minimum=1, maximum=50).check("limit", 51)

    assert rejection is not None
    assert rejection.rule == "maximum"


@pytest.mark.unit
def test_a_non_numeric_value_cannot_be_range_checked() -> None:
    rejection = ArgumentConstraint(minimum=1).check("limit", "ten")

    assert rejection is not None
    assert rejection.rule == "not-comparable"


@pytest.mark.unit
def test_an_explicit_default_of_none_still_counts_as_a_default() -> None:
    assert ArgumentConstraint(default=None).has_default is True
    assert ArgumentConstraint().has_default is False
    assert ArgumentConstraint(default="c-1").has_default is True


@pytest.mark.unit
def test_a_rejection_detail_omits_the_offending_value() -> None:
    rejection = ArgumentConstraint(allow=("c-1",), policy="p").check("customer_id", "secret")

    assert rejection is not None
    detail = rejection.as_detail()

    assert detail["name"] == "customer_id"
    assert detail["rule"] == "allow-set"
    assert "secret" not in str(detail)


@pytest.mark.unit
def test_describing_a_constraint_reports_the_rules_it_enforces() -> None:
    described = ArgumentConstraint(allow=("c-1", "c-2"), minimum=1).describe()

    assert "c-1" in str(described)


# --- filtering a whole call -----------------------------------------------------------


@pytest.mark.unit
def test_an_empty_constraint_set_is_falsey_and_keeps_everything() -> None:
    empty = ConstraintSet()

    kept, rejected = empty.filter({"customer_id": "c-9", "limit": 9_000})

    assert not empty
    assert kept == {"customer_id": "c-9", "limit": 9_000}
    assert rejected == ()


@pytest.mark.unit
def test_an_argument_with_no_entry_in_the_set_is_unconstrained() -> None:
    constraints = _one("customer_id", ArgumentConstraint(allow=("c-1",)))

    kept, rejected = constraints.filter({"customer_id": "c-1", "note": "anything at all"})

    assert kept == {"customer_id": "c-1", "note": "anything at all"}
    assert rejected == ()


@pytest.mark.unit
def test_filtering_keeps_the_valid_arguments_and_reports_the_rest() -> None:
    constraints = ConstraintSet(
        arguments={
            "customer_id": ArgumentConstraint(allow=("c-1", "c-2")),
            "limit": ArgumentConstraint(minimum=1, maximum=50),
        }
    )

    kept, rejected = constraints.filter({"customer_id": "c-1", "limit": 500})

    assert kept == {"customer_id": "c-1"}
    assert [item.name for item in rejected] == ["limit"]
    assert rejected[0].rule == "maximum"


@pytest.mark.unit
def test_filtering_never_raises_on_a_rejection() -> None:
    constraints = _one("customer_id", ArgumentConstraint(allow=("c-1",)))

    kept, rejected = constraints.filter({"customer_id": "c-9"})

    assert kept == {}
    assert len(rejected) == 1


# --- defaults -------------------------------------------------------------------------


@pytest.mark.unit
def test_a_default_fills_an_argument_the_caller_omitted() -> None:
    constraints = _one("region", ArgumentConstraint(default="eu-west"))

    arguments, applied, _ = constraints.inject_defaults({}, ("region", "limit"))

    assert arguments == {"region": "eu-west"}
    assert applied == {"region": "eu-west"}


@pytest.mark.unit
def test_a_default_never_overrides_a_value_the_caller_supplied() -> None:
    constraints = _one("region", ArgumentConstraint(default="eu-west"))

    arguments, applied, _ = constraints.inject_defaults({"region": "eu-north"}, ("region",))

    assert arguments == {"region": "eu-north"}
    assert applied == {}


@pytest.mark.unit
def test_a_default_replaces_an_argument_that_was_dropped() -> None:
    constraints = _one(
        "region",
        ArgumentConstraint(pattern=r"eu-[a-z]+", default="eu-west"),
    )
    kept, rejected = constraints.filter({"region": "us-east"})

    arguments, applied, _ = constraints.inject_defaults(kept, ("region",))

    assert len(rejected) == 1
    assert arguments == {"region": "eu-west"}
    assert applied == {"region": "eu-west"}


@pytest.mark.unit
def test_a_default_for_a_parameter_the_callable_does_not_accept_is_skipped() -> None:
    constraints = _one("tenant", ArgumentConstraint(default="acme"))

    arguments, applied, _ = constraints.inject_defaults({}, ("customer_id",))

    assert arguments == {}
    assert applied == {}


@pytest.mark.unit
def test_an_argument_with_no_configured_default_is_left_absent() -> None:
    constraints = _one("limit", ArgumentConstraint(minimum=1))

    arguments, applied, _ = constraints.inject_defaults({}, ("limit",))

    assert arguments == {}
    assert applied == {}


@pytest.mark.unit
def test_an_explicit_default_of_none_is_injectable() -> None:
    constraints = _one("region", ArgumentConstraint(default=None))

    arguments, applied, _ = constraints.inject_defaults({}, ("region",))

    assert arguments == {"region": None}
    assert applied == {"region": None}


# --- required arguments ---------------------------------------------------------------


@pytest.mark.unit
def test_a_required_argument_with_no_value_and_no_default_is_reported() -> None:
    constraints = ConstraintSet(
        arguments={
            "tenant": ArgumentConstraint(required=True),
            "fmt": ArgumentConstraint(required=True, default="csv"),
        }
    )

    assert constraints.missing_required(("fmt",)) == ("tenant",)


@pytest.mark.unit
def test_nothing_is_missing_once_every_required_argument_has_a_value() -> None:
    constraints = _one("tenant", ArgumentConstraint(required=True))

    assert constraints.missing_required(("tenant",)) == ()


@pytest.mark.unit
def test_an_optional_argument_is_never_reported_missing() -> None:
    constraints = _one("region", ArgumentConstraint(default="eu-west"))

    assert constraints.missing_required(()) == ()


# --- merging --------------------------------------------------------------------------


@pytest.mark.unit
def test_merging_replaces_a_constraint_outright_rather_than_field_by_field() -> None:
    baseline = _one("limit", ArgumentConstraint(minimum=1, maximum=5))
    specific = _one("limit", ArgumentConstraint(allow=(1, 2, 3)))

    merged = baseline.merged_with(specific)

    assert merged.arguments["limit"].allow == (1, 2, 3)
    assert merged.arguments["limit"].minimum is None
    assert merged.arguments["limit"].maximum is None


@pytest.mark.unit
def test_merging_keeps_the_arguments_the_other_set_says_nothing_about() -> None:
    baseline = ConstraintSet(
        arguments={
            "limit": ArgumentConstraint(maximum=5),
            "tenant": ArgumentConstraint(allow=("acme",)),
        }
    )
    specific = _one("limit", ArgumentConstraint(maximum=50))

    merged = baseline.merged_with(specific)

    assert merged.arguments["limit"].maximum == 50
    assert merged.arguments["tenant"].allow == ("acme",)


@pytest.mark.unit
def test_merging_leaves_both_operands_unchanged() -> None:
    baseline = _one("limit", ArgumentConstraint(maximum=5))
    specific = _one("limit", ArgumentConstraint(maximum=50))

    baseline.merged_with(specific)

    assert baseline.arguments["limit"].maximum == 5
    assert specific.arguments["limit"].maximum == 50


@pytest.mark.unit
def test_describing_a_set_names_every_constrained_argument() -> None:
    constraints = ConstraintSet(
        arguments={
            "customer_id": ArgumentConstraint(allow=("c-1",)),
            "limit": ArgumentConstraint(maximum=50),
        }
    )

    described = constraints.describe()

    assert "customer_id" in described
    assert "limit" in described


# --- properties -----------------------------------------------------------------------


_VALUES = st.integers(min_value=-20, max_value=20)


@pytest.mark.unit
@_HYPOTHESIS
@given(
    allow=st.none() | st.frozensets(_VALUES, min_size=1, max_size=5),
    minimum=st.none() | _VALUES,
    maximum=st.none() | _VALUES,
    value=_VALUES,
)
def test_filtering_keeps_exactly_the_values_that_satisfy_their_constraint(
    allow: frozenset[int] | None,
    minimum: int | None,
    maximum: int | None,
    value: int,
) -> None:
    constraint = ArgumentConstraint(
        allow=None if allow is None else tuple(sorted(allow)),
        minimum=minimum,
        maximum=maximum,
    )
    satisfies = (
        (allow is None or value in allow)
        and (minimum is None or value >= minimum)
        and (maximum is None or value <= maximum)
    )

    kept, rejected = _one("limit", constraint).filter({"limit": value})

    if satisfies:
        assert kept == {"limit": value}
        assert rejected == ()
    else:
        assert kept == {}
        assert [item.name for item in rejected] == ["limit"]
        assert rejected[0].rule in {"allow-set", "minimum", "maximum"}


@pytest.mark.unit
@_HYPOTHESIS
@given(
    allowed=st.lists(_VALUES, min_size=2, max_size=6, unique=True),
    index=st.integers(min_value=0, max_value=5),
)
def test_an_injected_default_never_overrides_a_supplied_valid_value(
    allowed: list[int],
    index: int,
) -> None:
    supplied = allowed[index % len(allowed)]
    default = allowed[(index + 1) % len(allowed)]
    constraints = _one("limit", ArgumentConstraint(allow=tuple(allowed), default=default))

    kept, rejected = constraints.filter({"limit": supplied})
    arguments, applied, _ = constraints.inject_defaults(kept, ("limit",))

    assert rejected == ()
    assert arguments == {"limit": supplied}
    assert applied == {}


@pytest.mark.unit
@_HYPOTHESIS
@given(
    allowed=st.lists(_VALUES, min_size=1, max_size=6, unique=True),
    proposed=_VALUES,
)
def test_a_rejected_value_is_replaced_by_the_default_and_never_reaches_the_callable(
    allowed: list[int],
    proposed: int,
) -> None:
    default = allowed[0]
    constraints = _one("limit", ArgumentConstraint(allow=tuple(allowed), default=default))

    kept, rejected = constraints.filter({"limit": proposed})
    arguments, _applied, _ = constraints.inject_defaults(kept, ("limit",))

    assert arguments["limit"] in allowed
    if proposed not in allowed:
        assert len(rejected) == 1
        assert arguments["limit"] == default
