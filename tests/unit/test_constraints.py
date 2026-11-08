"""The argument filter: which proposed values survive, and which defaults fill the gaps."""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction

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


# --- a deny-set reaches inside a container --------------------------------------------
#
# Denial is the fail-closed direction, so it is element-wise: wrapping a forbidden value in a
# list must not defeat the rule that names it. Permission stays scalar-only -- see the guards
# at the end of this section, which pin that asymmetry in place.


@pytest.mark.unit
def test_a_deny_set_rejects_a_denied_value_inside_a_list() -> None:
    rejection = ArgumentConstraint(deny=("prod",)).check("targets", ["dev", "prod"])

    assert rejection is not None
    assert rejection.rule == "deny-set"


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        ["prod"],
        ("prod",),
        {"prod"},
        frozenset({"prod"}),
        [["dev"], ["prod"]],
        {"env": "prod"},
        {"env": ["prod"]},
        [{"env": {"name": "prod"}}],
    ],
)
def test_a_deny_set_reaches_a_denied_value_however_deeply_it_is_wrapped(value: object) -> None:
    rejection = ArgumentConstraint(deny=("prod",)).check("targets", value)

    assert rejection is not None
    assert rejection.rule == "deny-set"


@pytest.mark.unit
def test_a_deny_set_reads_a_mappings_keys_as_well_as_its_values() -> None:
    """A denied name used as a key is as much a reference to it as one used as a value."""
    rejection = ArgumentConstraint(deny=("prod",)).check("overrides", {"prod": {"replicas": 9}})

    assert rejection is not None
    assert rejection.rule == "deny-set"


@pytest.mark.unit
def test_a_container_of_values_the_deny_set_does_not_list_is_still_admitted() -> None:
    constraint = ArgumentConstraint(deny=("prod",))

    assert constraint.check("targets", ["dev", "staging"]) is None
    assert constraint.check("overrides", {"dev": ["eu", "us"]}) is None
    assert constraint.check("targets", []) is None


@pytest.mark.unit
def test_a_rejection_from_inside_a_container_still_names_the_argument_and_the_grant() -> None:
    rejection = ArgumentConstraint(deny=("prod",), policy="grant-no-prod").check(
        "targets", ["dev", "prod"]
    )

    assert rejection is not None
    assert rejection.name == "targets"
    assert rejection.policy == "grant-no-prod"
    assert rejection.reason
    assert rejection.value == ["dev", "prod"]


@pytest.mark.unit
def test_a_denied_element_and_a_denied_value_are_told_apart_in_the_reason() -> None:
    """Both are ``deny-set``; a caller still has to be able to see where the value was."""
    constraint = ArgumentConstraint(deny=("prod",))

    direct = constraint.check("target", "prod")
    contained = constraint.check("targets", ["dev", "prod"])

    assert direct is not None
    assert contained is not None
    assert direct.reason != contained.reason


@pytest.mark.unit
def test_a_string_is_a_leaf_and_is_never_read_character_by_character() -> None:
    """A guard, not a change: iterating a string would turn a deny-set into a substring rule."""
    assert ArgumentConstraint(deny=("p",)).check("target", "prod") is None
    assert ArgumentConstraint(deny=(b"p",)).check("target", b"prod") is None


@pytest.mark.unit
def test_a_denied_element_is_still_matched_by_type_as_well_as_by_value() -> None:
    assert ArgumentConstraint(deny=(1,)).check("flags", [True]) is None
    assert ArgumentConstraint(deny=(True,)).check("flags", [1]) is None
    assert ArgumentConstraint(deny=(1,)).check("flags", [1]) is not None


@pytest.mark.unit
def test_a_self_referential_proposal_is_rejected_rather_than_followed_forever() -> None:
    """A proposal is untrusted input, so a cycle in it must fail closed, not blow the stack."""
    circular: list[object] = ["dev"]
    circular.append(circular)

    rejection = ArgumentConstraint(deny=("prod",)).check("targets", circular)

    assert rejection is not None
    assert rejection.rule == "deny-set"


@pytest.mark.unit
def test_a_proposal_nested_past_what_is_searched_is_rejected_unsearched() -> None:
    nested: object = "dev"
    for _ in range(64):
        nested = [nested]

    rejection = ArgumentConstraint(deny=("prod",)).check("targets", nested)

    assert rejection is not None
    assert rejection.rule == "deny-set"


@pytest.mark.unit
def test_an_allow_set_still_rejects_a_container_outright_rather_than_element_wise() -> None:
    """The asymmetry, stated where it would be easiest to "fix" by accident.

    Reading an allow-set element-wise would *widen* what a principal may pass -- a list of
    permitted values would satisfy a rule written about one value -- so it stays scalar-only.
    """
    rejection = ArgumentConstraint(allow=("dev", "prod")).check("targets", ["dev"])

    assert rejection is not None
    assert rejection.rule == "allow-set"


@pytest.mark.unit
def test_a_pattern_and_a_bound_still_reject_a_container_as_not_comparable() -> None:
    pattern = ArgumentConstraint(pattern="[a-z]+").check("targets", ["dev"])
    bound = ArgumentConstraint(maximum=50).check("limits", [10])

    assert pattern is not None
    assert pattern.rule == "not-comparable"
    assert bound is not None
    assert bound.rule == "not-comparable"


# --- what can carry a numeric bound ---------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("amount", [Decimal("1"), Decimal("50.25"), Decimal("100")])
def test_a_decimal_satisfies_a_numeric_bound(amount: Decimal) -> None:
    """``Decimal`` is the type money is held in, and a desk limit is a bound on money."""
    assert ArgumentConstraint(minimum=1, maximum=100).check("amount", amount) is None


@pytest.mark.unit
def test_a_decimal_above_the_maximum_is_rejected_as_too_large_not_as_uncomparable() -> None:
    rejection = ArgumentConstraint(maximum=1000).check("amount", Decimal("1500.00"))

    assert rejection is not None
    assert rejection.rule == "maximum"


@pytest.mark.unit
def test_a_decimal_below_the_minimum_is_rejected_as_too_small() -> None:
    rejection = ArgumentConstraint(minimum=1).check("amount", Decimal("0.50"))

    assert rejection is not None
    assert rejection.rule == "minimum"


@pytest.mark.unit
def test_a_decimal_is_compared_at_its_own_precision_not_through_a_float() -> None:
    """The point of accepting ``Decimal`` at all: the bound decides on the exact value."""
    constraint = ArgumentConstraint(maximum=1000)

    assert constraint.check("amount", Decimal("1000.00")) is None

    rejection = constraint.check("amount", Decimal("1000.01"))

    assert rejection is not None
    assert rejection.rule == "maximum"


@pytest.mark.unit
def test_any_other_real_number_carries_a_bound_too() -> None:
    constraint = ArgumentConstraint(minimum=1, maximum=50)

    assert constraint.check("limit", Fraction(99, 2)) is None

    rejection = constraint.check("limit", Fraction(101, 2))

    assert rejection is not None
    assert rejection.rule == "maximum"


@pytest.mark.unit
@pytest.mark.parametrize("value", [Decimal("NaN"), Decimal("sNaN"), float("nan")])
def test_a_value_that_is_not_a_number_cannot_be_bounded(value: object) -> None:
    """A NaN orders against nothing, so a bound has nothing to say about it: fail closed.

    Stated against both spellings because they fail differently in Python -- a ``Decimal`` NaN
    raises from an ordering comparison and a ``float`` NaN answers ``False`` to all of them,
    which would quietly satisfy a lone ``maximum``.
    """
    rejection = ArgumentConstraint(maximum=1000).check("amount", value)

    assert rejection is not None
    assert rejection.rule == "not-comparable"


@pytest.mark.unit
def test_an_infinity_is_still_ordered_against_a_bound() -> None:
    """Unlike a NaN it has a side of the bound, and the side it is on is the wrong one."""
    above = ArgumentConstraint(maximum=1000).check("amount", Decimal("Infinity"))
    below = ArgumentConstraint(minimum=1).check("amount", Decimal("-Infinity"))

    assert above is not None
    assert above.rule == "maximum"
    assert below is not None
    assert below.rule == "minimum"


@pytest.mark.unit
def test_a_boolean_still_cannot_satisfy_a_numeric_bound() -> None:
    """A guard, not a change: ``True >= 1`` must not make a flag a number."""
    rejection = ArgumentConstraint(minimum=1, maximum=50).check("limit", True)

    assert rejection is not None
    assert rejection.rule == "not-comparable"


@pytest.mark.unit
def test_a_number_that_cannot_be_ordered_cannot_satisfy_a_bound() -> None:
    """``complex`` is a number and is not ordered, so a bound cannot be tested against it."""
    rejection = ArgumentConstraint(minimum=1).check("limit", 1j)

    assert rejection is not None
    assert rejection.rule == "not-comparable"


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


# --- defaults for a name the signature does not list ----------------------------------
#
# A callable declaring ``**kwargs`` accepts names its signature does not list, so a default
# for one of them is deliverable. It is opt-in because the parameter filter exists to stop a
# stale grant making an ordinary call fail with an unexpected keyword argument.


@pytest.mark.unit
def test_a_default_for_an_unlisted_name_is_injectable_when_unlisted_names_are_accepted() -> None:
    constraints = _one("tenant", ArgumentConstraint(default="acme"))

    arguments, applied, _ = constraints.inject_defaults({}, ("customer_id",), accept_unlisted=True)

    assert arguments == {"tenant": "acme"}
    assert applied == {"tenant": "acme"}


@pytest.mark.unit
def test_a_default_for_an_unlisted_name_is_skipped_unless_unlisted_names_are_accepted() -> None:
    constraints = _one("tenant", ArgumentConstraint(default="acme"))

    arguments, applied, _ = constraints.inject_defaults({}, ("customer_id",), accept_unlisted=False)

    assert arguments == {}
    assert applied == {}


@pytest.mark.unit
def test_an_unlisted_default_fills_the_gap_a_rejected_value_left() -> None:
    """The shape the promise is for: a bounded kwargs-only argument narrows, it does not die."""
    constraints = _one("tenant", ArgumentConstraint(allow=("acme",), default="acme"))

    kept, rejected = constraints.filter({"tenant": "globex"})
    arguments, applied, _ = constraints.inject_defaults(
        kept, ("customer_id",), accept_unlisted=True
    )

    assert [item.name for item in rejected] == ["tenant"]
    assert arguments == {"tenant": "acme"}
    assert applied == {"tenant": "acme"}


@pytest.mark.unit
def test_an_unlisted_default_is_still_checked_against_its_own_constraint() -> None:
    """Accepting unlisted names widens *which* defaults are deliverable, not *whether*."""
    constraints = _one("tenant", ArgumentConstraint(allow=("acme",), default="globex"))

    arguments, applied, withheld = constraints.inject_defaults(
        {}, ("customer_id",), accept_unlisted=True
    )

    assert arguments == {}
    assert applied == {}
    assert [item.name for item in withheld] == ["tenant"]


@pytest.mark.unit
def test_accepting_unlisted_names_still_never_overrides_a_supplied_value() -> None:
    constraints = _one("tenant", ArgumentConstraint(default="acme"))

    arguments, applied, _ = constraints.inject_defaults(
        {"tenant": "globex"}, (), accept_unlisted=True
    )

    assert arguments == {"tenant": "globex"}
    assert applied == {}


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


@pytest.mark.unit
@_HYPOTHESIS
@given(
    denied=st.frozensets(_VALUES, min_size=1, max_size=5),
    proposed=st.lists(_VALUES, max_size=6),
)
def test_a_deny_set_rejects_a_container_exactly_when_it_holds_a_denied_value(
    denied: frozenset[int],
    proposed: list[int],
) -> None:
    constraint = ArgumentConstraint(deny=tuple(sorted(denied)))

    rejection = constraint.check("targets", proposed)

    if denied & set(proposed):
        assert rejection is not None
        assert rejection.rule == "deny-set"
    else:
        assert rejection is None


@pytest.mark.unit
@_HYPOTHESIS
@given(
    amount=st.decimals(min_value=-20, max_value=20, places=2),
    minimum=st.none() | _VALUES,
    maximum=st.none() | _VALUES,
)
def test_a_decimal_is_bounded_by_exactly_the_comparison_the_bound_states(
    amount: Decimal,
    minimum: int | None,
    maximum: int | None,
) -> None:
    constraint = ArgumentConstraint(minimum=minimum, maximum=maximum)
    satisfies = (minimum is None or amount >= minimum) and (maximum is None or amount <= maximum)

    rejection = constraint.check("amount", amount)

    assert (rejection is None) is satisfies
    if rejection is not None:
        assert rejection.rule in {"minimum", "maximum"}
