"""A constraint has to be satisfiable, and its own default has to satisfy it.

Two faults that used to be found at call time, by whoever called next:

* **An injected default was never checked.** A supplied value was filtered and an omitted one
  was filled in, and only the first path ran a check — so the way to defeat a constraint was
  to stop proposing a value. ``inject_defaults`` now withholds a default its own constraint
  rejects.
* **An unsatisfiable constraint stored silently.** ``minimum=100, maximum=10`` constructed
  without complaint and surfaced later as a refusal of everything.
  ``ArgumentConstraint.inconsistencies`` names the fault, and a grant store runs it at the
  write.

The write-time check is the primary defense and the call-time check is the backstop, because
a constraint set can also be built in code without a store ever seeing it.
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest

from sentrykit.audit import AuditTrail
from sentrykit.cedar import Entity, EntityRef, PolicyEngine
from sentrykit.config import configure
from sentrykit.constraints import ArgumentConstraint, ConstraintSet
from sentrykit.context import Principal
from sentrykit.engine import ArgumentSpec, Governor
from sentrykit.errors import ArgumentRejected, ConfigurationError, DefaultUnavailable
from sentrykit.stores.base import GrantSpec
from sentrykit.stores.jsonfile import JsonFileGrantStore
from sentrykit.stores.memory import InMemoryAuditSink, InMemoryGrantStore

ALICE = EntityRef("User", "alice")
SEARCH_ACTION = EntityRef("Action", "tool.search_orders")
ORDERS_TOOL = EntityRef("Tool", "orders")

POLICY = '@id("anyone-may-search")\npermit (principal, action, resource);'


def search_orders(
    customer_id: str = "c-1", limit: int = 10, region: str = "eu"
) -> dict[str, object]:
    return {"customer_id": customer_id, "limit": limit, "region": region}


def export_orders(tenant: str = "") -> dict[str, object]:
    return {"tenant": tenant}


@pytest.fixture
def governor() -> Governor:
    return Governor(PolicyEngine(POLICY, (Entity(ORDERS_TOOL),)))


def _principal(**constraints: ArgumentConstraint) -> Principal:
    return Principal(
        id="alice",
        constraints={'Action::"tool.search_orders"': ConstraintSet(arguments=dict(constraints))},
    )


# --- a default is checked against its own constraint ------------------------------------


@pytest.mark.unit
def test_a_default_its_own_constraint_rejects_is_withheld_rather_than_injected() -> None:
    """The exact pair that used to sail through: an inverted range and an off-list default."""
    constraints = ConstraintSet(
        arguments={
            "limit": ArgumentConstraint(minimum=100, maximum=10, default=500),
            "region": ArgumentConstraint(allow=("eu", "uk"), default="us"),
        }
    )

    result = constraints.inject_defaults({}, ("limit", "region"))

    assert result.arguments == {}
    assert result.applied == {}
    assert {item.name for item in result.withheld} == {"limit", "region"}
    assert {item.rule for item in result.withheld} == {"maximum", "allow-set"}


@pytest.mark.unit
def test_a_default_that_satisfies_its_constraint_is_still_injected() -> None:
    constraints = ConstraintSet(
        arguments={"region": ArgumentConstraint(allow=("eu", "uk"), default="eu")}
    )

    result = constraints.inject_defaults({}, ("region",))

    assert result.arguments == {"region": "eu"}
    assert result.applied == {"region": "eu"}
    assert result.withheld == ()


@pytest.mark.unit
def test_withholding_carries_the_constraints_provenance_but_not_the_default_value() -> None:
    constraints = ConstraintSet(
        arguments={"region": ArgumentConstraint(allow=("eu",), default="us", policy="grant-region")}
    )

    (withheld,) = constraints.inject_defaults({}, ("region",)).withheld

    assert withheld.policy == "grant-region"
    # The default *value* is withheld from the report for the same reason ``describe`` omits
    # it: a per-principal default can itself be sensitive.
    assert withheld.value is None
    assert "us" not in withheld.reason


@pytest.mark.unit
def test_omitting_an_argument_no_longer_defeats_its_constraint(
    governor: Governor,
) -> None:
    """The end-to-end shape of the defect: propose nothing, receive the forbidden value."""
    spec = ArgumentSpec.from_callable(search_orders)

    plan = governor.plan(
        spec,
        principal=_principal(region=ArgumentConstraint(allow=("eu", "uk"), default="us")),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    assert "region" not in plan.processed or plan.processed["region"] != "us"
    assert [item.name for item in plan.rejected] == ["region"]


@pytest.mark.unit
def test_a_required_argument_whose_default_is_unusable_refuses_the_call(
    governor: Governor,
) -> None:
    spec = ArgumentSpec.from_callable(export_orders)
    principal = Principal(
        id="alice",
        constraints={
            'Action::"tool.search_orders"': ConstraintSet(
                arguments={
                    "tenant": ArgumentConstraint(allow=("acme",), default="globex", required=True)
                }
            )
        },
    )

    with pytest.raises(DefaultUnavailable) as caught:
        governor.plan(spec, principal=principal, action=SEARCH_ACTION, resource=ORDERS_TOOL)

    assert caught.value.name == "tenant"


@pytest.mark.unit
def test_a_withheld_default_is_not_blamed_on_the_caller_under_strict_handling(
    governor: Governor,
) -> None:
    """``arg_handling`` arbitrates the caller's proposal; an unusable default is not theirs.

    Strict handling turns a *rejected proposal* into ``ArgumentRejected``. Raising it for an
    argument the caller never mentioned would report an operator's misconfiguration as the
    caller's mistake, and would give them nothing to change.
    """
    configure(arg_handling="strict")
    spec = ArgumentSpec.from_callable(search_orders)

    plan = governor.plan(
        spec,
        principal=_principal(region=ArgumentConstraint(allow=("eu",), default="us")),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    assert [item.name for item in plan.rejected] == ["region"]


@pytest.mark.unit
def test_a_supplied_value_is_still_the_one_that_raises_under_strict_handling(
    governor: Governor,
) -> None:
    configure(arg_handling="strict")
    spec = ArgumentSpec.from_callable(search_orders)

    with pytest.raises(ArgumentRejected):
        governor.plan(
            spec,
            principal=_principal(region=ArgumentConstraint(allow=("eu",), default="us")),
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"region": "cn"},
        )


@pytest.mark.unit
def test_a_withheld_default_reaches_the_audit_record(governor: Governor) -> None:
    sink = InMemoryAuditSink()
    audited = Governor(governor.policy, audit=AuditTrail(sink))
    spec = ArgumentSpec.from_callable(search_orders)

    audited.plan(
        spec,
        principal=_principal(region=ArgumentConstraint(allow=("eu",), default="us")),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"customer_id": "c-1"},
    )

    (record,) = sink.records
    assert [item.name for item in record.rejected] == ["region"]


# --- a constraint has to be satisfiable -------------------------------------------------


@pytest.mark.unit
def test_inverted_bounds_are_reported() -> None:
    (problem,) = ArgumentConstraint(minimum=100, maximum=10).inconsistencies()

    assert "minimum 100 is above maximum 10" in problem


@pytest.mark.unit
def test_an_uncompilable_pattern_is_reported() -> None:
    (problem,) = ArgumentConstraint(pattern="[unclosed").inconsistencies()

    assert "not a valid regular expression" in problem


@pytest.mark.unit
def test_a_structural_fault_short_circuits_the_value_level_probes() -> None:
    """Every value fails under a broken pattern, so restating it per value says nothing new."""
    problems = ArgumentConstraint(
        pattern="[unclosed", allow=("eu", "uk"), default="eu"
    ).inconsistencies()

    assert len(problems) == 1


@pytest.mark.unit
def test_a_permitted_value_the_pattern_rejects_is_dead_configuration() -> None:
    (problem,) = ArgumentConstraint(allow=("eu", "US"), pattern="[a-z]+").inconsistencies()

    assert "'US'" in problem
    assert "does not match the required pattern" in problem


@pytest.mark.unit
def test_a_permitted_value_outside_the_bounds_is_reported() -> None:
    (problem,) = ArgumentConstraint(allow=(5, 500), minimum=1, maximum=50).inconsistencies()

    assert "500" in problem
    assert "above the maximum" in problem


@pytest.mark.unit
def test_a_default_outside_the_allow_set_is_reported_without_naming_it() -> None:
    (problem,) = ArgumentConstraint(allow=("eu", "uk"), default="us").inconsistencies()

    assert "the configured default does not satisfy" in problem
    assert "us" not in problem


@pytest.mark.unit
def test_a_deny_set_that_swallows_the_allow_set_is_reported() -> None:
    problems = ArgumentConstraint(allow=("eu",), deny=("eu",)).inconsistencies()

    assert len(problems) == 1
    assert "explicitly denied" in problems[0]


@pytest.mark.unit
def test_a_default_the_deny_set_reaches_inside_is_reported() -> None:
    """The write-time half of element-wise denial, and the reason it has to be the same check.

    A default is injected for an argument nobody proposed, so a deny-set the filter reads
    element-wise and the write-time check does not would store clean and then hand the
    forbidden value back through the default.
    """
    (problem,) = ArgumentConstraint(deny=("prod",), default=["dev", "prod"]).inconsistencies()

    assert "the configured default does not satisfy" in problem
    assert "denied" in problem


@pytest.mark.unit
def test_a_permitted_container_the_deny_set_reaches_inside_is_dead_configuration() -> None:
    (problem,) = ArgumentConstraint(
        allow=(("dev",), ("dev", "prod")), deny=("prod",)
    ).inconsistencies()

    assert "'prod'" in problem
    assert "denied" in problem


@pytest.mark.unit
def test_a_grant_store_refuses_a_default_the_deny_set_reaches_inside() -> None:
    store = InMemoryGrantStore()

    with pytest.raises(ConfigurationError) as caught:
        store.grant(
            GrantSpec(
                principal=ALICE,
                kind="constraint",
                subject="targets",
                constraint=ArgumentConstraint(deny=("prod",), default=["prod"]),
            )
        )

    assert "cannot be satisfied" in str(caught.value)
    assert store.grants_for(ALICE) == ()


@pytest.mark.unit
def test_a_decimal_default_inside_its_bounds_is_not_a_fault() -> None:
    """A desk limit on money: the grant is coherent, so the write must not refuse it."""
    assert (
        ArgumentConstraint(minimum=1, maximum=1000, default=Decimal("500.00")).inconsistencies()
        == ()
    )


@pytest.mark.unit
def test_a_decimal_default_outside_its_bounds_is_reported_as_out_of_bounds() -> None:
    (problem,) = ArgumentConstraint(
        minimum=1, maximum=1000, default=Decimal("1500.00")
    ).inconsistencies()

    assert "above the maximum" in problem


@pytest.mark.unit
def test_a_grant_store_accepts_a_decimal_desk_limit() -> None:
    store = InMemoryGrantStore()

    record = store.grant(
        GrantSpec(
            principal=ALICE,
            kind="constraint",
            subject="amount",
            constraint=ArgumentConstraint(minimum=1, maximum=1000, default=Decimal("500.00")),
        )
    )

    assert record.spec.subject == "amount"


@pytest.mark.unit
def test_a_coherent_constraint_has_nothing_to_report() -> None:
    assert (
        ArgumentConstraint(
            allow=("eu", "uk"), pattern="[a-z]{2}", minimum=None, default="eu"
        ).inconsistencies()
        == ()
    )


@pytest.mark.unit
def test_a_required_argument_with_a_default_is_not_a_contradiction() -> None:
    """It looks like one and is not.

    ``inject_defaults`` skips any name the callable does not accept, so a required, defaulted
    constraint naming a parameter that is not in the signature still raises
    ``DefaultUnavailable`` legitimately. Reporting the pair as a fault would flag a working
    configuration.
    """
    assert ArgumentConstraint(required=True, default="acme").inconsistencies() == ()


@pytest.mark.unit
def test_a_required_defaulted_constraint_for_an_unknown_parameter_still_refuses(
    governor: Governor,
) -> None:
    spec = ArgumentSpec.from_callable(export_orders)
    principal = Principal(
        id="alice",
        constraints={
            'Action::"tool.search_orders"': ConstraintSet(
                arguments={"not_a_parameter": ArgumentConstraint(required=True, default="acme")}
            )
        },
    )

    with pytest.raises(DefaultUnavailable) as caught:
        governor.plan(spec, principal=principal, action=SEARCH_ACTION, resource=ORDERS_TOOL)

    assert caught.value.name == "not_a_parameter"


@pytest.mark.unit
def test_a_set_labels_each_problem_with_its_argument() -> None:
    problems = ConstraintSet(
        arguments={
            "limit": ArgumentConstraint(minimum=100, maximum=10),
            "region": ArgumentConstraint(allow=("eu",), default="us"),
        }
    ).inconsistencies()

    assert len(problems) == 2
    assert problems[0].startswith("argument 'limit': ")
    assert problems[1].startswith("argument 'region': ")


# --- the grant store refuses one at the write -------------------------------------------


@pytest.mark.unit
def test_a_grant_store_refuses_an_unsatisfiable_constraint() -> None:
    store = InMemoryGrantStore()

    with pytest.raises(ConfigurationError) as caught:
        store.grant(
            GrantSpec(
                principal=ALICE,
                kind="constraint",
                subject="limit",
                constraint=ArgumentConstraint(minimum=100, maximum=10),
            )
        )

    assert "cannot be satisfied" in str(caught.value)
    assert store.grants_for(ALICE) == ()


@pytest.mark.unit
def test_a_grant_store_refuses_a_constraint_whose_default_it_would_reject() -> None:
    store = InMemoryGrantStore()

    with pytest.raises(ConfigurationError):
        store.grant(
            GrantSpec(
                principal=ALICE,
                kind="constraint",
                subject="region",
                constraint=ArgumentConstraint(allow=("eu", "uk"), default="us"),
            )
        )


@pytest.mark.unit
def test_a_file_backed_store_refuses_it_too_and_writes_nothing(tmp_path: Path) -> None:
    path = tmp_path / "grants.json"
    store = JsonFileGrantStore(path)

    with pytest.raises(ConfigurationError):
        store.grant(
            GrantSpec(
                principal=ALICE,
                kind="constraint",
                subject="limit",
                constraint=ArgumentConstraint(minimum=100, maximum=10),
            )
        )

    assert not path.exists()


@pytest.mark.unit
def test_a_coherent_constraint_grant_is_still_accepted() -> None:
    store = InMemoryGrantStore()

    record = store.grant(
        GrantSpec(
            principal=ALICE,
            kind="constraint",
            subject="limit",
            constraint=ArgumentConstraint(minimum=1, maximum=50, default=10),
        )
    )

    assert record.spec.subject == "limit"


@pytest.mark.unit
def test_the_check_is_at_the_write_so_a_row_already_on_disk_still_loads(
    tmp_path: Path,
) -> None:
    """One bad row must not make every principal in the file unreadable.

    A validator on ``ArgumentConstraint`` itself would refuse at *construction*, which a store
    also performs when it reads. That is a wider refusal than the fault deserves: the call
    path already fails closed per argument, so the store stays readable and the bad row simply
    withholds its default.
    """
    path = tmp_path / "grants.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "name": "jsonfile",
                "grants": [
                    {
                        "id": "0001",
                        "spec": {
                            "principal": ["User", "alice"],
                            "kind": "constraint",
                            "subject": "limit",
                            "constraint": {"minimum": 100, "maximum": 10, "default": 500},
                            "action": "*",
                        },
                        "granted_at": "2026-08-18T12:00:00Z",
                    }
                ],
                "entities": [],
            }
        ),
        encoding="utf-8",
    )

    principal = JsonFileGrantStore(path).get_principal("alice")

    assert principal is not None
    constraints = principal.constraints_for(SEARCH_ACTION)
    assert constraints.inconsistencies()
    assert constraints.inject_defaults({}, ("limit",)).arguments == {}


@pytest.mark.unit
def test_constructing_an_incoherent_constraint_directly_is_not_an_error() -> None:
    """The same point, stated where it is enforced: the model itself does not refuse."""
    assert ArgumentConstraint(minimum=100, maximum=10).minimum == 100
