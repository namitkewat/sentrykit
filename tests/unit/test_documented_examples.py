"""The examples in `README.md` and `docs/quickstart.md` do what they say they do.

Documentation that has drifted from the code is worse than none: a reader trusts it, copies
it, and debugs the wrong thing. These tests run the published example end to end and assert
the exact envelope the docs print, so a change to the pipeline that would invalidate the
narrative fails here rather than in a reader's terminal.
"""

from __future__ import annotations

import pytest

from sentrykit import (
    ArgumentConstraint,
    AuthzDenied,
    ConstraintSet,
    Entity,
    EntityRef,
    NoContext,
    Principal,
    configure,
    establish,
    install,
    protect,
)

POLICIES = """
@id("support-may-search-orders")
permit (
  principal in Role::"support",
  action == Action::"tool.search_orders",
  resource == Tool::"orders"
);

@id("suspended-principals-are-forbidden")
forbid (principal, action, resource)
when { principal has suspended && principal.suspended };
"""
"""Verbatim from the quickstart."""


@pytest.fixture
def documented_search() -> object:
    """The quickstart's protected callable, over the quickstart's policy set."""
    install(
        POLICIES,
        entities=[Entity(EntityRef("Role", "support")), Entity(EntityRef("Tool", "orders"))],
    )

    @protect(action='Action::"tool.search_orders"', resource='Tool::"orders"')
    def search_orders(customer_id: str, region: str = "eu", limit: int = 100) -> dict[str, object]:
        return {"customer_id": customer_id, "region": region, "limit": limit}

    return search_orders


@pytest.fixture
def alice() -> Principal:
    """The quickstart's principal: entitled, but only to `eu` and a page size up to 50."""
    return Principal(
        id="alice",
        roles=("support",),
        constraints={
            'Action::"tool.search_orders"': ConstraintSet(
                arguments={
                    "region": ArgumentConstraint(
                        allow=("eu",), default="eu", policy="grant-eu-only"
                    ),
                    "limit": ArgumentConstraint(
                        minimum=1, maximum=50, default=10, policy="grant-page-size"
                    ),
                }
            )
        },
    )


@pytest.mark.unit
def test_the_documented_call_is_narrowed_to_what_the_principal_is_entitled_to(
    documented_search: object, alice: Principal
) -> None:
    """The headline claim: an over-broad request runs, narrowed, rather than being refused."""
    with establish(alice, channel="agent", request_id="req-1"):
        result = documented_search(customer_id="c-1", region="us", limit=500)  # type: ignore[operator]

    assert result["customer_id"] == "c-1"
    assert result["region"] == "eu"
    assert result["limit"] == 10


@pytest.mark.unit
def test_the_documented_summary_envelope_matches_what_the_docs_print(
    documented_search: object, alice: Principal
) -> None:
    """`summary` names what happened and discloses no argument values."""
    configure(verbosity="summary")

    with establish(alice, channel="agent"):
        envelope = documented_search(customer_id="c-1", region="us", limit=500)["_authz"]  # type: ignore[operator]

    assert envelope["decision"] == "allow"
    assert envelope["action"] == 'Action::"tool.search_orders"'
    assert envelope["resource"] == 'Tool::"orders"'
    assert envelope["defaults_applied"] == {"region": None, "limit": None}
    assert [(r["name"], r["rule"]) for r in envelope["rejected"]] == [
        ("region", "allow-set"),
        ("limit", "maximum"),
    ]
    assert all("value" not in rejection for rejection in envelope["rejected"])
    assert "processed" not in envelope
    assert "principal" not in envelope


@pytest.mark.unit
def test_the_documented_verbose_envelope_adds_the_values(
    documented_search: object, alice: Principal
) -> None:
    """`verbose` adds the principal, the processed arguments and the offending values."""
    configure(verbosity="verbose")

    with establish(alice, channel="agent"):
        envelope = documented_search(customer_id="c-1", region="us", limit=500)["_authz"]  # type: ignore[operator]

    assert envelope["principal"] == 'User::"alice"'
    assert envelope["processed"] == {"customer_id": "c-1", "region": "eu", "limit": 10}
    assert envelope["defaults_applied"] == {"region": "eu", "limit": 10}
    assert [rejection["value"] for rejection in envelope["rejected"]] == ["us", 500]


@pytest.mark.unit
def test_the_documented_denials_report_the_policy_the_docs_name(
    documented_search: object,
) -> None:
    """A default deny names nothing; the `forbid` names itself by its `@id` annotation."""
    mallory = Principal(id="mallory", roles=("guest",))
    with establish(mallory), pytest.raises(AuthzDenied) as unpermitted:
        documented_search(customer_id="c-1")  # type: ignore[operator]

    sam = Principal(id="sam", roles=("support",), attributes={"suspended": True})
    with establish(sam), pytest.raises(AuthzDenied) as forbidden:
        documented_search(customer_id="c-1")  # type: ignore[operator]

    assert list(unpermitted.value.determining_policies) == []
    assert list(forbidden.value.determining_policies) == ["suspended-principals-are-forbidden"]


@pytest.mark.unit
def test_forgetting_to_establish_context_fails_closed(documented_search: object) -> None:
    """The rule the quickstart asks the reader to internalize."""
    with pytest.raises(NoContext):
        documented_search(customer_id="c-1")  # type: ignore[operator]


@pytest.mark.unit
def test_the_readme_relationship_example_authorizes_through_the_chain() -> None:
    """The README's `alice -> Team -> Division -> Project` walk, exactly as printed."""
    policy = """
@id("project-members-may-read-project-orders")
permit (
  principal in Project::"orders-eu",
  action == Action::"order.read",
  resource in Project::"orders-eu"
);
"""
    install(
        policy,
        entities=[
            Entity(EntityRef("Project", "orders-eu")),
            Entity(EntityRef("Division", "emea"), parents=(EntityRef("Project", "orders-eu"),)),
            Entity(EntityRef("Team", "eu-support"), parents=(EntityRef("Division", "emea"),)),
            Entity(EntityRef("Order", "ord-0003"), parents=(EntityRef("Project", "orders-eu"),)),
        ],
    )

    @protect(action='Action::"order.read"', resource='Order::"ord-0003"')
    def read_order(order_id: str) -> dict[str, str]:
        return {"order_id": order_id}

    with establish(Principal(id="alice", parents=(EntityRef("Team", "eu-support"),))):
        assert read_order(order_id="ord-0003")["order_id"] == "ord-0003"
