"""Multi-hop authorization relationships are resolved by Cedar, not by application code.

This is the claim sentrykit is built around: a principal may
reach a resource through a chain of entity edges — user in team, team in division, division
on project, project owns the record — and that chain is walked deterministically by Cedar's
entity hierarchy, never inferred by a model and never reimplemented as a ladder of ``if``
statements in the caller.

The mechanism belongs to the core, so it is proved here rather than left to the agent
showcase: :meth:`~sentrykit.context.Principal.all_parents` turns roles and teams into parent
edges, :class:`~sentrykit.cedar.Entity` carries the rest of the graph, and Cedar computes the
transitive closure. Nothing in ``sentrykit`` walks the chain itself — which is exactly why
these tests are written against the *outcome* of a policy that names only the far end of it.
"""

from __future__ import annotations

import pytest

from sentrykit.cedar import Entity, EntityRef, PolicyEngine
from sentrykit.context import Principal
from sentrykit.engine import ArgumentSpec, Governor
from sentrykit.errors import AuthzDenied

READ_ORDER = EntityRef("Action", "order.read")
ORDER = EntityRef("Order", "o-1")

RELATIONSHIP_POLICY = """
@id("project-members-may-read-project-orders")
permit (
  principal in Project::"orders-eu",
  action == Action::"order.read",
  resource in Project::"orders-eu"
);
"""
"""Names only the far end of the chain.

The policy never mentions a team or a division. If the call is authorized, it is because
Cedar walked ``User -> Team -> Division -> Project`` on its own.
"""

GRAPH: tuple[Entity, ...] = (
    Entity(EntityRef("Project", "orders-eu")),
    Entity(EntityRef("Project", "orders-us")),
    Entity(EntityRef("Division", "emea"), parents=(EntityRef("Project", "orders-eu"),)),
    Entity(EntityRef("Division", "amer"), parents=(EntityRef("Project", "orders-us"),)),
    Entity(EntityRef("Team", "eu-support"), parents=(EntityRef("Division", "emea"),)),
    Entity(EntityRef("Team", "us-support"), parents=(EntityRef("Division", "amer"),)),
    Entity(ORDER, parents=(EntityRef("Project", "orders-eu"),)),
)
"""Three hops from a team to a project, and the order hanging off the project."""


def read_order(order_id: str) -> dict[str, str]:
    """A protected callable standing in for anything with a side effect."""
    return {"order_id": order_id}


@pytest.fixture
def relationship_governor() -> Governor:
    """A governor over the multi-hop graph above."""
    return Governor(PolicyEngine(RELATIONSHIP_POLICY, GRAPH))


@pytest.fixture
def spec() -> ArgumentSpec:
    """The argument spec for :func:`read_order`."""
    return ArgumentSpec.from_callable(read_order)


def _plan(governor: Governor, spec: ArgumentSpec, principal: Principal) -> None:
    """Plan a read of ``Order::"o-1"`` as ``principal``, raising on refusal."""
    governor.plan(
        spec, principal=principal, action=READ_ORDER, resource=ORDER, proposed={"order_id": "o-1"}
    )


@pytest.mark.unit
def test_a_three_hop_relationship_authorizes_a_call_no_policy_mentions_directly(
    relationship_governor: Governor, spec: ArgumentSpec
) -> None:
    """User in team, team in division, division on project, project owns the order."""
    alice = Principal(id="alice", parents=(EntityRef("Team", "eu-support"),))

    _plan(relationship_governor, spec, alice)


@pytest.mark.unit
def test_the_same_call_is_denied_when_the_chain_leads_somewhere_else(
    relationship_governor: Governor, spec: ArgumentSpec
) -> None:
    """Bob's chain is just as long; it lands on the wrong project, so the edge is absent."""
    bob = Principal(id="bob", parents=(EntityRef("Team", "us-support"),))

    with pytest.raises(AuthzDenied):
        _plan(relationship_governor, spec, bob)


@pytest.mark.unit
def test_a_principal_with_no_edges_at_all_is_denied(
    relationship_governor: Governor, spec: ArgumentSpec
) -> None:
    """Default deny: unattached to the graph is not the same as attached but unprivileged."""
    stranger = Principal(id="stranger")

    with pytest.raises(AuthzDenied):
        _plan(relationship_governor, spec, stranger)


@pytest.mark.unit
def test_breaking_one_link_in_the_chain_denies_the_whole_path(spec: ArgumentSpec) -> None:
    """The relationship is the authorization, so removing an edge removes the access.

    Rebuilds the graph with the team detached from its division and nothing else changed.
    Alice keeps her team, the policy keeps its wording, and the call stops being allowed --
    which is what "the relationship is resolved by policy" has to mean in practice.
    """
    severed = tuple(
        Entity(entity.uid) if entity.uid == EntityRef("Team", "eu-support") else entity
        for entity in GRAPH
    )
    governor = Governor(PolicyEngine(RELATIONSHIP_POLICY, severed))
    alice = Principal(id="alice", parents=(EntityRef("Team", "eu-support"),))

    with pytest.raises(AuthzDenied):
        _plan(governor, spec, alice)


@pytest.mark.unit
def test_the_resource_side_of_the_chain_is_walked_too(
    relationship_governor: Governor, spec: ArgumentSpec
) -> None:
    """``resource in Project`` matches through the order's parent edge, not by naming it.

    An order outside the project is refused even though the principal is unchanged, so both
    halves of the policy's ``in`` are doing real work.
    """
    alice = Principal(id="alice", parents=(EntityRef("Team", "eu-support"),))
    governor = Governor(
        PolicyEngine(
            RELATIONSHIP_POLICY,
            (
                *GRAPH,
                Entity(EntityRef("Order", "o-2"), parents=(EntityRef("Project", "orders-us"),)),
            ),
        )
    )

    with pytest.raises(AuthzDenied):
        governor.plan(
            spec,
            principal=alice,
            action=READ_ORDER,
            resource=EntityRef("Order", "o-2"),
            proposed={"order_id": "o-2"},
        )


@pytest.mark.unit
def test_a_role_and_a_team_are_the_same_kind_of_edge(spec: ArgumentSpec) -> None:
    """``roles=`` is sugar over ``parents=``, so an RBAC grant composes with a ReBAC one.

    Proves the two are not separate mechanisms: a policy written against a role and one
    written against a project membership are satisfied by the same entity graph.
    """
    policy = (
        RELATIONSHIP_POLICY
        + """
@id("auditors-may-read-any-order")
permit (principal in Role::"auditor", action == Action::"order.read", resource);
"""
    )
    governor = Governor(PolicyEngine(policy, (*GRAPH, Entity(EntityRef("Role", "auditor")))))
    auditor = Principal(id="dana", roles=("auditor",))

    _plan(governor, spec, auditor)
