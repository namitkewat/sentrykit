"""The example's authorization data: Cedar policy logic, plus the grants that feed it.

The split is policies-as-code, grants-as-data in miniature. :data:`POLICY_TEXT` is
*logic* — it would live in a
reviewed file under version control and never be rewritten at runtime. :func:`build_grants`
seeds *data* — who holds which role, which team they are on, and which argument values each
principal may pass — the only half an admin surface is ever allowed to mutate.

Nothing here mentions MCP, or a model, or a tool. The same policy and the same grants govern
the FastAPI example and a background job without a line changing; what the agent boundary adds
is a second question — *which tools may this caller even be shown* — answered from exactly
these entities.

The entity graph is deliberately the one in `tests/unit/test_relationships.py`, because the
showcase policy is the claim the library is built around and it should be recognizable in both
places.
"""

from __future__ import annotations

from sentrykit import ArgumentConstraint, Entity, EntityRef, GrantSpec
from sentrykit.stores.memory import InMemoryGrantStore

POLICY_TEXT = """
@id("support-may-search")
permit (
  principal in Role::"support",
  action == Action::"orders.search",
  resource == Tool::"orders"
);

@id("auditor-may-export")
permit (
  principal in Role::"auditor",
  action == Action::"orders.export",
  resource == Tool::"orders"
);

@id("no-pdf-exports")
forbid (
  principal,
  action == Action::"orders.export",
  resource
) when { context.args has fmt && context.args.fmt == "pdf" };

@id("project-members-may-read-project-orders")
permit (
  principal in Project::"orders-eu",
  action == Action::"orders.read",
  resource in Project::"orders-eu"
);
"""
"""Four policies, and the last one is the reason this example exists.

The first two are ordinary role gates, reached through the ``Role::`` parent edges the grant
store gives each principal. The third is a ``forbid`` that reads ``context.args``, so a
principal who *may* export still cannot export a PDF — Cedar's forbid always wins, which is
how an exception is expressed without editing the permit.

``project-members-may-read-project-orders`` is the showcase. **It names only the far end of
the chain.** It never mentions a team, never mentions a division, and never mentions
``Order::"o-1"``. Alice reaches it over four hops —
``User::"alice" -> Team::"eu-support" -> Division::"emea" -> Project::"orders-eu"``, and the
order over its own edge ``Order::"o-1" -> Project::"orders-eu"`` — and **Cedar walks every one
of them**. No application code resolves that relationship, no model infers it, and no ladder
of ``if`` statements approximates it: it is the transitive closure of an entity graph, computed
deterministically, and :func:`build_grants` with ``severed=True`` proves it by removing one
edge and watching the access disappear.
"""


def build_grants(*, severed: bool = False) -> InMemoryGrantStore:
    """Seed a fresh grant store with the example's entity graph, roles and constraints.

    Fresh on every call so two servers in one process (or two tests) never share mutable
    state.

    Args:
        severed: When true, ``Team::"eu-support"`` is seeded with **no parent division**, and
            nothing else changes. Alice keeps her team, the policy keeps its wording, and her
            read of ``Order::"o-1"`` stops being authorized — because the relationship *was*
            the authorization.

    Returns:
        A store holding the multi-hop graph, ``alice`` as ``support`` on ``eu-support`` with a
        constrained ``region`` and a capped ``limit``, and ``bob`` as ``auditor`` on
        ``us-support``.
    """
    store = InMemoryGrantStore()

    # The nodes a parent edge points *at* have to exist for Cedar to resolve ``principal in
    # Project::"orders-eu"`` through them, and the resources have to exist to be named by
    # ``resource ==`` and matched by ``resource in``.
    graph: tuple[Entity, ...] = (
        Entity(EntityRef("Tool", "orders")),
        Entity(EntityRef("Role", "support")),
        Entity(EntityRef("Role", "auditor")),
        Entity(EntityRef("Project", "orders-eu")),
        Entity(EntityRef("Project", "orders-us")),
        Entity(EntityRef("Division", "emea"), parents=(EntityRef("Project", "orders-eu"),)),
        Entity(EntityRef("Division", "amer"), parents=(EntityRef("Project", "orders-us"),)),
        # The one edge the severed variant drops. Everything else is identical, which is what
        # makes the comparison mean something.
        Entity(
            EntityRef("Team", "eu-support"),
            parents=() if severed else (EntityRef("Division", "emea"),),
        ),
        Entity(EntityRef("Team", "us-support"), parents=(EntityRef("Division", "amer"),)),
        Entity(EntityRef("Order", "o-1"), parents=(EntityRef("Project", "orders-eu"),)),
    )
    for entity in graph:
        store.add_entity(entity)

    alice = EntityRef("User", "alice")
    store.grant(GrantSpec(principal=alice, kind="role", subject="support"))
    # A team membership and a role are the same kind of edge — both become parents of the
    # principal — so the RBAC gate and the four-hop ReBAC chain are satisfied by one grant
    # store and one Cedar evaluation, not by two mechanisms bolted together.
    store.grant(GrantSpec(principal=alice, kind="parent", subject='Team::"eu-support"'))
    # Alice may search two regions and nowhere else, and gets ``eu`` when she names none. The
    # default is what turns "argument omitted" into "argument decided by policy" rather than
    # into a hole the callable has to fill with a Python default it chose for itself.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="region",
            action="orders.search",
            constraint=ArgumentConstraint(allow=("eu", "uk"), default="eu", policy="alice-region"),
        )
    )
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="limit",
            action="orders.search",
            constraint=ArgumentConstraint(maximum=50, default=10, policy="alice-limit"),
        )
    )

    bob = EntityRef("User", "bob")
    store.grant(GrantSpec(principal=bob, kind="role", subject="auditor"))
    # Bob's chain is exactly as long as alice's. It simply lands on the other project, which
    # is why he is refused ``Order::"o-1"`` without any policy naming him.
    store.grant(GrantSpec(principal=bob, kind="parent", subject='Team::"us-support"'))
    return store
