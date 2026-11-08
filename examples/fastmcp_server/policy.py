"""The example's authorization data: where the Cedar logic lives, and the grants that feed it.

This module demonstrates **policies-as-code, grants-as-data** in miniature, and the split is
visible in the file layout rather than only in prose:

* `policies/*.cedar` is *logic*. Real Cedar files, reviewed in git, loaded by a
  :class:`~sentrykit.stores.filesystem.FilesystemPolicySource`. Nothing at runtime rewrites
  them. One of them declares an **argument ceiling** in a `@constraints` annotation, so the
  reviewed file states the maximum anybody may pass.
* :func:`build_grants` seeds *data*. Who holds which role, which team they are on, and which
  argument values each principal may pass — the only half an admin surface is ever allowed to
  mutate.

Nothing here mentions MCP, or a model, or a tool. The same policy files and the same grants
govern an HTTP service and a background job without a line changing; what the agent boundary
adds is a second question — *which tools may this caller even be shown* — answered from
exactly these entities.

Run the whole thing with `pixi run -e agent run-mcp`.
"""

from __future__ import annotations

from pathlib import Path

from sentrykit import ArgumentConstraint, Entity, EntityRef, GrantSpec
from sentrykit.stores.memory import InMemoryGrantStore

POLICY_DIR = Path(__file__).parent / "policies"
"""The reviewed Cedar directory, handed to ``FilesystemPolicySource`` in ``server.py``."""

POLICY_TEXT = "\n".join(p.read_text(encoding="utf-8") for p in sorted(POLICY_DIR.glob("*.cedar")))
"""The same text, read back from disk for anything that wants to quote or hash it.

The files are the source. This constant exists so a reader, a report or a test can see the
policy without opening a directory, and it is deliberately *derived* rather than a second copy
that could drift from what the server actually loads.
"""


def build_grants(*, severed: bool = False) -> InMemoryGrantStore:
    """Seed a fresh grant store with the example's entity graph, roles and constraints.

    Fresh on every call so two servers in one process (or two tests) never share mutable
    state.

    Args:
        severed: When true, ``Team::"eu-support"`` is seeded with **no parent division**, and
            nothing else changes. Alice keeps her team, the policy keeps its wording, and her
            read of ``Order::"ord-0003"`` stops being authorized — because the relationship *was*
            the authorization.

    Returns:
        A store holding the multi-hop graph and three principals: ``alice`` as ``support`` on
        ``eu-support``, ``bob`` as ``auditor`` on ``us-support``, and ``dana`` as ``admin`` on
        ``eu-support``.
    """
    store = InMemoryGrantStore()

    # The nodes a parent edge points *at* have to exist for Cedar to resolve ``principal in
    # Project::"orders-eu"`` through them, and the resources have to exist to be named by
    # ``resource ==`` and matched by ``resource in``.
    graph: tuple[Entity, ...] = (
        Entity(EntityRef("Tool", "orders")),
        Entity(EntityRef("Tool", "refunds")),
        Entity(EntityRef("Role", "support")),
        Entity(EntityRef("Role", "auditor")),
        # An admin is a superset of support, expressed as one edge rather than as a second
        # grant on every admin. Dana holds only ``admin`` and still satisfies
        # ``principal in Role::"support"``.
        Entity(EntityRef("Role", "admin"), parents=(EntityRef("Role", "support"),)),
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
        Entity(EntityRef("Order", "ord-0003"), parents=(EntityRef("Project", "orders-eu"),)),
    )
    for entity in graph:
        store.add_entity(entity)

    _grant_alice(store)
    _grant_bob(store)
    _grant_dana(store)
    return store


def _grant_alice(store: InMemoryGrantStore) -> None:
    """Grant the support user: two roles' worth of edges and four argument constraints.

    Args:
        store: The store to seed.
    """
    alice = EntityRef("User", "alice")
    store.grant(GrantSpec(principal=alice, kind="role", subject="support"))
    # A team membership and a role are the same kind of edge — both become parents of the
    # principal — so the RBAC gate and the four-hop relationship chain are satisfied by one
    # grant store and one Cedar evaluation, not by two mechanisms bolted together.
    store.grant(GrantSpec(principal=alice, kind="parent", subject='Team::"eu-support"'))

    # allow-set + default. Two regions and nowhere else; ``eu`` when she names none. The
    # default is what turns "argument omitted" into "argument decided by policy" rather than
    # into a hole the callable has to fill with a value it chose for itself. A value outside
    # the set is rejected and this default refills the gap — the call proceeds, with ``eu``.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="region",
            action="orders.search",
            constraint=ArgumentConstraint(allow=("eu", "uk"), default="eu", policy="alice-region"),
        )
    )
    # maximum + default. 50 is tighter than the reviewed ceiling of 100, and the tighter bound
    # is the one that reports, so a rejection for alice names ``alice-limit`` and never
    # ``support-may-search``.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="limit",
            action="orders.search",
            constraint=ArgumentConstraint(maximum=50, default=10, policy="alice-limit"),
        )
    )

    # pattern, and deliberately NO default. A value that does not match has nothing to refill
    # from, so the call is refused with ``DefaultUnavailable`` rather than completed with an
    # order id nobody asked for. Guessing an identifier would be worse than refusing.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="order_id",
            action="refunds.issue",
            constraint=ArgumentConstraint(pattern=r"ord-[0-9]{4}", policy="alice-order-id"),
        )
    )
    # minimum + maximum + default. The gate may permit a 900-unit refund — the desk limit in
    # the reviewed policy is 1000 — and this grant still rejects it, then refills with 50.
    # Gate and argument layer are two questions, and both get asked.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="amount",
            action="refunds.issue",
            constraint=ArgumentConstraint(
                minimum=1, maximum=750, default=50, policy="alice-amount"
            ),
        )
    )
    # allow-set + default again, on a different action. Constraints are keyed by
    # (principal, action, argument), so ``region`` on ``refunds.issue`` is a separate grant
    # from ``region`` on ``orders.search`` and can say something different.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="region",
            action="refunds.issue",
            constraint=ArgumentConstraint(
                allow=("eu", "uk"), default="eu", policy="alice-refund-region"
            ),
        )
    )


def _grant_bob(store: InMemoryGrantStore) -> None:
    """Grant the auditor: the other project, and the one deny-set in the example.

    Args:
        store: The store to seed.
    """
    bob = EntityRef("User", "bob")
    store.grant(GrantSpec(principal=bob, kind="role", subject="auditor"))
    # Bob's chain is exactly as long as alice's. It simply lands on the other project, which
    # is why he is refused ``Order::"ord-0003"`` without any policy naming him.
    store.grant(GrantSpec(principal=bob, kind="parent", subject='Team::"us-support"'))
    # deny-set + default. A deny-set names what is out; everything else is in. ``xml`` is
    # rejected and ``csv`` refills the gap, so the export still happens — in a format bob is
    # allowed to have. Compare ``fmt="pdf"``, which the reviewed `no-pdf-exports` forbid
    # refuses at the gate before the argument layer is reached at all.
    store.grant(
        GrantSpec(
            principal=bob,
            kind="constraint",
            subject="fmt",
            action="orders.export",
            constraint=ArgumentConstraint(deny=("xml",), default="csv", policy="bob-fmt"),
        )
    )


def _grant_dana(store: InMemoryGrantStore) -> None:
    """Grant the admin: one role edge, and defaults with no bound of their own.

    Args:
        store: The store to seed.
    """
    dana = EntityRef("User", "dana")
    store.grant(GrantSpec(principal=dana, kind="role", subject="admin"))
    store.grant(GrantSpec(principal=dana, kind="parent", subject='Team::"eu-support"'))
    # default only — no maximum. Dana's own grant bounds nothing, so the reviewed
    # ``@constraints`` ceiling of 100 in `10-orders.cedar` is her only bound on ``limit``, and
    # a rejection names ``support-may-search``: the policy file, not a grant. What she gets
    # back is **25**, this default. It is not the ceiling and it is not the value she asked
    # for; the proposal was rejected and her default refilled the gap.
    store.grant(
        GrantSpec(
            principal=dana,
            kind="constraint",
            subject="limit",
            action="orders.search",
            constraint=ArgumentConstraint(default=25, policy="dana-limit"),
        )
    )
    store.grant(
        GrantSpec(
            principal=dana,
            kind="constraint",
            subject="region",
            action="orders.search",
            constraint=ArgumentConstraint(default="eu", policy="dana-region"),
        )
    )
