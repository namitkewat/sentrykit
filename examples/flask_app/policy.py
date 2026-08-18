"""Policy logic and grant data for the Flask example — the ADR-005 split, in miniature.

The Cedar text below is *code*: it is authored here, reviewed in version control, and never
rewritten at runtime. Everything that changes per person — who is support, who is an auditor,
which regions Alice may search, how many rows she may ask for — is *data* in a
:class:`~sentrykit.stores.memory.InMemoryGrantStore`, which an admin surface could mutate
without touching a line of the policy above it.

Read the two together and the division is the point: the policy says *auditors may export*,
the grants say *bob is an auditor*, and neither statement needs the other rewritten to change.
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

@id("support-may-summarize")
permit (
  principal in Role::"support",
  action == Action::"orders.summarize",
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
  resource == Tool::"orders"
) when { context.args has fmt && context.args.fmt == "pdf" };
"""
"""The reviewed Cedar policy set.

Four rules, chosen to show the four things sentrykit does at the action layer: a role gate
(``support-may-search``), a second gate on a callable that is not a route
(``support-may-summarize``), a *different* role on a *different* action
(``auditor-may-export``), and a forbid that reads the caller's proposed arguments
(``no-pdf-exports``) — Cedar seeing the arguments before the side effect happens is the whole
premise, and a ``forbid`` beats every ``permit`` no matter who the caller is.
"""


def build_grants() -> InMemoryGrantStore:
    """Seed the grant store this example authorizes against.

    Returns:
        A store holding the entity graph the policy refers to (``Tool::"orders"`` and the two
        roles) plus the per-principal grants: Alice is support and may search only ``eu``/``uk``
        with a limit of at most 50, Bob is an auditor and may export.

        Alice's two argument constraints are the interesting part. They are *grants*, not
        policy, and they carry defaults — so a caller who supplies neither ``region`` nor
        ``limit`` still gets a well-formed, authorized call rather than a refusal.
    """
    store = InMemoryGrantStore()

    # The stable half of the graph. ``install()`` merges these into the engine's entity set, so
    # ``principal in Role::"support"`` has something to resolve against.
    for ref in (
        EntityRef("Tool", "orders"),
        EntityRef("Role", "support"),
        EntityRef("Role", "auditor"),
    ):
        store.add_entity(Entity(ref))

    alice = EntityRef("User", "alice")
    store.grant(GrantSpec(principal=alice, kind="role", subject="support"))
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

    store.grant(GrantSpec(principal=EntityRef("User", "bob"), kind="role", subject="auditor"))
    return store
