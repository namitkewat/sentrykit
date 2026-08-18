"""The example's authorization data: Cedar policy logic, plus the grants that feed it.

The split is ADR-005 in miniature. :data:`POLICY_TEXT` is *logic* — it would live in a
reviewed file under version control and never be rewritten at runtime. :func:`build_grants`
seeds *data* — who holds which role, and which argument values each principal may pass — the
only half an admin surface is ever allowed to mutate.

Nothing here mentions HTTP. That is the point: the same policy and the same grants govern the
Flask example, an MCP tool and a background job without a line changing.
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
"""Four policies covering the three shapes the example demonstrates.

The first three are ordinary role gates, reached through the ``Role::`` parent edges the grant
store gives each principal. The fourth is the one worth reading twice: a ``forbid`` that
inspects ``context.args``, so ``bob`` — who *may* export — still cannot export a PDF. Cedar's
forbid always wins, which is how an exception is expressed without editing the permit.
"""


def build_grants() -> InMemoryGrantStore:
    """Seed a fresh grant store with the example's roles and argument constraints.

    Fresh on every call so two apps in one process (or two tests) never share mutable state.

    Returns:
        A store holding: the stable entities the parent edges point at, ``alice`` as
        ``support`` with a constrained ``region`` and a capped ``limit``, and ``bob`` as
        ``auditor``.
    """
    store = InMemoryGrantStore()

    # The nodes the parent edges point at have to exist for Cedar to resolve ``principal in
    # Role::"support"``, and the resource has to exist to be named by ``resource ==``.
    for uid in (
        EntityRef("Tool", "orders"),
        EntityRef("Role", "support"),
        EntityRef("Role", "auditor"),
    ):
        store.add_entity(Entity(uid))

    alice = EntityRef("User", "alice")
    store.grant(GrantSpec(principal=alice, kind="role", subject="support"))
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

    store.grant(GrantSpec(principal=EntityRef("User", "bob"), kind="role", subject="auditor"))
    return store
