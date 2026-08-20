"""Where authorization for this example comes from: reviewed policy files, plus grant data.

The split is policies-as-code, grants-as-data in miniature, and it is why there are two
things in this module rather than one.

* **Policy logic lives in ``policies/*.cedar``**, loaded by
  :class:`~sentrykit.stores.filesystem.FilesystemPolicySource`. Those files are reviewed in
  version control and never rewritten at runtime. Open them: they are where the argument
  ceiling is declared, and they are what a reviewer reads to learn the widest value anyone
  may ask for.
* **Grants are data**, seeded by :func:`build_grants` into a store an admin surface could
  mutate all day without touching a line of reviewed policy.

Nothing here mentions HTTP. The same directory and the same grants govern the Flask example,
an MCP tool and a background job with no line changing.

Run the whole thing with ``pixi run -e web run-fastapi``.
"""

from __future__ import annotations

from pathlib import Path

from sentrykit import ArgumentConstraint, Entity, EntityRef, GrantSpec
from sentrykit.stores.memory import InMemoryGrantStore

POLICY_DIR = Path(__file__).parent / "policies"
"""The reviewed policy directory, handed to ``install(policy_source=...)``."""

POLICY_TEXT = "\n".join(
    path.read_text(encoding="utf-8") for path in sorted(POLICY_DIR.glob("*.cedar"))
)
"""The same policy logic as one string, for a reader who wants it in one place.

Sorted, because Cedar numbers policies positionally in the text it parsed and the loader
concatenates the directory in that same order. The numeric filename prefixes only make the
order obvious to a human; they are not required.
"""


def build_grants() -> InMemoryGrantStore:
    """Seed a fresh grant store with the desk's entity graph and per-principal grants.

    Fresh on every call, so two apps in one process — or two tests — never share mutable
    state.

    Returns:
        A store holding the stable entities the policies' parent edges point at, three
        principals, and the argument constraints that decide what each of them may pass.
    """
    store = InMemoryGrantStore()

    # The stable half of the graph. A parent edge needs a node to point at before Cedar can
    # walk it, and a resource needs to exist before ``resource ==`` can name it. These edges
    # are what ``project-members-may-read-project-orders`` resolves:
    #
    #     User::"alice" -> Team::"eu-support" -> Division::"emea" -> Project::"orders-eu"
    #     Order::"o-1"  -> Project::"orders-eu"
    #
    # Multi-hop and nested, resolved by the engine rather than by application code. It is a
    # capability that composes underneath the argument layer, not the headline.
    for entity in (
        Entity(EntityRef("Tool", "orders")),
        Entity(EntityRef("Tool", "refunds")),
        Entity(EntityRef("Role", "support")),
        Entity(EntityRef("Role", "auditor")),
        # An admin is a superset of support, expressed as one edge instead of as a second
        # grant on every admin. ``principal in Role::"support"`` is true for Dana because of
        # this line alone.
        Entity(EntityRef("Role", "admin"), parents=(EntityRef("Role", "support"),)),
        Entity(EntityRef("Project", "orders-eu")),
        Entity(EntityRef("Project", "orders-us")),
        Entity(EntityRef("Division", "emea"), parents=(EntityRef("Project", "orders-eu"),)),
        Entity(EntityRef("Division", "amer"), parents=(EntityRef("Project", "orders-us"),)),
        Entity(EntityRef("Team", "eu-support"), parents=(EntityRef("Division", "emea"),)),
        Entity(EntityRef("Team", "us-support"), parents=(EntityRef("Division", "amer"),)),
        Entity(EntityRef("Order", "o-1"), parents=(EntityRef("Project", "orders-eu"),)),
    ):
        store.add_entity(entity)

    _grant_alice(store)
    _grant_bob(store)
    _grant_dana(store)
    return store


def _grant_alice(store: InMemoryGrantStore) -> None:
    """Grant the support agent: her place in the graph, and four argument constraints.

    Args:
        store: The store to write into.
    """
    alice = EntityRef("User", "alice")
    store.grant(GrantSpec(principal=alice, kind="role", subject="support"))
    store.grant(GrantSpec(principal=alice, kind="parent", subject='Team::"eu-support"'))

    # allow-set + default. The allow-set says which values she may pass; the default says
    # what she gets when she passes none, and also what fills the gap when a value of hers
    # is rejected. Propose ``region=cn`` and both halves fire: ``cn`` is rejected and ``eu``
    # takes its place.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="region",
            action="orders.search",
            constraint=ArgumentConstraint(allow=("eu", "uk"), default="eu", policy="alice-region"),
        )
    )
    # maximum + default, and the two numbers are deliberately unrelated. A ``limit`` above 50
    # is rejected and refilled with 10 — never trimmed to 50. Watch the ``_authz`` envelope:
    # ``rejected`` names the 500 she asked for and ``defaults_applied`` names the 10 she got.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="limit",
            action="orders.search",
            constraint=ArgumentConstraint(maximum=50, default=10, policy="alice-limit"),
        )
    )

    # pattern, and deliberately **no default**. Refilling refines a proposal; it cannot
    # invent one. An ``order_id`` that fails the pattern is dropped, nothing can fill the
    # gap, and the call is refused with ``DefaultUnavailable`` — a 400 whose ``_authz``
    # names the argument rather than an action, because the gate said yes and the argument
    # layer said no.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="order_id",
            action="refunds.issue",
            constraint=ArgumentConstraint(pattern=r"ord-[0-9]{4}", policy="alice-order-id"),
        )
    )
    # minimum + maximum + default. Her bounds sit *inside* the desk limit the reviewed policy
    # enforces, so a refund of 900 passes the Cedar gate and is still rejected by her own
    # grant — two layers, two answers, and the envelope shows both.
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
    # allow-set + default again, on a different action. A constraint is per (principal,
    # action, argument), so ``region`` on ``refunds.issue`` is a separate grant from
    # ``region`` on ``orders.search`` and is free to differ.
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
    """Grant the auditor: his place in the graph, and one deny-set.

    Args:
        store: The store to write into.
    """
    bob = EntityRef("User", "bob")
    store.grant(GrantSpec(principal=bob, kind="role", subject="auditor"))
    store.grant(GrantSpec(principal=bob, kind="parent", subject='Team::"us-support"'))

    # deny-set + default. The mirror image of an allow-set: everything passes except what is
    # named. ``xml`` is rejected and ``csv`` fills the gap, so the export still runs.
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
    """Grant the admin: her place in the graph, and two defaults with no bounds of their own.

    Args:
        store: The store to write into.
    """
    dana = EntityRef("User", "dana")
    store.grant(GrantSpec(principal=dana, kind="role", subject="admin"))
    store.grant(GrantSpec(principal=dana, kind="parent", subject='Team::"eu-support"'))

    # default only, and that is the whole point of this grant. Dana's own data sets no
    # maximum, so the only bound on her ``limit`` is the ceiling declared in
    # ``policies/10-orders.cedar``. She asks for 500, breaches the ceiling of 100, and runs
    # with 25 — her own default, unrelated to the ceiling she breached. The rejection names
    # ``support-may-search``, the reviewed policy, because that is the layer that produced it.
    store.grant(
        GrantSpec(
            principal=dana,
            kind="constraint",
            subject="limit",
            action="orders.search",
            constraint=ArgumentConstraint(default=25, policy="dana-limit"),
        )
    )
    # default only again: an admin may search any region, and still gets one chosen for her
    # when she names none.
    store.grant(
        GrantSpec(
            principal=dana,
            kind="constraint",
            subject="region",
            action="orders.search",
            constraint=ArgumentConstraint(default="eu", policy="dana-region"),
        )
    )
