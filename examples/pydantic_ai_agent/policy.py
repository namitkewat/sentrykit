"""The example's authorization data: where the reviewed policy lives, and what an admin edits.

Run the whole example with `pixi run -e agent run-agent`; this module is the half that decides
what any of it is allowed to do.

The split is policies-as-code, grants-as-data in miniature, and here it is literal. The Cedar
*logic* is `.cedar` text on disk under `policies/`, loaded by
:class:`~sentrykit.stores.filesystem.FilesystemPolicySource` — files a reviewer reads in a pull
request and nothing rewrites at runtime. :func:`build_grants` seeds *data*: who holds which
role, which team they belong to, and which argument values each principal may pass. Only that
second half is ever an admin surface's to mutate.

Read it and notice what is **missing**: there is no agent, no bot, no service account, and no
``delegated_by`` anywhere. That absence is the point. An agent acting for alice *is* alice as
far as the policy is concerned, so alice's role edge and alice's argument constraints are what
govern the call her agent's model proposed. The delegation is expressed by the application
choosing whose ``deps`` it runs with, not by a second vocabulary in the policy — which is why
these files are byte-for-byte the kind of policy a web app ships.
"""

from __future__ import annotations

from pathlib import Path

from sentrykit import ArgumentConstraint, Entity, EntityRef, GrantSpec
from sentrykit.stores.memory import InMemoryGrantStore

POLICY_DIR = Path(__file__).parent / "policies"
"""The reviewed policy directory, handed to ``FilesystemPolicySource``."""

POLICY_TEXT = "\n".join(p.read_text(encoding="utf-8") for p in sorted(POLICY_DIR.glob("*.cedar")))
"""The same text, concatenated, for readers and callers that want it inline.

The numeric filename prefixes order this concatenation and Cedar's positional numbering; they
carry no meaning of their own, and a flat ``policies.cedar`` would behave identically.
"""


def build_grants() -> InMemoryGrantStore:
    """Seed a fresh grant store with the example's entity graph, roles and argument rules.

    Fresh on every call so two agents in one process (or two tests) never share mutable state.

    Returns:
        A store holding the stable entities the parent edges point at, the three principals,
        and every argument constraint the demonstration exercises.
    """
    store = InMemoryGrantStore()

    # Cedar resolves `principal in Role::"support"` and `resource in Project::"orders-eu"` by
    # walking parent edges, so every node an edge points at has to exist. This graph is the
    # relationship layer: it composes with everything else and needs no code of its own.
    for entity in (
        Entity(EntityRef("Tool", "orders")),
        Entity(EntityRef("Tool", "refunds")),
        Entity(EntityRef("Role", "support")),
        Entity(EntityRef("Role", "auditor")),
        # An admin is a superset of support, said once as an edge rather than as a second
        # grant on every admin. dana holds only `admin` and still satisfies `in Role::"support"`.
        Entity(EntityRef("Role", "admin"), parents=(EntityRef("Role", "support"),)),
        Entity(EntityRef("Project", "orders-eu")),
        Entity(EntityRef("Project", "orders-us")),
        Entity(EntityRef("Division", "emea"), parents=(EntityRef("Project", "orders-eu"),)),
        Entity(EntityRef("Division", "amer"), parents=(EntityRef("Project", "orders-us"),)),
        Entity(EntityRef("Team", "eu-support"), parents=(EntityRef("Division", "emea"),)),
        Entity(EntityRef("Team", "us-support"), parents=(EntityRef("Division", "amer"),)),
        # The resource end of the same chain. Reading o-1 is a question about two walks
        # meeting at Project::"orders-eu", not about an access list on the order.
        Entity(EntityRef("Order", "o-1"), parents=(EntityRef("Project", "orders-eu"),)),
    ):
        store.add_entity(entity)

    _grant_alice(store)
    _grant_bob(store)
    _grant_dana(store)
    return store


def _grant_alice(store: InMemoryGrantStore) -> None:
    """Grant alice the support role, the EU team edge, and her argument rules.

    Args:
        store: The store to write into.
    """
    alice = EntityRef("User", "alice")
    store.grant(GrantSpec(principal=alice, kind="role", subject="support"))
    store.grant(GrantSpec(principal=alice, kind="parent", subject='Team::"eu-support"'))

    # ALLOW-SET + DEFAULT. A region outside the set is rejected, and `eu` refills the gap, so
    # the call proceeds with a value policy chose. It is reject-and-refill: `cn` does not
    # become the nearest permitted thing, it is discarded and replaced by her own default.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="region",
            action="orders.search",
            constraint=ArgumentConstraint(allow=("eu", "uk"), default="eu", policy="alice-region"),
        )
    )
    # MAXIMUM + DEFAULT. limit=500 is rejected and refilled with 10 — not with 50. Nothing in
    # sentrykit ever hands back the bound a value breached.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="limit",
            action="orders.search",
            constraint=ArgumentConstraint(maximum=50, default=10, policy="alice-limit"),
        )
    )
    # PATTERN, with NO default. There is nothing to refill from, so a malformed order id is a
    # `DefaultUnavailable` refusal rather than a quiet substitution — which is right: no
    # default order id could be correct, and inventing one would refund the wrong order.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="order_id",
            action="refunds.issue",
            constraint=ArgumentConstraint(pattern=r"ord-[0-9]{4}", policy="alice-order-id"),
        )
    )
    # MINIMUM + MAXIMUM + DEFAULT. Both ends bounded on one argument. Note how this composes
    # with the reviewed desk limit: 900 is under the desk's 1000, so the gate permits the
    # call, and the argument layer still rejects the value against alice's own 750 and refills
    # with 50. Two layers answering two different questions about one number.
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
    # ALLOW-SET + DEFAULT again, on a different action. Constraints are per (principal,
    # action, argument), so the same argument name can be bounded differently per action.
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
    """Grant bob the auditor role, the US team edge, and his export format rule.

    Args:
        store: The store to write into.
    """
    bob = EntityRef("User", "bob")
    store.grant(GrantSpec(principal=bob, kind="role", subject="auditor"))
    store.grant(GrantSpec(principal=bob, kind="parent", subject='Team::"us-support"'))

    # DENY-SET + DEFAULT: everything except xml, which is rejected and refilled with csv. A
    # deny-set is the shape to reach for when the permitted values are open-ended and the
    # forbidden ones are few. `pdf` is refused a layer earlier, by reviewed policy, and that
    # difference is worth watching in the output: one narrows, the other denies.
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
    """Grant dana the admin role, the EU team edge, and defaults with no bounds of their own.

    Args:
        store: The store to write into.
    """
    dana = EntityRef("User", "dana")
    store.grant(GrantSpec(principal=dana, kind="role", subject="admin"))
    store.grant(GrantSpec(principal=dana, kind="parent", subject='Team::"eu-support"'))

    # DEFAULT ONLY — no allow-set, no maximum. Dana's only bound on `limit` is the ceiling
    # declared in `policies/10-orders.cedar`, and this default is what refills the gap when
    # that ceiling rejects a value. She proposes 500, the ceiling of 100 rejects it, and she
    # runs with 25: the refill is her default, never the bound that refused her.
    store.grant(
        GrantSpec(
            principal=dana,
            kind="constraint",
            subject="limit",
            action="orders.search",
            constraint=ArgumentConstraint(default=25, policy="dana-limit"),
        )
    )
    # DEFAULT ONLY, again: a value to inject when she names no region, and no restriction on
    # the ones she does name.
    store.grant(
        GrantSpec(
            principal=dana,
            kind="constraint",
            subject="region",
            action="orders.search",
            constraint=ArgumentConstraint(default="eu", policy="dana-region"),
        )
    )
