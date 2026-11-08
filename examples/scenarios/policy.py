"""The suite's authorization data: the reviewed policy on disk, and the grants an admin edits.

Run the suite with `pixi run -e default python -m examples.scenarios`; this module is what the
governed arm runs under. The ungoverned arm runs under nothing, which is the comparison.

The split is policies-as-code, grants-as-data, and here it is literal. The Cedar *logic* is
`.cedar` text under `policies/`, loaded by
:class:`~sentrykit.stores.filesystem.FilesystemPolicySource` — files a reviewer reads in a pull
request and nothing rewrites at runtime. :func:`build_grants` seeds *data*: who holds which role,
which team they belong to, and which argument values each principal may pass. An admin surface
mutates only the second half.

## Two principals, and what each one is for

* **alice** is support, on the EU team. She is the principal the argument layer is demonstrated
  against: six of the seven constraints below are hers, covering an allow-set, a bound, a
  deny-set, and a default with no bound of its own.
* **bob** is an auditor, on the US team. He holds two constraints and, on purpose, a gap: no
  ``tenant_id`` rule at all. The suite needs one principal for whom the reviewed ceiling is the
  only thing standing between a proposed value and the desk, with nothing of his own to refill
  from, because that is the shape most real deployments start in.

Nothing here names an agent, a bot, a service account, or a model. A caller acting for alice *is*
alice as far as policy is concerned, so what governs the call is alice's role edge and alice's
argument constraints — whether the proposal came from a person, a model, or a stranger's text that
a model read and believed.
"""

from __future__ import annotations

from pathlib import Path

from sentrykit import ArgumentConstraint, Entity, EntityRef, GrantSpec
from sentrykit.stores.memory import InMemoryGrantStore

POLICY_DIR = Path(__file__).parent / "policies"
"""The reviewed policy directory, handed to ``install(policy_source=...)``."""

POLICY_TEXT = "\n".join(p.read_text(encoding="utf-8") for p in sorted(POLICY_DIR.glob("*.cedar")))
"""The same text, concatenated, for readers and callers that want it inline.

The numeric filename prefixes order this concatenation and Cedar's positional numbering; they
carry no meaning of their own, and a flat ``policies.cedar`` would behave identically.
"""


def build_grants() -> InMemoryGrantStore:
    """Seed a fresh grant store with the suite's entity graph, roles and argument rules.

    Fresh on every call so two runs in one process (or two tests) never share mutable state. The
    suite leans on that: a scenario that re-seeds is a scenario that can be read in isolation.

    Returns:
        A store holding the stable entities the parent edges point at, both principals, and every
        argument constraint the suite exercises.
    """
    store = InMemoryGrantStore()

    # Cedar resolves `principal in Role::"support"` by walking parent edges, so every node an edge
    # points at has to exist. The three tools are the resources the reviewed permits name; the
    # team edges carry no policy of their own here and are seeded because a principal's parents
    # must resolve.
    for entity in (
        Entity(EntityRef("Tool", "orders")),
        Entity(EntityRef("Tool", "tickets")),
        Entity(EntityRef("Tool", "exports")),
        Entity(EntityRef("Role", "support")),
        # An auditor is a superset of support, said once as an edge rather than as a second grant
        # on every auditor. bob holds only `auditor` and still satisfies `in Role::"support"` --
        # which is how the reviewed tenant ceiling reaches him at all.
        Entity(EntityRef("Role", "auditor"), parents=(EntityRef("Role", "support"),)),
        Entity(EntityRef("Team", "eu-support")),
        Entity(EntityRef("Team", "us-support")),
    ):
        store.add_entity(entity)

    _grant_alice(store)
    _grant_bob(store)
    return store


def _grant_alice(store: InMemoryGrantStore) -> None:
    """Grant alice the support role, the EU team edge, and her argument rules.

    Args:
        store: The store to write into.
    """
    alice = EntityRef("User", "alice")
    store.grant(GrantSpec(principal=alice, kind="role", subject="support"))
    store.grant(GrantSpec(principal=alice, kind="parent", subject='Team::"eu-support"'))

    # ALLOW-SET + DEFAULT. A region outside the set is rejected and `eu` refills the gap, so the
    # call proceeds with a value policy chose. It is reject-and-refill: `cn` does not become the
    # nearest permitted thing, it is discarded and replaced by her own default.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="region",
            action="desk.search",
            constraint=ArgumentConstraint(allow=("eu", "uk"), default="eu", policy="alice-region"),
        )
    )
    # MAXIMUM + DEFAULT. limit=100000 is rejected and refilled with 10 — not with 50, and not with
    # the reviewed ceiling's 100. Nothing in sentrykit ever hands back the bound a value breached.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="limit",
            action="desk.search",
            constraint=ArgumentConstraint(maximum=50, default=10, policy="alice-limit"),
        )
    )
    # ALLOW-SET + DEFAULT on a second action. Constraints are per (principal, action, argument),
    # so bounding `region` on a search says nothing about `region` on an export — which is why
    # the export that mints a handle needs a rule of its own, stated here.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="region",
            action="desk.export",
            constraint=ArgumentConstraint(
                allow=("eu", "uk"), default="eu", policy="alice-export-region"
            ),
        )
    )
    # DEFAULT ONLY — no allow-set, no bound. Her only restriction on `tenant_id` is the ceiling
    # declared in `policies/10-desk.cedar`, and this is purely what refills the gap when that
    # ceiling rejects a value. She proposes somebody else's tenant, the reviewed file rejects it,
    # and she runs against `acme`: the refill is her default, never the rule that refused her.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="tenant_id",
            action="desk.tenants",
            constraint=ArgumentConstraint(default="acme", policy="alice-tenant"),
        )
    )
    # MAXIMUM + DEFAULT again, and a tighter pair than her search limit: the same argument name
    # bounded differently per action, because a cross-tenant listing is not a search.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="limit",
            action="desk.tenants",
            constraint=ArgumentConstraint(maximum=25, default=5, policy="alice-tenant-limit"),
        )
    )
    # DENY-SET with NO default, on the destructive call. A deny-set is the shape to reach for when
    # the permitted values are open-ended and the forbidden one is specific — she may clear out
    # any region except her own. There is nothing to refill from, and the function's `region`
    # parameter carries a Python default of `eu`, so a caller who names no region at all is
    # refused: a signature default answers to the same check a policy default does, which is what
    # stops an omitted argument from being the way around a rule about it.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="region",
            action="desk.cancel",
            constraint=ArgumentConstraint(deny=("eu",), policy="alice-no-eu-cancels"),
        )
    )
    # ALLOW-SET + DEFAULT, narrowed to one value. Worth following into the result: the argument is
    # settled correctly every time, and the body still returns a desk-wide total beside it. What a
    # body computes is the body author's decision, and no grant written here reaches it.
    store.grant(
        GrantSpec(
            principal=alice,
            kind="constraint",
            subject="region",
            action="desk.report",
            constraint=ArgumentConstraint(
                allow=("eu",), default="eu", policy="alice-report-region"
            ),
        )
    )


def _grant_bob(store: InMemoryGrantStore) -> None:
    """Grant bob the auditor role, the US team edge, and his two export rules.

    Args:
        store: The store to write into.
    """
    bob = EntityRef("User", "bob")
    store.grant(GrantSpec(principal=bob, kind="role", subject="auditor"))
    store.grant(GrantSpec(principal=bob, kind="parent", subject='Team::"us-support"'))

    # PATTERN, with NO default. There is nothing to refill from, so a malformed handle is a
    # refusal rather than a quiet substitution — which is right: no default export id could be
    # correct, and inventing one would hand him somebody else's export. The pattern also fixes
    # the shape of the one argument this action takes, which is all a constraint can do when the
    # argument is an opaque handle.
    store.grant(
        GrantSpec(
            principal=bob,
            kind="constraint",
            subject="job_id",
            action="desk.fetch",
            constraint=ArgumentConstraint(pattern=r"exp-[0-9]{4}", policy="bob-job-id"),
        )
    )
    # ALLOW-SET with NO default, on the one action where the region is an argument rather than
    # something hidden inside a handle. He may claim `us` and nothing else, and because there is
    # no default, claiming anything else is refused instead of quietly rewritten — a claim about
    # what a handle covers is not a value anybody should be refilling on his behalf.
    store.grant(
        GrantSpec(
            principal=bob,
            kind="constraint",
            subject="region",
            action="desk.fetch_rows",
            constraint=ArgumentConstraint(allow=("us",), policy="bob-fetch-region"),
        )
    )
    # And deliberately nothing for `tenant_id`. He reaches the tenant listing through the auditor
    # edge into `Role::"support"`, so the ceiling in `policies/10-desk.cedar` governs him, and it
    # is the only thing that does. With no default of his own there is no gap to refill, so where
    # alice continues on `acme`, he is refused — one reviewed line, two outcomes, decided entirely
    # by whether the principal has a default to fall back to.
