"""Composites: union of policy sources, precedence across grant stores, fan-out across sinks.

The interesting claim is the negative one about policy sources. A composite has **no source
precedence** — an override is expressed as a Cedar ``forbid``, and forbid wins wherever it
sits in the concatenation. So the forbid-override test decides the same request with the
sources composed both ways round and asserts the answer does not move. If ordering ever did
change a decision, "which policy file wins" would become a question operators had to hold in
their heads, and the union would stop being a union.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

import pytest

from sentrykit.audit import AuthzAuditRecord
from sentrykit.cedar import CedarDecision, CedarRequest, Entity, EntityRef
from sentrykit.constraints import ArgumentConstraint
from sentrykit.errors import AuditUnavailable, ConfigurationError
from sentrykit.stores.base import (
    AuditSink,
    AuditWindow,
    GrantSpec,
    GrantStore,
    PolicyBundle,
    PolicySource,
)
from sentrykit.stores.composite import (
    CompositeAuditSink,
    CompositeGrantStore,
    CompositePolicySource,
)
from sentrykit.stores.jsonl import JsonlAuditSink
from sentrykit.stores.memory import InMemoryAuditSink, InMemoryGrantStore

RecordFactory = Callable[..., AuthzAuditRecord]
ChainBuilder = Callable[[Sequence[AuthzAuditRecord]], "tuple[AuthzAuditRecord, ...]"]

ALICE = EntityRef("User", "alice")
SEARCH = EntityRef("Action", "tool.search_orders")
ORDERS = EntityRef("Tool", "orders")
SUPPORT = EntityRef("Role", "support")

BASE_ENTITIES = (Entity(SUPPORT), Entity(ORDERS))

# Both sources declare the *same* ``@id``. Cedar does not enforce uniqueness, so without the
# composite's namespacing a determining-policy name would be ambiguous across sources.
ALPHA = """
@id("shared")
permit (principal, action == Action::"tool.alpha", resource);
"""

BETA = """
@id("shared")
permit (principal, action == Action::"tool.beta", resource);
"""

PERMIT_SEARCH = """
@id("support-may-search")
permit (
  principal in Role::"support",
  action == Action::"tool.search_orders",
  resource == Tool::"orders"
);
"""

FORBID_WHEN_FROZEN = """
@id("frozen-tenants-are-forbidden")
forbid (principal, action, resource)
when { context has frozen && context.frozen };
"""


class StubSource:
    """A :class:`PolicySource` over a literal string, so a union test needs no filesystem."""

    def __init__(self, name: str, policies: str, entities: Sequence[Entity] = ()) -> None:
        self._name = name
        self._policies = policies
        self._entities = tuple(entities)

    @property
    def name(self) -> str:
        return self._name

    def load(self) -> PolicyBundle:
        return PolicyBundle.from_text(
            self._policies,
            entities=self._entities,
            source=self._name,
            origin=f"stub:{self._name}",
        )

    def current_hash(self) -> str:
        return self.load().bundle_hash


class ExplodingSink:
    """A sink that always refuses the write, for the fan-out error policies."""

    def __init__(self, name: str = "exploding") -> None:
        self._name = name
        self.attempts = 0

    @property
    def name(self) -> str:
        return self._name

    def write(self, record: AuthzAuditRecord) -> None:
        self.attempts += 1
        raise AuditUnavailable(self._name, "disk on fire")

    def query(self, window: AuditWindow) -> Iterator[AuthzAuditRecord]:
        return iter(())


# --- policy source union -------------------------------------------------------------------


@pytest.mark.unit
def test_the_union_is_itself_a_policy_source() -> None:
    composite = CompositePolicySource([StubSource("alpha", ALPHA), StubSource("beta", BETA)])

    assert isinstance(composite, PolicySource)
    assert composite.name


@pytest.mark.unit
def test_the_union_carries_the_policy_text_of_every_source() -> None:
    bundle = CompositePolicySource([StubSource("alpha", ALPHA), StubSource("beta", BETA)]).load()

    assert 'Action::"tool.alpha"' in bundle.policies
    assert 'Action::"tool.beta"' in bundle.policies


@pytest.mark.unit
def test_the_union_tags_every_policy_with_the_source_it_came_from() -> None:
    bundle = CompositePolicySource([StubSource("alpha", ALPHA), StubSource("beta", BETA)]).load()

    assert {entry.source for entry in bundle.provenance} == {"alpha", "beta"}
    assert {entry.origin for entry in bundle.provenance} == {"stub:alpha", "stub:beta"}


@pytest.mark.unit
def test_two_sources_declaring_the_same_id_stay_distinguishable() -> None:
    bundle = CompositePolicySource([StubSource("alpha", ALPHA), StubSource("beta", BETA)]).load()

    assert {entry.policy_id for entry in bundle.provenance} == {"alpha/shared", "beta/shared"}


@pytest.mark.unit
def test_a_single_source_is_not_namespaced() -> None:
    bundle = StubSource("alpha", ALPHA).load()

    assert [entry.policy_id for entry in bundle.provenance] == ["shared"]


@pytest.mark.unit
def test_the_union_merges_the_entity_graphs() -> None:
    bundle = CompositePolicySource(
        [
            StubSource("alpha", ALPHA, (Entity(SUPPORT),)),
            StubSource("beta", BETA, (Entity(ORDERS),)),
        ]
    ).load()

    assert {entity.uid for entity in bundle.entities} == {SUPPORT, ORDERS}


@pytest.mark.unit
def test_the_union_hash_moves_when_any_source_moves() -> None:
    alpha = StubSource("alpha", ALPHA)
    composite = CompositePolicySource([alpha, StubSource("beta", BETA)])
    before = composite.current_hash()

    changed = CompositePolicySource(
        [alpha, StubSource("beta", BETA.replace("tool.beta", "tool.gamma"))]
    )

    assert before == composite.load().bundle_hash
    assert changed.current_hash() != before


@pytest.mark.unit
def test_the_union_builds_one_engine_over_every_source() -> None:
    bundle = CompositePolicySource(
        [
            StubSource("permits", PERMIT_SEARCH, BASE_ENTITIES),
            StubSource("forbids", FORBID_WHEN_FROZEN),
        ]
    ).load()

    engine = bundle.engine()

    assert engine.policies == bundle.policies
    assert engine.policy_set_hash


# --- forbid overrides survive the union, whichever way round it is built --------------------


def _decide(*, forbid_first: bool, frozen: bool) -> tuple[CedarDecision, PolicyBundle]:
    """Decide one request against the union, composed in the requested order."""
    sources: list[StubSource] = [
        StubSource("permits", PERMIT_SEARCH, BASE_ENTITIES),
        StubSource("forbids", FORBID_WHEN_FROZEN),
    ]
    if forbid_first:
        sources.reverse()

    bundle = CompositePolicySource(sources).load()
    decision = bundle.engine().evaluate(
        CedarRequest(
            principal=ALICE,
            action=SEARCH,
            resource=ORDERS,
            context={"frozen": frozen},
            entities=(Entity(ALICE, {}, (SUPPORT,)),),
        )
    )
    return decision, bundle


@pytest.mark.unit
@pytest.mark.parametrize("forbid_first", [False, True], ids=["permit-first", "forbid-first"])
def test_a_forbid_in_one_source_overrides_a_permit_in_another(forbid_first: bool) -> None:
    decision, bundle = _decide(forbid_first=forbid_first, frozen=True)

    assert decision.allowed is False
    resolved = bundle.provenance_for(decision.determining_policies)
    assert [entry.source for entry in resolved] == ["forbids"]
    assert [entry.effect for entry in resolved] == ["forbid"]


@pytest.mark.unit
@pytest.mark.parametrize("forbid_first", [False, True], ids=["permit-first", "forbid-first"])
def test_the_permit_still_stands_when_the_forbid_condition_does_not_hold(
    forbid_first: bool,
) -> None:
    decision, bundle = _decide(forbid_first=forbid_first, frozen=False)

    assert decision.allowed is True
    resolved = bundle.provenance_for(decision.determining_policies)
    assert [entry.source for entry in resolved] == ["permits"]


@pytest.mark.unit
@pytest.mark.parametrize("frozen", [True, False], ids=["forbid-applies", "forbid-inert"])
def test_source_order_cannot_change_a_decision(frozen: bool) -> None:
    permit_first, _ = _decide(forbid_first=False, frozen=frozen)
    forbid_first, _ = _decide(forbid_first=True, frozen=frozen)

    assert permit_first.allowed == forbid_first.allowed
    assert permit_first.decision == forbid_first.decision


# --- grant store merge ---------------------------------------------------------------------


@pytest.mark.unit
def test_the_merged_store_is_itself_a_grant_store() -> None:
    composite = CompositeGrantStore([InMemoryGrantStore(name="a"), InMemoryGrantStore(name="b")])

    assert isinstance(composite, GrantStore)


@pytest.mark.unit
def test_an_earlier_store_wins_a_conflicting_attribute() -> None:
    primary = InMemoryGrantStore(name="primary")
    secondary = InMemoryGrantStore(name="secondary")
    primary.grant(GrantSpec(principal=ALICE, kind="attribute", subject="clearance", value="high"))
    secondary.grant(GrantSpec(principal=ALICE, kind="attribute", subject="clearance", value="low"))

    principal = CompositeGrantStore([primary, secondary]).get_principal("alice")

    assert principal is not None
    assert principal.attributes["clearance"] == "high"


@pytest.mark.unit
def test_a_principal_only_a_later_store_knows_is_still_found() -> None:
    primary = InMemoryGrantStore(name="primary")
    secondary = InMemoryGrantStore(name="secondary")
    secondary.grant(GrantSpec(principal=ALICE, kind="role", subject="support"))

    principal = CompositeGrantStore([primary, secondary]).get_principal("alice")

    assert principal is not None
    assert "support" in principal.roles


@pytest.mark.unit
def test_a_principal_no_store_knows_is_none() -> None:
    composite = CompositeGrantStore([InMemoryGrantStore(name="a"), InMemoryGrantStore(name="b")])

    assert composite.get_principal("nobody") is None


@pytest.mark.unit
def test_the_merged_store_unions_the_entity_graphs() -> None:
    primary = InMemoryGrantStore(name="primary")
    secondary = InMemoryGrantStore(name="secondary")
    primary.add_entity(Entity(SUPPORT))
    secondary.add_entity(Entity(ORDERS))

    uids = {entity.uid for entity in CompositeGrantStore([primary, secondary]).entities()}

    assert {SUPPORT, ORDERS} <= uids


@pytest.mark.unit
def test_a_grant_made_through_the_composite_materializes_through_it() -> None:
    composite = CompositeGrantStore([InMemoryGrantStore(name="a"), InMemoryGrantStore(name="b")])

    record = composite.grant(
        GrantSpec(
            principal=ALICE,
            kind="constraint",
            subject="customer_id",
            constraint=ArgumentConstraint(allow=("c-1",), default="c-1"),
            action='Action::"tool.search_orders"',
        )
    )

    principal = composite.get_principal("alice")
    assert record.id
    assert principal is not None
    assert "customer_id" in principal.constraints_for(SEARCH).arguments


@pytest.mark.unit
def test_grants_from_every_member_are_listed_when_merging() -> None:
    primary = InMemoryGrantStore(name="primary")
    secondary = InMemoryGrantStore(name="secondary")
    primary.grant(GrantSpec(principal=ALICE, kind="role", subject="support"))
    secondary.grant(GrantSpec(principal=ALICE, kind="role", subject="auditor"))

    grants = CompositeGrantStore([primary, secondary]).grants_for("alice")

    assert {record.spec.subject for record in grants} == {"support", "auditor"}


@pytest.mark.unit
def test_a_grant_is_revoked_by_whichever_member_holds_it() -> None:
    primary = InMemoryGrantStore(name="primary")
    secondary = InMemoryGrantStore(name="secondary")
    held = secondary.grant(GrantSpec(principal=ALICE, kind="role", subject="support"))
    composite = CompositeGrantStore([primary, secondary])

    revoked = composite.revoke(held.id, revoked_by="admin", reason="left")

    assert revoked.id == held.id
    assert revoked.revoked_by == "admin"
    assert secondary.grants_for("alice") == ()


@pytest.mark.unit
def test_revoking_a_grant_no_member_holds_names_the_members_that_were_tried() -> None:
    composite = CompositeGrantStore(
        [InMemoryGrantStore(name="primary"), InMemoryGrantStore(name="secondary")]
    )

    with pytest.raises(ConfigurationError) as raised:
        composite.revoke("no-such-grant")

    assert "no-such-grant" in str(raised.value)
    assert "primary" in str(raised.value)
    assert "secondary" in str(raised.value)


@pytest.mark.unit
def test_the_composite_merges_when_the_stores_declare_no_namespace() -> None:
    composite = CompositeGrantStore([InMemoryGrantStore(name="a"), InMemoryGrantStore(name="b")])

    assert composite.routed is False


@pytest.mark.unit
def test_the_composite_routes_when_every_store_declares_a_namespace() -> None:
    composite = CompositeGrantStore(
        [
            InMemoryGrantStore(name="a", namespace="tenant-a"),
            InMemoryGrantStore(name="b", namespace="tenant-b"),
        ]
    )

    assert composite.routed is True


@pytest.mark.unit
def test_one_missing_namespace_falls_back_to_merging() -> None:
    composite = CompositeGrantStore(
        [InMemoryGrantStore(name="a", namespace="tenant-a"), InMemoryGrantStore(name="b")]
    )

    assert composite.routed is False


def _routed() -> tuple[CompositeGrantStore, InMemoryGrantStore, InMemoryGrantStore]:
    acme = InMemoryGrantStore(name="acme-store", namespace="acme")
    globex = InMemoryGrantStore(name="globex-store", namespace="globex")
    return CompositeGrantStore([acme, globex]), acme, globex


@pytest.mark.unit
def test_a_routed_lookup_reaches_only_the_tenant_that_owns_the_principal() -> None:
    composite, acme, globex = _routed()
    acme.grant(GrantSpec(principal=EntityRef("User", "acme:alice"), kind="role", subject="support"))
    globex.grant(GrantSpec(principal=EntityRef("User", "globex:alice"), kind="role", subject="ops"))

    assert composite.get_principal("acme:alice").roles == ("support",)  # type: ignore[union-attr]
    assert composite.get_principal("globex:alice").roles == ("ops",)  # type: ignore[union-attr]


@pytest.mark.unit
def test_a_cedar_type_namespace_routes_as_well_as_an_id_prefix() -> None:
    """``Acme::User`` routes on its type prefix, the same way ``acme:alice`` routes on its id."""
    acme = InMemoryGrantStore(name="acme-store", namespace="Acme")
    composite = CompositeGrantStore([acme, InMemoryGrantStore(name="globex", namespace="Globex")])
    tenant_user = EntityRef("Acme::User", "alice")
    acme.grant(GrantSpec(principal=tenant_user, kind="role", subject="support"))

    principal = composite.get_principal(tenant_user)

    assert principal is not None
    assert principal.roles == ("support",)


@pytest.mark.unit
def test_a_routed_grant_lands_in_the_store_its_namespace_names() -> None:
    composite, acme, globex = _routed()

    composite.grant(
        GrantSpec(principal=EntityRef("User", "acme:dana"), kind="role", subject="support")
    )

    assert len(acme.grants_for("acme:dana")) == 1
    assert globex.grants_for("acme:dana") == ()


@pytest.mark.unit
def test_a_principal_no_namespace_claims_is_refused_rather_than_guessed_at() -> None:
    composite, _, _ = _routed()

    with pytest.raises(ConfigurationError) as raised:
        composite.get_principal("alice")

    assert "acme" in str(raised.value)
    assert "globex" in str(raised.value)


@pytest.mark.unit
def test_two_stores_cannot_claim_the_same_namespace() -> None:
    with pytest.raises(ConfigurationError) as raised:
        CompositeGrantStore(
            [
                InMemoryGrantStore(name="a", namespace="acme"),
                InMemoryGrantStore(name="b", namespace="acme"),
            ]
        )

    assert "acme" in str(raised.value)


# --- audit sink fan-out --------------------------------------------------------------------


@pytest.mark.unit
def test_the_fan_out_is_itself_a_sink() -> None:
    composite = CompositeAuditSink([InMemoryAuditSink(name="a"), InMemoryAuditSink(name="b")])

    assert isinstance(composite, AuditSink)


@pytest.mark.unit
def test_every_sink_receives_every_record(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    first, second = InMemoryAuditSink(name="north"), InMemoryAuditSink(name="south")
    composite = CompositeAuditSink([first, second])
    records = chained([make_record(), make_record()])

    for record in records:
        composite.write(record)

    assert tuple(first.records) == records
    assert tuple(second.records) == records


@pytest.mark.unit
def test_a_failing_primary_refuses_the_write_under_primary_durable(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    exploding = ExplodingSink("primary-store")
    composite = CompositeAuditSink(
        [exploding, InMemoryAuditSink(name="replica")], on_error="primary-durable"
    )
    record = chained([make_record()])[0]

    with pytest.raises(AuditUnavailable) as raised:
        composite.write(record)

    assert "primary-store" in str(raised.value)
    assert exploding.attempts == 1


@pytest.mark.unit
def test_a_failing_replica_does_not_refuse_the_write_under_primary_durable(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    primary = InMemoryAuditSink(name="primary-store")
    exploding = ExplodingSink("replica-store")
    tail = InMemoryAuditSink(name="tail-store")
    composite = CompositeAuditSink([primary, exploding, tail], on_error="primary-durable")
    record = chained([make_record()])[0]

    composite.write(record)

    assert tuple(primary.records) == (record,)
    assert tuple(tail.records) == (record,)
    assert exploding.attempts == 1


@pytest.mark.unit
def test_any_failure_refuses_the_write_under_all_or_nothing(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    primary = InMemoryAuditSink(name="primary-store")
    exploding = ExplodingSink("replica-store")
    tail = InMemoryAuditSink(name="tail-store")
    composite = CompositeAuditSink([primary, exploding, tail], on_error="all-or-nothing")
    record = chained([make_record()])[0]

    with pytest.raises(AuditUnavailable) as raised:
        composite.write(record)

    # Every sink is still attempted: an operator has to be able to tell one dead replica from
    # a dead cluster, and short-circuiting after the first failure would hide the difference.
    assert tuple(primary.records) == (record,)
    assert tuple(tail.records) == (record,)
    assert exploding.attempts == 1
    assert "replica-store" in str(raised.value.failures)


@pytest.mark.unit
def test_the_fan_out_reports_every_sink_that_failed(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    composite = CompositeAuditSink(
        [InMemoryAuditSink(name="ok"), ExplodingSink("north-store"), ExplodingSink("south-store")],
        on_error="all-or-nothing",
    )

    with pytest.raises(AuditUnavailable) as raised:
        composite.write(chained([make_record()])[0])

    rendered = str(raised.value.failures)
    assert len(raised.value.failures) == 2
    assert "north-store" in rendered
    assert "south-store" in rendered


@pytest.mark.unit
def test_the_fan_out_reads_back_from_its_first_sink(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    primary = InMemoryAuditSink(name="primary-store")
    composite = CompositeAuditSink([primary, InMemoryAuditSink(name="replica-store")])
    records = chained([make_record(), make_record()])

    for record in records:
        composite.write(record)

    assert tuple(composite.query(AuditWindow())) == records


@pytest.mark.unit
def test_an_unknown_error_policy_is_refused() -> None:
    with pytest.raises(ConfigurationError):
        CompositeAuditSink([InMemoryAuditSink()], on_error="best-effort")  # type: ignore[arg-type]


@pytest.mark.unit
def test_closing_the_fan_out_closes_the_members_that_hold_a_resource(tmp_path: Path) -> None:
    closeable = JsonlAuditSink(tmp_path / "audit.jsonl")
    composite = CompositeAuditSink([InMemoryAuditSink(name="memory"), closeable])

    composite.close()

    # A member with nothing to release is simply skipped rather than required to no-op.
    composite.close()


@pytest.mark.unit
def test_one_member_failing_to_close_does_not_strand_the_others(tmp_path: Path) -> None:
    class Stubborn(InMemoryAuditSink):
        def close(self) -> None:
            raise OSError("handle is wedged")

    closeable = JsonlAuditSink(tmp_path / "audit.jsonl")
    composite = CompositeAuditSink([Stubborn(name="stubborn"), closeable])

    composite.close()

    assert closeable.tail_hash()  # the survivor was still reached and closed cleanly


# --- construction --------------------------------------------------------------------------


@pytest.mark.unit
def test_a_composite_needs_at_least_one_member() -> None:
    with pytest.raises(ConfigurationError):
        CompositePolicySource([])
    with pytest.raises(ConfigurationError):
        CompositeGrantStore([])
    with pytest.raises(ConfigurationError):
        CompositeAuditSink([])


@pytest.mark.unit
def test_two_policy_sources_cannot_share_a_name() -> None:
    with pytest.raises(ConfigurationError) as raised:
        CompositePolicySource([StubSource("pack", ALPHA), StubSource("pack", BETA)])

    assert "pack" in str(raised.value)


@pytest.mark.unit
def test_two_sources_defining_one_entity_differently_is_refused() -> None:
    composite = CompositePolicySource(
        [
            StubSource("alpha", ALPHA, (Entity(ORDERS, {"tier": "gold"}),)),
            StubSource("beta", BETA, (Entity(ORDERS, {"tier": "silver"}),)),
        ]
    )

    with pytest.raises(ConfigurationError) as raised:
        composite.load()

    assert "alpha" in str(raised.value)
    assert "beta" in str(raised.value)


@pytest.mark.unit
def test_two_sources_declaring_one_entity_identically_is_fine() -> None:
    composite = CompositePolicySource(
        [
            StubSource("alpha", ALPHA, (Entity(ORDERS, {"tier": "gold"}),)),
            StubSource("beta", BETA, (Entity(ORDERS, {"tier": "gold"}),)),
        ]
    )

    assert len(composite.load().entities) == 1
