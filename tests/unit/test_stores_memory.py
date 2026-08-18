"""The in-memory backends: grants materialize into a principal, and lifecycles are honoured.

The grant store's contract is that the *decision path never reasons about grant lifecycles* —
by the time a :class:`~sentrykit.context.Principal` comes back, an expired or revoked grant
has already been left out. Every expiry test therefore fixes the clock: either by passing an
explicit ``now``, or with ``freezegun`` where the API is being asked to find its own.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime

import pytest
from freezegun import freeze_time

from sentrykit.audit import AuthzAuditRecord
from sentrykit.cedar import Entity, EntityRef
from sentrykit.constraints import ArgumentConstraint
from sentrykit.errors import ConfigurationError
from sentrykit.registry import parse_dsn
from sentrykit.stores.base import AuditSink, AuditWindow, GrantSpec, GrantStore
from sentrykit.stores.memory import InMemoryAuditSink, InMemoryGrantStore, InMemoryTokenVault

ALICE = EntityRef("User", "alice")
MONDAY = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
TUESDAY = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
FRIDAY = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)

SEARCH = EntityRef("Action", "tool.search_orders")

RecordFactory = Callable[..., AuthzAuditRecord]
ChainBuilder = Callable[[Sequence[AuthzAuditRecord]], "tuple[AuthzAuditRecord, ...]"]


def _role(subject: str = "support", **extra: object) -> GrantSpec:
    return GrantSpec(principal=ALICE, kind="role", subject=subject, **extra)


# --- materialization -----------------------------------------------------------------------


@pytest.mark.unit
def test_the_store_satisfies_the_grant_store_contract() -> None:
    assert isinstance(InMemoryGrantStore(), GrantStore)


@pytest.mark.unit
def test_a_granted_role_appears_on_the_materialized_principal() -> None:
    store = InMemoryGrantStore()
    store.grant(_role(), now=MONDAY)

    principal = store.get_principal("alice", now=TUESDAY)

    assert principal is not None
    assert principal.uid == ALICE
    assert "support" in principal.roles


@pytest.mark.unit
def test_a_granted_parent_edge_appears_on_the_materialized_principal() -> None:
    store = InMemoryGrantStore()
    store.grant(
        GrantSpec(principal=ALICE, kind="parent", subject='Team::"payments"'),
        now=MONDAY,
    )

    principal = store.get_principal(ALICE, now=TUESDAY)

    assert principal is not None
    assert EntityRef("Team", "payments") in principal.all_parents()


@pytest.mark.unit
def test_a_granted_attribute_appears_on_the_materialized_principal() -> None:
    store = InMemoryGrantStore()
    store.grant(
        GrantSpec(principal=ALICE, kind="attribute", subject="clearance", value="high"),
        now=MONDAY,
    )

    principal = store.get_principal("alice", now=TUESDAY)

    assert principal is not None
    assert principal.attributes["clearance"] == "high"


@pytest.mark.unit
def test_a_granted_constraint_is_keyed_by_the_action_it_applies_to() -> None:
    store = InMemoryGrantStore()
    store.grant(
        GrantSpec(
            principal=ALICE,
            kind="constraint",
            subject="customer_id",
            constraint=ArgumentConstraint(allow=("c-1", "c-2"), default="c-1"),
            action='Action::"tool.search_orders"',
        ),
        now=MONDAY,
    )

    principal = store.get_principal("alice", now=TUESDAY)

    assert principal is not None
    constraints = principal.constraints_for(SEARCH)
    assert "customer_id" in constraints.arguments
    assert constraints.arguments["customer_id"].default == "c-1"


@pytest.mark.unit
def test_a_principal_the_store_has_never_heard_of_materializes_to_none() -> None:
    assert InMemoryGrantStore().get_principal("nobody", now=TUESDAY) is None


@pytest.mark.unit
def test_two_stores_do_not_share_state() -> None:
    first = InMemoryGrantStore()
    first.grant(_role(), now=MONDAY)

    assert InMemoryGrantStore().get_principal("alice", now=TUESDAY) is None


# --- lifecycles ----------------------------------------------------------------------------


@pytest.mark.unit
def test_a_grant_applies_before_it_expires() -> None:
    store = InMemoryGrantStore()
    store.grant(_role(expires_at=FRIDAY), now=MONDAY)

    principal = store.get_principal("alice", now=TUESDAY)

    assert principal is not None
    assert "support" in principal.roles


@pytest.mark.unit
def test_an_expired_grant_is_not_materialized() -> None:
    store = InMemoryGrantStore()
    store.grant(_role(expires_at=TUESDAY), now=MONDAY)

    principal = store.get_principal("alice", now=FRIDAY)

    assert principal is None or "support" not in principal.roles


@pytest.mark.unit
def test_expiry_is_evaluated_against_the_clock_when_no_moment_is_passed() -> None:
    store = InMemoryGrantStore()
    store.grant(_role(expires_at=TUESDAY), now=MONDAY)

    with freeze_time("2026-08-18T00:00:00+00:00"):
        before = store.get_principal("alice")
    with freeze_time("2026-08-21T00:00:00+00:00"):
        after = store.get_principal("alice")

    assert before is not None
    assert "support" in before.roles
    assert after is None or "support" not in after.roles


@pytest.mark.unit
def test_a_revoked_grant_is_not_materialized() -> None:
    store = InMemoryGrantStore()
    granted = store.grant(_role(), now=MONDAY)

    store.revoke(granted.id, revoked_by="admin", reason="left the team", now=TUESDAY)

    principal = store.get_principal("alice", now=FRIDAY)
    assert principal is None or "support" not in principal.roles


@pytest.mark.unit
def test_revocation_returns_the_updated_record() -> None:
    store = InMemoryGrantStore()
    granted = store.grant(_role(), now=MONDAY)

    revoked = store.revoke(granted.id, revoked_by="admin", reason="left the team", now=TUESDAY)

    assert revoked.id == granted.id
    assert revoked.revoked_at == TUESDAY
    assert revoked.revoked_by == "admin"
    assert revoked.revoked_reason == "left the team"
    assert revoked.is_active(FRIDAY) is False


@pytest.mark.unit
def test_the_history_of_a_grant_survives_its_revocation() -> None:
    store = InMemoryGrantStore()
    granted = store.grant(_role(), now=MONDAY)
    store.revoke(granted.id, now=TUESDAY)

    assert store.grants_for("alice") == ()

    history = store.grants_for("alice", include_inactive=True)
    assert [record.id for record in history] == [granted.id]
    assert history[0].granted_at == MONDAY
    assert history[0].spec.subject == "support"


@pytest.mark.unit
def test_grants_are_listed_oldest_first() -> None:
    store = InMemoryGrantStore()
    first = store.grant(_role("support"), now=MONDAY)
    second = store.grant(_role("auditor"), now=TUESDAY)

    assert [record.id for record in store.grants_for("alice")] == [first.id, second.id]


@pytest.mark.unit
def test_a_grant_is_stamped_with_the_clock_when_no_moment_is_passed() -> None:
    store = InMemoryGrantStore()

    with freeze_time("2026-08-18T12:00:00+00:00"):
        granted = store.grant(_role())

    assert granted.granted_at.replace(tzinfo=None) == datetime(2026, 8, 18, 12, 0)


@pytest.mark.unit
def test_a_constraint_grant_that_carries_no_constraint_is_refused() -> None:
    store = InMemoryGrantStore()

    with pytest.raises(ConfigurationError):
        store.grant(GrantSpec(principal=ALICE, kind="constraint", subject="customer_id"))


@pytest.mark.unit
def test_revoking_a_grant_that_does_not_exist_is_refused() -> None:
    with pytest.raises(ConfigurationError) as raised:
        InMemoryGrantStore().revoke("no-such-grant")

    assert "no-such-grant" in str(raised.value)


# --- entities ------------------------------------------------------------------------------


@pytest.mark.unit
def test_the_store_contributes_the_nodes_its_edges_point_at_but_never_principals() -> None:
    store = InMemoryGrantStore()
    store.grant(_role(), now=MONDAY)
    store.grant(GrantSpec(principal=ALICE, kind="parent", subject='Team::"payments"'), now=MONDAY)

    uids = {entity.uid for entity in store.entities()}

    assert EntityRef("Role", "support") in uids
    assert EntityRef("Team", "payments") in uids
    assert ALICE not in uids


@pytest.mark.unit
def test_an_explicitly_added_entity_joins_the_graph() -> None:
    store = InMemoryGrantStore()

    store.add_entity(Entity(EntityRef("Tool", "orders"), {"tier": "gold"}))

    added = {entity.uid: entity for entity in store.entities()}
    assert added[EntityRef("Tool", "orders")].attributes["tier"] == "gold"


@pytest.mark.unit
def test_from_dsn_builds_the_store_the_registry_would() -> None:
    store = InMemoryGrantStore.from_dsn(parse_dsn("memory://"))

    assert isinstance(store, InMemoryGrantStore)
    assert store.name == "memory"


# --- the in-memory sink and vault ----------------------------------------------------------


@pytest.mark.unit
def test_the_in_memory_sink_keeps_every_record_it_is_given(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    sink = InMemoryAuditSink()
    records = chained([make_record(), make_record(), make_record()])

    for record in records:
        sink.write(record)

    assert isinstance(sink, AuditSink)
    assert tuple(sink.records) == records


@pytest.mark.unit
def test_the_in_memory_sink_answers_a_window_query(
    make_record: RecordFactory,
    chained: ChainBuilder,
) -> None:
    sink = InMemoryAuditSink()
    for record in chained(
        [
            make_record(),
            make_record(decision="deny", outcome="denied"),
            make_record(),
        ]
    ):
        sink.write(record)

    denials = list(sink.query(AuditWindow(decision="deny")))

    assert [record.outcome for record in denials] == ["denied"]


@pytest.mark.unit
def test_the_token_vault_mints_a_stable_token_and_can_give_it_back() -> None:
    vault = InMemoryTokenVault()

    token = vault.tokenize("4111-1111-1111-1111", field="card")

    assert vault.tokenize("4111-1111-1111-1111", field="card") == token
    assert vault.resolve(token) == "4111-1111-1111-1111"


@pytest.mark.unit
def test_the_token_vault_separates_values_and_forgets_on_erasure() -> None:
    vault = InMemoryTokenVault()
    first = vault.tokenize("one", field="card")
    second = vault.tokenize("two", field="card")

    assert first != second

    vault.erase(first)

    assert vault.resolve(first) is None
    assert vault.resolve(second) == "two"


@pytest.mark.unit
def test_an_unminted_token_resolves_to_nothing() -> None:
    assert InMemoryTokenVault().resolve("token:absent") is None
