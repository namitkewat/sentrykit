"""What the shipped Cedar policy pack decides, pattern by pattern.

Every pattern gets a permit case *and* a refusal case, and both assert
``determining_policies`` rather than only ``allowed``. That is not belt and braces: several
of these patterns exist precisely because the *wrong* policy could reach the right verdict —
a delegated agent denied by the plain absence of a permit looks identical to one denied by
its delegation scope until you read which policy decided, and only one of the two is the
guarantee the pack claims to make.

Time is passed explicitly as ``context.now`` rather than read from a clock. Cedar compares
epoch seconds (:func:`~sentrykit.cedar.coerce_value` renders every ``datetime`` that way), so
an expiry test that let the clock move would be asserting against a moving target.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta

import pytest

from sentrykit.cedar import (
    CedarDecision,
    CedarRequest,
    Entity,
    EntityRef,
    policy_annotations,
    validate_policies,
)
from sentrykit.policy import PATTERNS, PackPattern, load_pack, pack_root, pack_schema
from sentrykit.stores.base import PolicyBundle

PACK = load_pack()
"""Loaded once: the pack is immutable data, and reloading it per test would only be slower."""

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
EARLIER = NOW - timedelta(days=1)
LATER = NOW + timedelta(days=1)
ONE_SECOND = timedelta(seconds=1)

FORBIDDEN_PACKAGES = frozenset({"fastapi", "flask", "starlette", "mcp", "pydantic_ai"})


# --- helpers -----------------------------------------------------------------------------


def role(name: str) -> EntityRef:
    return EntityRef("Role", name)


def group(name: str) -> EntityRef:
    return EntityRef("Group", name)


def user(name: str) -> EntityRef:
    return EntityRef("User", name)


def thing(name: str) -> EntityRef:
    return EntityRef("Resource", name)


def node(
    uid: EntityRef,
    attributes: Mapping[str, object] | None = None,
    parents: Sequence[EntityRef] = (),
) -> Entity:
    return Entity(uid, attributes or {}, tuple(parents))


def decide(
    principal: EntityRef,
    action: EntityRef,
    resource: EntityRef,
    *,
    entities: Sequence[Entity],
    context: Mapping[str, object] | None = None,
    now: datetime = NOW,
    bundle: PolicyBundle = PACK,
) -> CedarDecision:
    """Ask the pack one question, with ``now`` supplied and the graph handed in per test."""
    engine = bundle.engine().with_entities(entities)
    return engine.evaluate(
        CedarRequest(
            principal=principal,
            action=action,
            resource=resource,
            context={"now": now, **(context or {})},
        )
    )


# --- the pack is well-formed -------------------------------------------------------------


@pytest.mark.unit
def test_the_shipped_pack_validates_against_its_own_schema() -> None:
    outcome = validate_policies(PACK.policies, pack_schema())

    assert outcome.passed, outcome.describe()


@pytest.mark.unit
def test_the_pack_loader_imports_no_web_framework_or_agent_sdk() -> None:
    for source_path in sorted(pack_root().parent.glob("*.py")):
        imported: set[str] = set()
        for statement in ast.walk(ast.parse(source_path.read_text(encoding="utf-8"))):
            if isinstance(statement, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in statement.names)
            elif isinstance(statement, ast.ImportFrom) and statement.module:
                imported.add(statement.module.split(".")[0])

        assert not FORBIDDEN_PACKAGES & imported, f"{source_path.name} imports a framework"


@pytest.mark.unit
@pytest.mark.parametrize("pattern", list(PATTERNS.values()), ids=lambda p: p.name)
def test_every_pattern_in_the_table_names_a_file_that_ships(pattern: PackPattern) -> None:
    assert (pack_root() / pattern.file).is_file()


@pytest.mark.unit
def test_every_policy_file_in_the_pack_is_named_by_the_table() -> None:
    shipped = {path.name for path in pack_root().glob("*.cedar")}

    assert shipped == {pattern.file for pattern in PATTERNS.values()}


@pytest.mark.unit
@pytest.mark.parametrize("pattern", list(PATTERNS.values()), ids=lambda p: p.name)
def test_a_patterns_declared_policy_ids_match_its_file_in_order(pattern: PackPattern) -> None:
    text = (pack_root() / pattern.file).read_text(encoding="utf-8")

    declared = tuple(annotation.declared_id for annotation in policy_annotations(text))

    assert declared == pattern.policy_ids


@pytest.mark.unit
@pytest.mark.parametrize("pattern", list(PATTERNS.values()), ids=lambda p: p.name)
def test_a_patterns_declared_obligations_match_its_file(pattern: PackPattern) -> None:
    declared = {
        obligation
        for entry in PACK.provenance
        if entry.policy_id in pattern.policy_ids
        for obligation in entry.obligations
    }

    assert declared == set(pattern.obligations)


# --- rbac --------------------------------------------------------------------------------

SUPPORT = role("support")
ORDERS = node(thing("orders"), {"required_role": SUPPORT})
RBAC_GRAPH = (node(SUPPORT), ORDERS, node(user("alice"), parents=[SUPPORT]), node(user("bob")))


@pytest.mark.unit
def test_rbac_permits_a_principal_holding_the_role_the_resource_requires() -> None:
    decision = decide(
        user("alice"), EntityRef("Action", "orders.search"), thing("orders"), entities=RBAC_GRAPH
    )

    assert decision.allowed
    assert decision.determining_policies == ("rbac-required-role",)


@pytest.mark.unit
def test_rbac_refuses_a_principal_without_the_role() -> None:
    decision = decide(
        user("bob"), EntityRef("Action", "orders.search"), thing("orders"), entities=RBAC_GRAPH
    )

    assert not decision.allowed
    assert decision.determining_policies == ()


# --- groups ------------------------------------------------------------------------------

EU = group("eu")
EU_WEST = group("eu-west")
GROUP_GRAPH = (
    node(EU),
    node(EU_WEST, parents=[EU]),
    node(thing("eu-ledger"), {"group": EU}),
    node(user("mo"), parents=[EU_WEST]),
    node(user("nia")),
)


@pytest.mark.unit
def test_group_membership_resolves_through_the_hierarchy() -> None:
    decision = decide(
        user("mo"), EntityRef("Action", "ledger.read"), thing("eu-ledger"), entities=GROUP_GRAPH
    )

    assert decision.allowed
    assert decision.determining_policies == ("group-membership",)


@pytest.mark.unit
def test_group_membership_refuses_a_principal_outside_the_hierarchy() -> None:
    decision = decide(
        user("nia"), EntityRef("Action", "ledger.read"), thing("eu-ledger"), entities=GROUP_GRAPH
    )

    assert not decision.allowed
    assert decision.determining_policies == ()


# --- ownership ---------------------------------------------------------------------------

OWNED_GRAPH = (
    node(thing("note"), {"owner": user("alice")}),
    node(user("alice")),
    node(user("bob")),
)


@pytest.mark.unit
def test_ownership_permits_the_owner() -> None:
    decision = decide(
        user("alice"), EntityRef("Action", "note.read"), thing("note"), entities=OWNED_GRAPH
    )

    assert decision.allowed
    assert decision.determining_policies == ("resource-owner",)


@pytest.mark.unit
def test_ownership_refuses_someone_who_is_not_the_owner() -> None:
    decision = decide(
        user("bob"), EntityRef("Action", "note.read"), thing("note"), entities=OWNED_GRAPH
    )

    assert not decision.allowed
    assert decision.determining_policies == ()


# --- delegation --------------------------------------------------------------------------

REFUND = EntityRef("Action", "orders.refund")
SEARCH = EntityRef("Action", "orders.search")
DELEGATION = {
    "delegated_by": user("ana"),
    "delegated_actions": [REFUND],
    "delegation_expires": LATER,
}
DELEGATION_GRAPH = (
    node(SUPPORT),
    ORDERS,
    node(user("ana"), parents=[SUPPORT]),
    node(user("agent"), DELEGATION, parents=[SUPPORT]),
    node(user("plain"), parents=[SUPPORT]),
    node(user("lapsed"), {**DELEGATION, "delegation_expires": EARLIER}, parents=[SUPPORT]),
)


@pytest.mark.unit
def test_delegation_permits_a_declared_call_inside_the_delegated_scope() -> None:
    decision = decide(
        user("agent"),
        REFUND,
        thing("orders"),
        entities=DELEGATION_GRAPH,
        context={"on_behalf_of": user("ana")},
    )

    assert decision.allowed
    # The agent holds the role in its own right too, so both permits fire. What matters is
    # that the delegation permit is one of them, since it is the one carrying the obligation.
    assert set(decision.determining_policies) == {"rbac-required-role", "delegation-on-behalf-of"}
    assert PACK.obligations_for(decision.determining_policies, allowed=True) == (
        "record:on_behalf_of",
    )


@pytest.mark.unit
def test_delegation_binds_the_agent_rather_than_merely_adding_to_it() -> None:
    # The same action, from a principal holding the same role but no delegation, is permitted.
    # So the refusal below is the delegation scope talking, not an absent entitlement.
    unbound = decide(user("plain"), SEARCH, thing("orders"), entities=DELEGATION_GRAPH)

    assert unbound.allowed
    assert unbound.determining_policies == ("rbac-required-role",)

    decision = decide(
        user("agent"),
        SEARCH,
        thing("orders"),
        entities=DELEGATION_GRAPH,
        context={"on_behalf_of": user("ana")},
    )

    assert not decision.allowed
    assert decision.determining_policies == ("delegation-outside-scope-forbidden",)


@pytest.mark.unit
def test_delegation_refuses_a_call_after_the_delegation_has_lapsed() -> None:
    decision = decide(
        user("lapsed"),
        REFUND,
        thing("orders"),
        entities=DELEGATION_GRAPH,
        context={"on_behalf_of": user("ana")},
    )

    assert not decision.allowed
    assert decision.determining_policies == ("delegation-expired-forbidden",)


# --- expiry ------------------------------------------------------------------------------

ENTITLED = {"entitlement_starts": EARLIER, "entitlement_expires": NOW}
EXPIRY_GRAPH = (node(SUPPORT), ORDERS, node(user("temp"), ENTITLED, parents=[SUPPORT]))


@pytest.mark.unit
def test_an_entitlement_still_permits_on_the_last_second_of_its_window() -> None:
    decision = decide(user("temp"), SEARCH, thing("orders"), entities=EXPIRY_GRAPH, now=NOW)

    assert decision.allowed
    assert decision.determining_policies == ("rbac-required-role",)


@pytest.mark.unit
def test_an_entitlement_refuses_one_second_after_its_window() -> None:
    decision = decide(
        user("temp"), SEARCH, thing("orders"), entities=EXPIRY_GRAPH, now=NOW + ONE_SECOND
    )

    assert not decision.allowed
    assert decision.determining_policies == ("entitlement-expired-forbidden",)


@pytest.mark.unit
def test_an_entitlement_refuses_before_it_begins() -> None:
    decision = decide(
        user("temp"), SEARCH, thing("orders"), entities=EXPIRY_GRAPH, now=EARLIER - ONE_SECOND
    )

    assert not decision.allowed
    assert decision.determining_policies == ("entitlement-not-yet-valid-forbidden",)


# --- break the glass ---------------------------------------------------------------------

INCIDENT = role("incident-commander")
VAULT = node(thing("vault"), {"emergency_only": True, "emergency_role": INCIDENT})
OPEN_VAULT = EntityRef("Action", "vault.open")
BTG_GRAPH = (
    node(INCIDENT),
    node(SUPPORT),
    VAULT,
    node(user("ivy"), parents=[INCIDENT]),
    node(user("sam"), parents=[SUPPORT]),
)
EMERGENCY = {"break_glass": True, "justification": "SEV-1 #4412"}


@pytest.mark.unit
def test_break_the_glass_permits_an_entitled_principal_with_a_flag_and_a_justification() -> None:
    decision = decide(
        user("ivy"), OPEN_VAULT, thing("vault"), entities=BTG_GRAPH, context=EMERGENCY
    )

    assert decision.allowed
    assert decision.determining_policies == ("break-the-glass",)
    assert PACK.obligations_for(decision.determining_policies, allowed=True) == (
        "notify:secops",
        "record:justification",
    )


@pytest.mark.unit
def test_an_emergency_resource_is_refused_outright_when_the_flag_is_absent() -> None:
    decision = decide(
        user("ivy"),
        OPEN_VAULT,
        thing("vault"),
        entities=BTG_GRAPH,
        context={"justification": "SEV-1 #4412"},
    )

    assert not decision.allowed
    assert decision.determining_policies == ("emergency-resource-forbidden-without-flag",)


@pytest.mark.unit
def test_the_flag_alone_authorizes_nobody() -> None:
    # The hole phase 5 research found and closed: `break_glass` is caller-supplied, so a
    # permit conditioned on it alone lets any client let itself in.
    decision = decide(
        user("sam"), OPEN_VAULT, thing("vault"), entities=BTG_GRAPH, context=EMERGENCY
    )

    assert not decision.allowed
    assert decision.determining_policies == ()


@pytest.mark.unit
def test_break_the_glass_refuses_an_entitled_principal_with_no_justification() -> None:
    decision = decide(
        user("ivy"),
        OPEN_VAULT,
        thing("vault"),
        entities=BTG_GRAPH,
        context={"break_glass": True, "justification": ""},
    )

    assert not decision.allowed
    assert decision.determining_policies == ()


# --- separation of duties ----------------------------------------------------------------

AUDITOR = role("auditor")
APPROVE = EntityRef("Action", "approve")
INVOICE_APPROVE = EntityRef("Action", "invoice.approve")
SOD_GRAPH = (
    node(AUDITOR),
    node(SUPPORT),
    # The host maps its own approval action into the group the pack ships, which is what lets
    # the four-eyes forbid apply without anyone editing reviewed policy logic.
    node(INVOICE_APPROVE, parents=[APPROVE]),
    node(thing("settlement"), {"required_role": SUPPORT, "conflicting_role": AUDITOR}),
    node(thing("invoice"), {"required_role": SUPPORT, "prepared_by": user("pat")}),
    node(user("pat"), parents=[SUPPORT]),
    node(user("quinn"), parents=[SUPPORT, AUDITOR]),
)


@pytest.mark.unit
def test_a_conflicting_role_is_refused_the_resource() -> None:
    decision = decide(
        user("quinn"),
        EntityRef("Action", "settlement.post"),
        thing("settlement"),
        entities=SOD_GRAPH,
    )

    assert not decision.allowed
    assert decision.determining_policies == ("sod-conflicting-role",)


@pytest.mark.unit
def test_a_principal_with_no_conflicting_role_reaches_the_same_resource() -> None:
    decision = decide(
        user("pat"), EntityRef("Action", "settlement.post"), thing("settlement"), entities=SOD_GRAPH
    )

    assert decision.allowed
    assert decision.determining_policies == ("rbac-required-role",)


@pytest.mark.unit
def test_nobody_approves_what_they_prepared_themselves() -> None:
    decision = decide(user("pat"), INVOICE_APPROVE, thing("invoice"), entities=SOD_GRAPH)

    assert not decision.allowed
    assert decision.determining_policies == ("sod-same-actor-approval",)


@pytest.mark.unit
def test_a_second_pair_of_eyes_may_approve() -> None:
    graph = (*SOD_GRAPH, node(user("kim"), parents=[SUPPORT]))

    decision = decide(user("kim"), INVOICE_APPROVE, thing("invoice"), entities=graph)

    assert decision.allowed
    assert decision.determining_policies == ("rbac-required-role",)


# --- just-in-time elevation --------------------------------------------------------------

DBA = role("dba")
FINANCE = role("finance")
JIT_GRAPH = (
    node(DBA),
    node(FINANCE),
    node(user("dev"), {"elevation_role": DBA, "elevation_until": NOW}),
    node(thing("replica"), {"required_role": DBA}),
    node(thing("ledger"), {"required_role": FINANCE}),
)
READ_REPLICA = EntityRef("Action", "replica.read")


@pytest.mark.unit
def test_jit_elevation_permits_on_the_last_second_of_the_window() -> None:
    decision = decide(user("dev"), READ_REPLICA, thing("replica"), entities=JIT_GRAPH, now=NOW)

    assert decision.allowed
    assert decision.determining_policies == ("jit-elevation",)
    assert PACK.obligations_for(decision.determining_policies, allowed=True) == ("notify:secops",)


@pytest.mark.unit
def test_jit_elevation_refuses_one_second_after_the_window() -> None:
    decision = decide(
        user("dev"), READ_REPLICA, thing("replica"), entities=JIT_GRAPH, now=NOW + ONE_SECOND
    )

    assert not decision.allowed
    assert decision.determining_policies == ("jit-elevation-expired-forbidden",)


@pytest.mark.unit
def test_jit_elevation_does_not_generalize_to_a_resource_requiring_another_role() -> None:
    decision = decide(
        user("dev"), EntityRef("Action", "ledger.read"), thing("ledger"), entities=JIT_GRAPH
    )

    assert not decision.allowed
    assert decision.determining_policies == ()


# --- the schema changes nothing about what the pack decides -------------------------------

ACCESS = EntityRef("Action", "access")
SCHEMA_CASES: tuple[tuple[str, EntityRef, EntityRef, EntityRef, tuple[Entity, ...], dict], ...] = (
    ("rbac permit", user("alice"), ACCESS, thing("orders"), RBAC_GRAPH, {}),
    ("rbac deny", user("bob"), ACCESS, thing("orders"), RBAC_GRAPH, {}),
    ("ownership permit", user("alice"), ACCESS, thing("note"), OWNED_GRAPH, {}),
    ("btg permit", user("ivy"), ACCESS, thing("vault"), BTG_GRAPH, dict(EMERGENCY)),
    ("btg deny", user("ivy"), ACCESS, thing("vault"), BTG_GRAPH, {}),
    ("sod same actor", user("pat"), APPROVE, thing("invoice"), SOD_GRAPH, {}),
    ("jit permit", user("dev"), ACCESS, thing("replica"), JIT_GRAPH, {}),
)


@pytest.mark.unit
@pytest.mark.parametrize("case", SCHEMA_CASES, ids=lambda case: case[0])
def test_the_pack_decides_identically_with_and_without_its_schema(
    case: tuple[str, EntityRef, EntityRef, EntityRef, tuple[Entity, ...], dict],
) -> None:
    _, principal, action, resource, graph, context = case
    with_schema = load_pack(schema=True)

    bare = decide(principal, action, resource, entities=graph, context=context)
    typed = decide(principal, action, resource, entities=graph, context=context, bundle=with_schema)

    assert typed.errors == ()
    assert (typed.decision, typed.determining_policies) == (
        bare.decision,
        bare.determining_policies,
    )
