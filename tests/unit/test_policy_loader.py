"""The pack as an ordinary policy source, and templates linked on sentrykit's side.

Two claims are load-bearing here and neither is obvious from reading the loader:

* **The pack is not privileged.** It reaches a governor through the same DSN, the same
  registry and the same union a user's own directory does — which is only true if
  ``build_policy_source(["pack://", "file://..."])` produces a composite whose provenance
  attributes every policy to the right artifact under both the namespaced and the raw
  spelling of its id. A pack that namespaced its own ids would come out ``pack/pack/...``.
* **A template link is a rule and a piece of data at once.** ``cedarpy`` has no linking API,
  so the link is textual on our side; the test that it stops permitting at its expiry is the
  only thing standing between a "time-boxed" grant and a standing one.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentrykit.cedar import CedarRequest, Entity, EntityRef, PolicyEngine
from sentrykit.errors import ConfigurationError
from sentrykit.policy import (
    PACK_NAME,
    PATTERNS,
    SCHEMA_FILE,
    LinkedPolicySource,
    PackPolicySource,
    TemplateLink,
    link_template,
    load_pack,
    loader,
    pack_root,
    pack_schema,
    pack_template,
)
from sentrykit.registry import build_policy_source, parse_dsn
from sentrykit.stores.base import PolicySource
from sentrykit.stores.composite import CompositePolicySource

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
EXPIRES = NOW + timedelta(hours=8)
ONE_SECOND = timedelta(seconds=1)

OWN_POLICY = """
@id("mine")
permit (principal, action == Action::"tool.mine", resource);
"""


@pytest.fixture
def own_policies(tmp_path: Path) -> Path:
    """A user's own policy directory, to union the pack with."""
    directory = tmp_path / "policies"
    directory.mkdir()
    (directory / "10-mine.cedar").write_text(OWN_POLICY, encoding="utf-8")
    return directory


# --- the source contract -----------------------------------------------------------------


@pytest.mark.unit
def test_the_pack_source_satisfies_the_policy_source_contract() -> None:
    assert isinstance(PackPolicySource(), PolicySource)


@pytest.mark.unit
def test_the_pack_contributes_one_provenance_entry_per_policy() -> None:
    bundle = load_pack()

    declared = sum(len(pattern.policy_ids) for pattern in PATTERNS.values())

    assert len(bundle.provenance) == declared
    assert {entry.source for entry in bundle.provenance} == {PACK_NAME}


@pytest.mark.unit
def test_each_provenance_entry_names_the_pattern_file_it_came_from() -> None:
    origins = {entry.policy_id: entry.origin for entry in load_pack().provenance}

    for pattern in PATTERNS.values():
        for policy_id in pattern.policy_ids:
            assert origins[policy_id].endswith(pattern.file)


@pytest.mark.unit
def test_the_bundle_carries_no_schema_unless_one_was_asked_for() -> None:
    assert load_pack().schema is None
    assert load_pack(schema=True).schema == pack_schema()


@pytest.mark.unit
def test_the_packs_entity_graph_ships_the_approval_action_group() -> None:
    assert Entity(EntityRef("Action", "approve")) in load_pack().entities


@pytest.mark.unit
def test_the_current_hash_matches_the_bundle_it_would_load() -> None:
    source = PackPolicySource()

    assert source.current_hash() == source.load().bundle_hash


@pytest.mark.unit
def test_the_hash_distinguishes_a_bundle_that_carries_the_schema() -> None:
    assert PackPolicySource(schema=True).current_hash() != PackPolicySource().current_hash()


# --- addressing by DSN -------------------------------------------------------------------


@pytest.mark.unit
def test_the_pack_is_reachable_through_the_registry_by_dsn() -> None:
    source = build_policy_source("pack://")

    assert isinstance(source, PackPolicySource)
    assert source.name == PACK_NAME
    assert len(source.patterns) == len(PATTERNS)


@pytest.mark.unit
def test_a_bare_scheme_means_the_whole_pack() -> None:
    assert len(PackPolicySource.from_dsn(parse_dsn("pack")).patterns) == len(PATTERNS)


@pytest.mark.unit
def test_a_subset_dsn_loads_only_the_named_patterns() -> None:
    bundle = build_policy_source("pack://ownership").load()

    assert tuple(entry.policy_id for entry in bundle.provenance) == ("resource-owner",)


@pytest.mark.unit
def test_a_subset_keeps_the_tables_order_not_the_dsns() -> None:
    # Cedar numbers policies positionally, so letting the DSN decide the order would make the
    # provenance index depend on how somebody typed the address.
    source = PackPolicySource.from_dsn(parse_dsn("pack://ownership,rbac"))

    assert tuple(pattern.name for pattern in source.patterns) == ("rbac", "ownership")


@pytest.mark.unit
def test_an_unknown_pattern_name_is_a_configuration_error_naming_the_real_ones() -> None:
    with pytest.raises(ConfigurationError) as raised:
        build_policy_source("pack://onwership")

    assert "onwership" in str(raised.value)
    assert "ownership" in str(raised.value)


@pytest.mark.unit
def test_the_dsn_carries_the_source_name_and_the_schema_opt_in() -> None:
    source = PackPolicySource.from_dsn(parse_dsn("pack://?name=baseline&schema=true"))

    assert source.name == "baseline"
    assert source.load().schema == pack_schema()


@pytest.mark.unit
def test_validation_can_be_turned_off_without_changing_what_loads() -> None:
    assert PackPolicySource(validate=False).load().policies == load_pack().policies


# --- composing with a user's own directory -----------------------------------------------


@pytest.mark.unit
def test_the_pack_unions_with_a_user_directory(own_policies: Path) -> None:
    source = build_policy_source(["pack://", f"file://{own_policies}"])

    assert isinstance(source, CompositePolicySource)
    assert [member.name for member in source.sources] == [PACK_NAME, own_policies.name]


@pytest.mark.unit
def test_a_union_namespaces_each_sources_ids_under_that_source(own_policies: Path) -> None:
    bundle = build_policy_source(["pack://", f"file://{own_policies}"]).load()

    ids = [entry.policy_id for entry in bundle.provenance]

    assert "pack/rbac-required-role" in ids
    assert f"{own_policies.name}/mine" in ids
    # The pack must not namespace its own ids: the composite does it, and doing it twice
    # would produce `pack/pack/rbac-required-role`.
    assert not any(entry.policy_id.startswith("pack/pack/") for entry in bundle.provenance)


@pytest.mark.unit
def test_a_union_resolves_provenance_under_both_spellings_of_an_id(own_policies: Path) -> None:
    bundle = build_policy_source(["pack://", f"file://{own_policies}"]).load()

    # Cedar keeps reporting the raw `@id`, because namespacing happens on our side; an audit
    # join that only understood one spelling would find nothing exactly when a union is used.
    namespaced = bundle.provenance_for(["pack/rbac-required-role"])
    raw = bundle.provenance_for(["rbac-required-role"])

    assert namespaced == raw
    assert namespaced[0].source == PACK_NAME
    assert namespaced[0].policy_id == "pack/rbac-required-role"

    mine = bundle.provenance_for(["mine"])

    assert mine[0].source == own_policies.name
    assert mine[0].policy_id == f"{own_policies.name}/mine"


@pytest.mark.unit
def test_a_union_still_decides_what_each_member_decides(own_policies: Path) -> None:
    bundle = build_policy_source(["pack://", f"file://{own_policies}"]).load()
    engine = bundle.engine().with_entities(
        [
            Entity(EntityRef("Role", "support")),
            Entity(EntityRef("User", "alice"), parents=(EntityRef("Role", "support"),)),
            Entity(
                EntityRef("Resource", "orders"),
                {"required_role": EntityRef("Role", "support")},
            ),
        ]
    )

    decision = engine.evaluate(
        CedarRequest(
            principal=EntityRef("User", "alice"),
            action=EntityRef("Action", "orders.search"),
            resource=EntityRef("Resource", "orders"),
            context={"now": NOW},
        )
    )

    assert decision.allowed
    assert bundle.provenance_for(decision.determining_policies)[0].origin.endswith("10-rbac.cedar")


# --- the shipped files -------------------------------------------------------------------


@pytest.mark.unit
def test_the_schema_is_read_from_the_pack_directory() -> None:
    assert pack_schema() == (pack_root() / SCHEMA_FILE).read_text(encoding="utf-8")


@pytest.mark.unit
def test_a_template_is_found_with_or_without_its_suffix() -> None:
    assert pack_template("time-boxed-grant") == pack_template("time-boxed-grant.cedartemplate")
    assert "?principal" in pack_template("time-boxed-grant")


@pytest.mark.unit
def test_an_unknown_template_names_the_ones_that_ship() -> None:
    with pytest.raises(ConfigurationError) as raised:
        pack_template("no-such-template")

    assert "time-boxed-grant" in str(raised.value)


# --- linking a template ------------------------------------------------------------------


def _link(*, link_id: str = "oncall-ana", expires_at: datetime | None = EXPIRES) -> TemplateLink:
    """The shipped time-boxed template, linked for one person and one resource."""
    return link_template(
        pack_template("time-boxed-grant"),
        link_id=link_id,
        principal='User::"ana"',
        resource='Resource::"paging"',
        expires_at=expires_at,
        granted_by='User::"rota-bot"',
        reason="on call until 20:00",
    )


def _decide_link(policy: str, *, now: datetime) -> bool:
    engine = PolicyEngine(
        policy,
        [Entity(EntityRef("User", "ana")), Entity(EntityRef("Resource", "paging"))],
    )
    return engine.evaluate(
        CedarRequest(
            principal=EntityRef("User", "ana"),
            action=EntityRef("Action", "paging.ack"),
            resource=EntityRef("Resource", "paging"),
            context={"now": now},
        )
    ).allowed


@pytest.mark.unit
def test_linking_fills_both_slots_and_names_the_policy() -> None:
    link = _link()

    assert "?principal" not in link.policy
    assert "?resource" not in link.policy
    assert '@id("oncall-ana")' in link.policy
    assert 'User::"ana"' in link.policy
    assert 'Resource::"paging"' in link.policy


@pytest.mark.unit
def test_a_time_boxed_link_permits_before_its_expiry_and_denies_after() -> None:
    policy = _link().policy

    assert _decide_link(policy, now=EXPIRES)
    assert not _decide_link(policy, now=EXPIRES + ONE_SECOND)


@pytest.mark.unit
def test_a_link_without_an_expiry_carries_no_expiry_condition() -> None:
    link = _link(expires_at=None)

    assert "context.now" not in link.policy
    assert _decide_link(link.policy, now=EXPIRES + timedelta(days=365))
    assert link.grant.expires_at is None


@pytest.mark.unit
def test_the_grant_records_the_same_fact_as_the_policy() -> None:
    link = _link()

    assert link.grant.principal == EntityRef("User", "ana")
    assert link.grant.kind == "attribute"
    assert link.grant.subject == "oncall-ana"
    assert link.grant.value == 'Resource::"paging"'
    assert link.grant.expires_at == EXPIRES
    assert link.grant.granted_by == 'User::"rota-bot"'
    assert link.grant.reason == "on call until 20:00"
    assert link.template == pack_template("time-boxed-grant")


@pytest.mark.unit
def test_an_expiry_is_written_as_epoch_seconds() -> None:
    assert f"context.now <= {int(EXPIRES.timestamp())}" in _link().policy


@pytest.mark.unit
def test_a_link_needs_a_name() -> None:
    with pytest.raises(ConfigurationError):
        _link(link_id="   ")


@pytest.mark.unit
def test_a_concrete_policy_is_not_a_template() -> None:
    with pytest.raises(ConfigurationError) as raised:
        link_template(
            "permit (principal, action, resource);",
            link_id="nothing-to-fill",
            principal='User::"ana"',
            resource='Resource::"paging"',
        )

    assert "no ?principal or ?resource slot" in str(raised.value)


@pytest.mark.unit
def test_a_slot_that_cannot_be_filled_is_reported_rather_than_left_in_the_text() -> None:
    # A policy still carrying a slot parses as a *template*, which is inert — so it would have
    # silently granted nothing at all.
    with pytest.raises(ConfigurationError) as raised:
        link_template(
            "permit (principal == ?principal, action == ?action, resource);",
            link_id="unfillable",
            principal='User::"ana"',
            resource='Resource::"paging"',
        )

    assert "?action" in str(raised.value)


# --- linked policies as a source ---------------------------------------------------------


@pytest.mark.unit
def test_a_linked_source_reports_each_link_under_its_own_id() -> None:
    source = LinkedPolicySource([_link()])

    bundle = source.load()

    assert source.name == "linked"
    assert [entry.policy_id for entry in bundle.provenance] == ["oncall-ana"]
    assert bundle.provenance[0].origin == "link:oncall-ana"
    assert source.current_hash() == bundle.bundle_hash


@pytest.mark.unit
def test_a_linked_source_reports_the_links_it_holds() -> None:
    link = _link()

    assert LinkedPolicySource([link], name="oncall").links == (link,)
    assert LinkedPolicySource([link], name="oncall").name == "oncall"


@pytest.mark.unit
def test_a_linked_source_with_no_links_is_an_empty_bundle_not_an_error() -> None:
    assert LinkedPolicySource([]).load().provenance == ()


@pytest.mark.unit
def test_a_linked_source_composes_alongside_the_pack() -> None:
    composite = CompositePolicySource([PackPolicySource(), LinkedPolicySource([_link()])])

    bundle = composite.load()
    ids = [entry.policy_id for entry in bundle.provenance]

    assert "pack/rbac-required-role" in ids
    assert "linked/oncall-ana" in ids
    assert bundle.provenance_for(["oncall-ana"])[0].source == "linked"


# --- a broken install ---------------------------------------------------------------------
#
# The pack ships inside the distribution, so every failure below means the *install* is wrong
# rather than the host's configuration. Each is exercised by pointing `pack_root` somewhere
# else, which is the only way to produce a state a correct install cannot reach.


@pytest.mark.unit
def test_a_missing_pattern_file_is_reported_as_an_incomplete_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "pack_root", lambda: tmp_path)

    with pytest.raises(ConfigurationError) as raised:
        PackPolicySource().load()

    assert "10-rbac.cedar" in str(raised.value)
    assert "incomplete" in str(raised.value)


@pytest.mark.unit
def test_a_missing_schema_is_reported_as_an_unreadable_shipped_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "pack_root", lambda: tmp_path)

    with pytest.raises(ConfigurationError) as raised:
        pack_schema()

    assert SCHEMA_FILE in str(raised.value)


@pytest.fixture
def mistyped_pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A copy of the pack whose RBAC policy names an entity type the schema never declares."""
    broken = tmp_path / "pack"
    shutil.copytree(pack_root(), broken)
    (broken / "10-rbac.cedar").write_text(
        '@id("rbac-required-role")\n'
        "permit (principal, action, resource)\n"
        'when { principal in Team::"engineering" };\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(loader, "pack_root", lambda: broken)
    return broken


@pytest.mark.unit
def test_a_pack_that_does_not_type_check_against_its_schema_refuses_to_wire(
    mistyped_pack: Path,
) -> None:
    with pytest.raises(ConfigurationError) as raised:
        PackPolicySource().load()

    assert "rbac-required-role" in str(raised.value)
    assert "broken" in str(raised.value)


@pytest.mark.unit
def test_validation_can_be_skipped_for_a_pack_that_does_not_type_check(
    mistyped_pack: Path,
) -> None:
    assert PackPolicySource(validate=False).load().provenance
