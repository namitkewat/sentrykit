"""The examples in the Phase 2 docs do what those pages say they do.

`tests/unit/test_documented_examples.py` pins the quickstart's narrative; this pins the three
pages Phase 2 wrote — `docs/policies.md`, `docs/audit.md` and `docs/plugins.md`. The reason is
the same and it is worth restating: documentation that has drifted from the code is worse
than none, because a reader trusts it, copies it, and then debugs the wrong thing.

Every literal asserted here appears verbatim on one of those pages. If a page and this file
disagree, one of them is a bug.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import pytest

from sentrykit import (
    AuditWindow,
    Entity,
    EntityRef,
    Principal,
    Sensitive,
    available,
    configure,
    establish,
    install,
    protect,
)
from sentrykit.audit import verify_chain
from sentrykit.constraints import ArgumentConstraint
from sentrykit.errors import ConfigurationError
from sentrykit.stores import InMemoryAuditSink, InMemoryGrantStore, JsonlAuditSink
from sentrykit.stores.base import GrantSpec

ACCOUNT = "ACCT-4417-9930"
"""The raw value `docs/audit.md` promises never reaches the sink."""

POLICIES = """
@id("support-may-look-up")
@obligations("hmac:account, notify:secops")
permit (
  principal in Role::"support",
  action == Action::"tool.lookup",
  resource == Tool::"accounts"
);
"""
"""Verbatim from `docs/policies.md` — Obligations."""

ENTITIES = [Entity(EntityRef("Role", "support")), Entity(EntityRef("Tool", "accounts"))]


@pytest.fixture
def audited_lookup() -> tuple[object, InMemoryAuditSink]:
    """The protected callable from `docs/audit.md`, wired to an in-memory sink."""
    sink = InMemoryAuditSink()
    configure(hmac_key="dev-key-not-for-production")
    install(POLICIES, entities=ENTITIES, audit_sink=sink)

    @protect(action='Action::"tool.lookup"', resource='Tool::"accounts"')
    def look_up(account: Annotated[str, Sensitive()], note: str = "") -> dict[str, object]:
        return {"account": account, "note": note}

    return look_up, sink


# --- docs/audit.md ---------------------------------------------------------------------


@pytest.mark.unit
def test_the_callable_receives_the_raw_value_and_the_sink_never_does(
    audited_lookup: tuple[object, InMemoryAuditSink],
) -> None:
    look_up, sink = audited_lookup

    with establish(Principal(id="alice", roles=("support",)), channel="agent"):
        result = look_up(account=ACCOUNT)  # type: ignore[operator]

    assert result["account"] == ACCOUNT
    written = json.dumps([record.model_dump(mode="json") for record in sink.records], default=str)
    assert ACCOUNT not in written


@pytest.mark.unit
def test_the_audit_record_reads_as_the_page_prints_it(
    audited_lookup: tuple[object, InMemoryAuditSink],
) -> None:
    look_up, sink = audited_lookup

    with establish(Principal(id="alice", roles=("support",)), channel="agent"):
        look_up(account=ACCOUNT)  # type: ignore[operator]

    record = sink.records[-1]
    assert record.determining_policies == ("support-may-look-up",)
    assert record.obligations == ("hmac:account", "notify:secops")
    assert record.masked == {"account": "hmac"}
    assert str(record.proposed["account"]).startswith("hmac:")
    assert record.provenance[0]["policy_id"] == "support-may-look-up"
    assert record.provenance[0]["effect"] == "permit"
    assert record.provenance[0]["source"] == "inline"
    assert record.provenance[0]["cedar_id"] == "policy0"


@pytest.mark.unit
def test_the_envelope_carries_the_non_masking_obligations_through(
    audited_lookup: tuple[object, InMemoryAuditSink],
) -> None:
    look_up, _ = audited_lookup

    with establish(Principal(id="alice", roles=("support",)), channel="agent"):
        result = look_up(account=ACCOUNT)  # type: ignore[operator]

    envelope = result["_authz"]
    assert envelope["obligations"] == ["hmac:account", "notify:secops"]


@pytest.mark.unit
def test_verify_chain_accepts_the_log_the_page_verifies(
    audited_lookup: tuple[object, InMemoryAuditSink],
) -> None:
    look_up, sink = audited_lookup

    for _ in range(3):
        with establish(Principal(id="alice", roles=("support",)), channel="agent"):
            look_up(account=ACCOUNT)  # type: ignore[operator]

    verdict = verify_chain(sink.records)

    assert verdict.ok
    assert verdict.broken_at is None
    assert verdict.reason is None


@pytest.mark.unit
def test_a_jsonl_sink_verifies_its_own_file_as_the_page_shows(tmp_path: Path) -> None:
    sink = InMemoryAuditSink()
    configure(hmac_key="dev-key-not-for-production")
    install(POLICIES, entities=ENTITIES, audit_sink=sink)
    log = tmp_path / "audit.jsonl"

    with JsonlAuditSink(log) as file_sink:
        install(POLICIES, entities=ENTITIES, audit_sink=file_sink)

        @protect(action='Action::"tool.lookup"', resource='Tool::"accounts"')
        def look_up(account: Annotated[str, Sensitive()]) -> dict[str, object]:
            return {"account": account}

        with establish(Principal(id="alice", roles=("support",)), channel="agent"):
            look_up(account=ACCOUNT)
        verdict = file_sink.verify()

    assert verdict.ok
    assert ACCOUNT not in log.read_text(encoding="utf-8")


@pytest.mark.unit
def test_an_empty_window_matches_everything_and_limit_truncates(
    audited_lookup: tuple[object, InMemoryAuditSink],
) -> None:
    look_up, sink = audited_lookup

    for _ in range(3):
        with establish(Principal(id="alice", roles=("support",)), channel="agent"):
            look_up(account=ACCOUNT)  # type: ignore[operator]

    assert len(list(sink.query(AuditWindow()))) == 3
    assert len(list(sink.query(AuditWindow(limit=2)))) == 2
    assert list(sink.query(AuditWindow(decision="deny"))) == []


# --- docs/policies.md ------------------------------------------------------------------


@pytest.mark.unit
def test_the_grant_example_materializes_and_then_revokes_a_role() -> None:
    store = InMemoryGrantStore()
    store.add_entity(Entity(EntityRef("Role", "support")))

    record = store.grant(
        GrantSpec(
            principal=EntityRef("User", "bob"),
            kind="role",
            subject="support",
            granted_by="ops",
            reason="ticket-4412",
            expires_at=datetime.now(UTC) + timedelta(hours=2),
        )
    )

    granted = store.get_principal("bob")
    assert granted is not None
    assert granted.roles == ("support",)

    store.revoke(record.id, revoked_by="ops", reason="rotation")

    revoked = store.get_principal("bob")
    assert revoked is None or revoked.roles == ()


@pytest.mark.unit
def test_revocation_marks_the_record_so_the_history_survives() -> None:
    store = InMemoryGrantStore()
    record = store.grant(
        GrantSpec(principal=EntityRef("User", "bob"), kind="role", subject="support")
    )

    store.revoke(record.id, revoked_by="ops", reason="rotation")

    history = store.grants_for("bob", include_inactive=True)
    assert len(history) == 1
    assert history[0].revoked_by == "ops"
    assert history[0].revoked_reason == "rotation"


@pytest.mark.unit
def test_a_per_argument_grant_constrains_and_defaults_that_argument() -> None:
    store = InMemoryGrantStore()
    store.grant(
        GrantSpec(
            principal=EntityRef("User", "bob"),
            kind="constraint",
            subject="region",
            action='Action::"tool.lookup"',
            constraint=ArgumentConstraint(
                allow=("eu-west",), default="eu-west", policy="grant-region"
            ),
        )
    )

    principal = store.get_principal("bob")

    assert principal is not None
    resolved = principal.constraints_for(EntityRef("Action", "tool.lookup"))
    assert resolved.arguments["region"].allow == ("eu-west",)
    assert resolved.arguments["region"].default == "eu-west"


@pytest.mark.unit
def test_a_policy_directory_loads_in_sorted_filename_order(tmp_path: Path) -> None:
    (tmp_path / "00-base.cedar").write_text(
        '@id("base-permit")\npermit (principal, action == Action::"a", resource);\n',
        encoding="utf-8",
    )
    (tmp_path / "10-support.cedar").write_text(
        '@id("support-permit")\npermit (principal, action == Action::"b", resource);\n',
        encoding="utf-8",
    )
    (tmp_path / "entities.json").write_text(
        json.dumps(
            [
                {"uid": {"type": "Role", "id": "support"}, "attrs": {}, "parents": []},
                {"uid": {"type": "Tool", "id": "accounts"}, "attrs": {}, "parents": []},
            ]
        ),
        encoding="utf-8",
    )

    governor = install(policy_source=f"file://{tmp_path.as_posix()}")

    bundle = governor.bundle
    assert bundle is not None
    assert [entry.policy_id for entry in bundle.provenance] == ["base-permit", "support-permit"]
    assert {str(entity.uid) for entity in bundle.entities} == {
        'Role::"support"',
        'Tool::"accounts"',
    }


@pytest.mark.unit
def test_a_forbid_wins_whichever_order_the_sources_are_unioned_in(tmp_path: Path) -> None:
    base = tmp_path / "base"
    tenant = tmp_path / "tenant-a"
    base.mkdir()
    tenant.mkdir()
    (base / "00-base.cedar").write_text(
        '@id("may-look-up")\npermit (principal, action == Action::"tool.lookup", resource);\n',
        encoding="utf-8",
    )
    (tenant / "20-restrictions.cedar").write_text(
        '@id("no-lookups-outside-business-hours")\n'
        'forbid (principal, action == Action::"tool.lookup", resource)\n'
        "unless { context.now_hour >= 9 && context.now_hour < 18 };\n",
        encoding="utf-8",
    )
    orders = [
        [f"file://{base.as_posix()}", f"file://{tenant.as_posix()}"],
        [f"file://{tenant.as_posix()}", f"file://{base.as_posix()}"],
    ]

    for sources in orders:
        governor = install(policy_source=sources)

        @protect(action='Action::"tool.lookup"', resource='Tool::"accounts"')
        def look_up(account: str) -> dict[str, object]:
            return {"account": account}

        with establish(Principal(id="alice"), channel="http", now_hour=11):
            assert look_up(account="a")["account"] == "a"

        with (
            establish(Principal(id="alice"), channel="http", now_hour=23),
            pytest.raises(Exception) as refused,
        ):
            look_up(account="a")
        assert "tool.lookup" in str(refused.value)
        assert governor.bundle is not None


@pytest.mark.unit
def test_an_entity_two_sources_define_differently_is_a_configuration_error(
    tmp_path: Path,
) -> None:
    graphs = {
        "one": [{"uid": {"type": "Role", "id": "support"}, "attrs": {}, "parents": []}],
        "two": [
            {"uid": {"type": "Role", "id": "support"}, "attrs": {"tier": "gold"}, "parents": []}
        ],
    }
    for name, graph in graphs.items():
        directory = tmp_path / name
        directory.mkdir()
        (directory / "p.cedar").write_text(
            f'@id("{name}")\npermit (principal, action == Action::"a", resource);\n',
            encoding="utf-8",
        )
        (directory / "entities.json").write_text(json.dumps(graph), encoding="utf-8")

    with pytest.raises(ConfigurationError) as refused:
        install(
            policy_source=[
                f"file://{(tmp_path / 'one').as_posix()}",
                f"file://{(tmp_path / 'two').as_posix()}",
            ]
        )

    assert "ambiguous" in str(refused.value)


@pytest.mark.unit
def test_two_sources_declaring_the_same_entity_identically_is_fine(tmp_path: Path) -> None:
    graph = json.dumps([{"uid": {"type": "Role", "id": "support"}, "attrs": {}, "parents": []}])
    for name in ("one", "two"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "p.cedar").write_text(
            f'@id("{name}")\npermit (principal, action == Action::"a", resource);\n',
            encoding="utf-8",
        )
        (directory / "entities.json").write_text(graph, encoding="utf-8")

    governor = install(
        policy_source=[
            f"file://{(tmp_path / 'one').as_posix()}",
            f"file://{(tmp_path / 'two').as_posix()}",
        ]
    )

    assert governor.bundle is not None
    assert [str(entity.uid) for entity in governor.bundle.entities] == ['Role::"support"']


# --- docs/plugins.md -------------------------------------------------------------------


@pytest.mark.unit
def test_the_page_lists_the_backends_that_actually_ship() -> None:
    assert available("audit_sink") == ("jsonl", "memory")
    assert available("policy_source") == ("file", "pack")
    assert available("grant_store") == ("memory",)


@pytest.mark.unit
def test_passing_a_built_instance_keeps_the_reference_the_page_promises() -> None:
    sink = InMemoryAuditSink()
    configure(hmac_key="dev-key-not-for-production")

    install(POLICIES, entities=ENTITIES, audit_sink=sink)

    @protect(action='Action::"tool.lookup"', resource='Tool::"accounts"')
    def look_up(account: Annotated[str, Sensitive()]) -> dict[str, object]:
        return {"account": account}

    with establish(Principal(id="alice", roles=("support",)), channel="agent"):
        look_up(account=ACCOUNT)

    assert sink.records


@pytest.mark.unit
def test_an_unknown_scheme_names_what_is_available() -> None:
    with pytest.raises(ConfigurationError) as refused:
        install(POLICIES, entities=ENTITIES, audit_sink="nosuchsink://x")

    message = str(refused.value)
    assert "nosuchsink" in message
    assert "jsonl" in message
