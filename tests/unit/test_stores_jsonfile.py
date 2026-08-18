"""The file-backed grant store: durable, cross-process, and stat-gated on the read path.

Three properties carry the weight here, and each has a test that would fail if the property
were quietly dropped:

* **The file is the store.** Everything a grant carries — a constraint's allow-set *and*
  whether it configured a default at all, an aware ``expires_at``, a non-string attribute
  value — has to survive a round trip through JSON, because a store that loses constraint
  data on restart silently widens what a principal may pass.
* **A read sees another process's write.** The CLI's whole use case is ``sentrykit grant``
  here and ``sentrykit revoke`` there, so two store objects over one path stand in for two
  processes.
* **A read does not re-parse a file that did not change.** ``get_principal`` is on the hot
  path of every governed call. The parse step is counted through a monkeypatched seam, so
  removing the gate turns the count from zero into one per read.

Time is always fixed — explicit ``now=`` where the API takes one, ``freeze_time`` where it
finds its own — because ``grants_for`` consults the wall clock to decide what is still active.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from freezegun import freeze_time

from sentrykit import install
from sentrykit.cedar import Entity, EntityRef
from sentrykit.constraints import ArgumentConstraint
from sentrykit.errors import ConfigurationError
from sentrykit.registry import build_grant_store, parse_dsn
from sentrykit.stores import jsonfile
from sentrykit.stores.base import GrantSpec, GrantStore, SupportsClose
from sentrykit.stores.jsonfile import JsonFileGrantStore

ALICE = EntityRef("User", "alice")
SEARCH = EntityRef("Action", "tool.search_orders")

MONDAY = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
TUESDAY = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
FRIDAY = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)

POLICY = 'permit(principal in Role::"support", action, resource);'


def _grants(tmp_path: Path) -> Path:
    return tmp_path / "grants.json"


def _role(subject: str = "support", **extra: object) -> GrantSpec:
    return GrantSpec(principal=ALICE, kind="role", subject=subject, **extra)


def _document(path: Path) -> dict[str, object]:
    """The raw file, read as JSON — for asserting on what is on disk, not in the store."""
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _count_parses(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Install a counting wrapper around the parse step and return the list it appends to."""
    original = jsonfile._read_document
    seen: list[Path] = []

    def counting(path: Path, name: str) -> jsonfile._Document:
        seen.append(path)
        return original(path, name)

    monkeypatch.setattr(jsonfile, "_read_document", counting)
    return seen


# --- a missing file ------------------------------------------------------------------------


@pytest.mark.unit
def test_a_store_over_a_path_that_does_not_exist_is_empty(tmp_path: Path) -> None:
    path = _grants(tmp_path)

    store = JsonFileGrantStore(path)

    assert store.get_principal("alice", now=TUESDAY) is None
    assert store.grants_for("alice") == ()
    assert store.entities() == ()
    # Constructing a store must not create anything: a governor wired at import time should
    # not leave a file behind in a deployment that never grants.
    assert not path.exists()


@pytest.mark.unit
def test_the_first_grant_creates_the_file_and_its_parent_directories(tmp_path: Path) -> None:
    path = tmp_path / "var" / "state" / "grants.json"
    store = JsonFileGrantStore(path)

    store.grant(_role(), now=MONDAY)

    assert path.is_file()
    assert _document(path)["version"] == jsonfile.FORMAT_VERSION


@pytest.mark.unit
def test_the_file_is_written_with_newline_line_endings_on_every_platform(
    tmp_path: Path,
) -> None:
    path = _grants(tmp_path)
    JsonFileGrantStore(path).grant(_role(), now=MONDAY)

    assert b"\r" not in path.read_bytes()


# --- the round trip ------------------------------------------------------------------------


@pytest.mark.unit
def test_a_role_grant_round_trips_through_the_file(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    JsonFileGrantStore(path).grant(_role(), now=MONDAY)

    reopened = JsonFileGrantStore(path)
    principal = reopened.get_principal("alice", now=TUESDAY)

    assert principal is not None
    assert principal.roles == ("support",)
    assert [record.spec.subject for record in reopened.grants_for("alice")] == ["support"]


@pytest.mark.unit
def test_a_parent_grant_round_trips_through_the_file(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    JsonFileGrantStore(path).grant(
        GrantSpec(principal=ALICE, kind="parent", subject='Team::"payments"'), now=MONDAY
    )

    principal = JsonFileGrantStore(path).get_principal(ALICE, now=TUESDAY)

    assert principal is not None
    assert EntityRef("Team", "payments") in principal.all_parents()


@pytest.mark.unit
def test_an_attribute_grant_round_trips_a_non_string_value(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    JsonFileGrantStore(path).grant(
        GrantSpec(principal=ALICE, kind="attribute", subject="clearance_level", value=7),
        now=MONDAY,
    )

    principal = JsonFileGrantStore(path).get_principal("alice", now=TUESDAY)

    assert principal is not None
    # Not "7": an integer that came back as a string would silently change what a numeric
    # Cedar comparison decides.
    assert principal.attributes["clearance_level"] == 7


@pytest.mark.unit
def test_a_constraint_grant_round_trips_its_allow_set_and_default(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    JsonFileGrantStore(path).grant(
        GrantSpec(
            principal=ALICE,
            kind="constraint",
            subject="customer_id",
            constraint=ArgumentConstraint(allow=("c-1", "c-2"), default="c-1"),
            action='Action::"tool.search_orders"',
        ),
        now=MONDAY,
    )

    principal = JsonFileGrantStore(path).get_principal("alice", now=TUESDAY)

    assert principal is not None
    constraint = principal.constraints_for(SEARCH).arguments["customer_id"]
    assert constraint.allow == ("c-1", "c-2")
    assert constraint.default == "c-1"
    assert constraint.has_default


@pytest.mark.unit
def test_a_constraint_with_no_default_does_not_acquire_one_on_the_way_through_the_file(
    tmp_path: Path,
) -> None:
    """``has_default`` is derived from ``model_fields_set``, so a naive dump would forge one.

    A full ``model_dump`` writes ``"default": null`` for a constraint that never configured a
    default; read back, that constraint claims ``has_default`` and the engine starts injecting
    ``None`` into every call that omitted the argument. This is the assertion that pins the
    ``exclude_unset=True`` in the writer.
    """
    path = _grants(tmp_path)
    JsonFileGrantStore(path).grant(
        GrantSpec(
            principal=ALICE,
            kind="constraint",
            subject="customer_id",
            constraint=ArgumentConstraint(allow=("c-1",)),
            action='Action::"tool.search_orders"',
        ),
        now=MONDAY,
    )

    principal = JsonFileGrantStore(path).get_principal("alice", now=TUESDAY)

    assert principal is not None
    assert not principal.constraints_for(SEARCH).arguments["customer_id"].has_default


@pytest.mark.unit
def test_an_aware_expiry_and_the_rest_of_the_lifecycle_round_trip(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    JsonFileGrantStore(path).grant(
        _role(expires_at=FRIDAY, granted_by="root", reason="on-call rotation"),
        now=MONDAY,
    )

    record = JsonFileGrantStore(path).grants_for("alice", include_inactive=True)[0]

    assert record.granted_at == MONDAY
    assert record.spec.expires_at == FRIDAY
    assert record.spec.expires_at is not None
    assert record.spec.expires_at.tzinfo is not None
    assert record.spec.granted_by == "root"
    assert record.spec.reason == "on-call rotation"


@pytest.mark.unit
def test_a_seeded_entity_round_trips_with_its_attributes_and_parents(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    JsonFileGrantStore(path).add_entity(
        Entity(
            EntityRef("Team", "payments"),
            attributes={"tier": 2, "region": "eu"},
            parents=(EntityRef("Org", "acme"),),
        )
    )

    entities = {entity.uid: entity for entity in JsonFileGrantStore(path).entities()}

    seeded = entities[EntityRef("Team", "payments")]
    assert seeded.attributes == {"tier": 2, "region": "eu"}
    assert seeded.parents == (EntityRef("Org", "acme"),)


@pytest.mark.unit
def test_the_reopened_store_answers_exactly_as_the_first_one_did(tmp_path: Path) -> None:
    """Every kind at once, compared record for record rather than field by field."""
    path = _grants(tmp_path)
    first = JsonFileGrantStore(path)
    first.add_entity(Entity(EntityRef("Role", "support")))
    first.grant(_role(), now=MONDAY)
    first.grant(GrantSpec(principal=ALICE, kind="parent", subject='Team::"payments"'), now=MONDAY)
    first.grant(
        GrantSpec(principal=ALICE, kind="attribute", subject="clearance_level", value=7),
        now=MONDAY,
    )
    first.grant(
        GrantSpec(
            principal=ALICE,
            kind="constraint",
            subject="customer_id",
            constraint=ArgumentConstraint(allow=("c-1", "c-2"), default="c-1"),
            action='Action::"tool.search_orders"',
        ),
        now=MONDAY,
    )
    expected_grants = first.grants_for("alice", include_inactive=True)
    expected_principal = first.get_principal("alice", now=TUESDAY)
    expected_entities = {entity.uid: entity for entity in first.entities()}
    del first

    reopened = JsonFileGrantStore(path)

    assert reopened.grants_for("alice", include_inactive=True) == expected_grants
    assert reopened.get_principal("alice", now=TUESDAY) == expected_principal
    assert {entity.uid: entity for entity in reopened.entities()} == expected_entities


# --- lifecycle -----------------------------------------------------------------------------


@pytest.mark.unit
def test_a_revocation_persists_and_marks_rather_than_deletes(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    store = JsonFileGrantStore(path)
    record = store.grant(_role(), now=MONDAY)

    store.revoke(record.id, revoked_by="root", reason="rotation ended", now=TUESDAY)

    reopened = JsonFileGrantStore(path)
    held = reopened.grants_for("alice", include_inactive=True)
    assert [entry.id for entry in held] == [record.id]
    assert held[0].revoked_at == TUESDAY
    assert held[0].revoked_by == "root"
    assert held[0].revoked_reason == "rotation ended"
    # The grant is gone from the decision path but not from the record set.
    assert reopened.grants_for("alice") == ()
    assert reopened.get_principal("alice", now=FRIDAY) is not None
    principal = reopened.get_principal("alice", now=FRIDAY)
    assert principal is not None
    assert principal.roles == ()


@pytest.mark.unit
def test_an_expired_grant_is_excluded_from_the_principal_but_kept_in_the_file(
    tmp_path: Path,
) -> None:
    path = _grants(tmp_path)
    with freeze_time(MONDAY):
        JsonFileGrantStore(path).grant(_role(expires_at=TUESDAY))

    with freeze_time(FRIDAY):
        reopened = JsonFileGrantStore(path)
        principal = reopened.get_principal("alice")

        assert principal is not None
        assert principal.roles == ()
        assert reopened.grants_for("alice") == ()
        assert len(reopened.grants_for("alice", include_inactive=True)) == 1

    grants = _document(path)["grants"]
    assert isinstance(grants, list)
    assert grants[0]["spec"]["expires_at"] == "2026-08-18T12:00:00Z"


@pytest.mark.unit
def test_revoking_an_already_revoked_grant_does_not_rewrite_the_file(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    store = JsonFileGrantStore(path)
    record = store.grant(_role(), now=MONDAY)
    store.revoke(record.id, revoked_by="root", now=TUESDAY)
    before = path.read_bytes()

    again = store.revoke(record.id, revoked_by="someone-else", now=FRIDAY)

    # The original revocation's actor and timestamp are the fact the record exists to keep.
    assert again.revoked_by == "root"
    assert again.revoked_at == TUESDAY
    assert path.read_bytes() == before


# --- cross-process visibility ----------------------------------------------------------------


@pytest.mark.unit
def test_a_write_through_one_store_is_visible_to_a_read_through_another(
    tmp_path: Path,
) -> None:
    """Two objects over one path stand in for two processes; neither calls ``reload``."""
    path = _grants(tmp_path)
    writer = JsonFileGrantStore(path)
    reader = JsonFileGrantStore(path)
    assert reader.get_principal("alice", now=TUESDAY) is None

    writer.grant(_role(), now=MONDAY)

    principal = reader.get_principal("alice", now=TUESDAY)
    assert principal is not None
    assert principal.roles == ("support",)


@pytest.mark.unit
def test_a_revocation_through_one_store_is_visible_to_a_read_through_another(
    tmp_path: Path,
) -> None:
    path = _grants(tmp_path)
    writer = JsonFileGrantStore(path)
    reader = JsonFileGrantStore(path)
    record = writer.grant(_role(), now=MONDAY)
    assert reader.grants_for("alice") != ()

    writer.revoke(record.id, revoked_by="root", now=TUESDAY)

    assert reader.grants_for("alice") == ()
    assert len(reader.grants_for("alice", include_inactive=True)) == 1


@pytest.mark.unit
def test_a_writer_carries_forward_a_grant_another_process_made(tmp_path: Path) -> None:
    """The document is replaced wholesale, so a stale writer is how a grant disappears."""
    path = _grants(tmp_path)
    first = JsonFileGrantStore(path)
    second = JsonFileGrantStore(path)

    first.grant(_role("support"), now=MONDAY)
    second.grant(_role("auditor"), now=MONDAY)

    subjects = {record.spec.subject for record in JsonFileGrantStore(path).grants_for("alice")}
    assert subjects == {"support", "auditor"}


@pytest.mark.unit
def test_reload_discards_in_memory_state_for_what_the_file_holds(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    store = JsonFileGrantStore(path)
    store.grant(_role(), now=MONDAY)
    path.unlink()

    store.reload()

    assert store.grants_for("alice", include_inactive=True) == ()
    assert store.get_principal("alice", now=TUESDAY) is None


# --- the refresh gate ------------------------------------------------------------------------


@pytest.mark.unit
def test_reads_do_not_reparse_a_file_that_has_not_changed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Remove the stat gate and this counts one parse per read instead of none."""
    path = _grants(tmp_path)
    store = JsonFileGrantStore(path)
    store.grant(_role(), now=MONDAY)
    other = JsonFileGrantStore(path)

    parses = _count_parses(monkeypatch)
    for _ in range(5):
        store.get_principal("alice", now=TUESDAY)
        store.grants_for("alice")
        store.entities()

    assert parses == []

    # ... and the gate opens exactly once when the file actually moves, not once per read.
    other.grant(_role("auditor"), now=MONDAY)
    store.get_principal("alice", now=TUESDAY)
    store.get_principal("alice", now=TUESDAY)

    assert len(parses) == 1
    principal = store.get_principal("alice", now=TUESDAY)
    assert principal is not None
    assert set(principal.roles) == {"support", "auditor"}


@pytest.mark.unit
def test_a_store_over_a_missing_file_does_not_parse_at_all(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parses = _count_parses(monkeypatch)

    store = JsonFileGrantStore(_grants(tmp_path))
    store.get_principal("alice", now=TUESDAY)

    assert parses == []


# --- a file that cannot be understood --------------------------------------------------------


@pytest.mark.unit
def test_a_file_that_is_not_json_is_a_configuration_error_naming_the_path(
    tmp_path: Path,
) -> None:
    path = _grants(tmp_path)
    path.write_text("{not json at all", encoding="utf-8")

    with pytest.raises(ConfigurationError, match=r"grants\.json"):
        JsonFileGrantStore(path)


@pytest.mark.unit
def test_a_file_whose_shape_is_wrong_is_a_configuration_error_naming_the_path(
    tmp_path: Path,
) -> None:
    path = _grants(tmp_path)
    path.write_text(json.dumps(["not", "a", "document"]), encoding="utf-8")

    with pytest.raises(ConfigurationError, match=r"grants\.json"):
        JsonFileGrantStore(path)


@pytest.mark.unit
@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"grants": [], "entities": []}, id="no-version"),
        pytest.param({"version": 99, "grants": [], "entities": []}, id="future-version"),
        pytest.param({"version": 1, "grants": {}, "entities": []}, id="grants-not-a-list"),
        pytest.param({"version": 1, "grants": [], "entities": {}}, id="entities-not-a-list"),
        pytest.param({"version": 1, "grants": [{"id": "x"}]}, id="grant-missing-fields"),
        pytest.param(
            {"version": 1, "grants": [], "entities": [{"attrs": {}}]}, id="entity-with-no-uid"
        ),
        pytest.param(
            {"version": 1, "grants": [], "entities": [{"uid": 'Role::"admin"'}]},
            id="entity-uid-not-a-reference",
        ),
    ],
)
def test_a_document_that_cannot_be_understood_is_refused_rather_than_read_as_empty(
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    """Starting empty on an unreadable file would silently discard an audit-relevant set."""
    path = _grants(tmp_path)
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ConfigurationError, match=r"grants\.json"):
        JsonFileGrantStore(path)


@pytest.mark.unit
def test_a_file_that_lists_one_grant_twice_is_refused(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    store = JsonFileGrantStore(path)
    store.grant(_role(), now=MONDAY)
    document = _document(path)
    grants = document["grants"]
    assert isinstance(grants, list)
    document["grants"] = [grants[0], grants[0]]
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="more than once"):
        JsonFileGrantStore(path)


@pytest.mark.unit
def test_an_empty_file_is_read_as_an_empty_store(tmp_path: Path) -> None:
    """Nothing to discard, so the friendly reading of ``touch`` costs nothing."""
    path = _grants(tmp_path)
    path.write_text("", encoding="utf-8")

    assert JsonFileGrantStore(path).grants_for("alice") == ()


@pytest.mark.unit
def test_a_file_that_becomes_unreadable_after_construction_surfaces_on_the_next_read(
    tmp_path: Path,
) -> None:
    path = _grants(tmp_path)
    store = JsonFileGrantStore(path)
    store.grant(_role(), now=MONDAY)
    path.write_text("{ truncated", encoding="utf-8")

    with pytest.raises(ConfigurationError, match=r"grants\.json"):
        store.get_principal("alice", now=TUESDAY)


# --- the atomic write ------------------------------------------------------------------------


@pytest.mark.unit
def test_a_write_whose_rename_fails_leaves_the_previous_document_intact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _grants(tmp_path)
    store = JsonFileGrantStore(path)
    store.grant(_role("support"), now=MONDAY)
    before = path.read_bytes()

    def refuse(self: Path, target: str | Path) -> Path:
        raise OSError("the rename could not be completed")

    monkeypatch.setattr(Path, "replace", refuse)
    with pytest.raises(ConfigurationError, match="cannot write"):
        store.grant(_role("admin"), now=TUESDAY)
    monkeypatch.undo()

    assert path.read_bytes() == before
    assert _document(path)["version"] == jsonfile.FORMAT_VERSION
    # Nothing was granted: not on disk, and not in the store either. A grant that did not
    # reach the file did not happen.
    assert [record.spec.subject for record in store.grants_for("alice")] == ["support"]
    assert [record.spec.subject for record in JsonFileGrantStore(path).grants_for("alice")] == [
        "support"
    ]
    # And no half-written temp file is left lying next to it.
    assert sorted(child.name for child in tmp_path.iterdir()) == [path.name]


@pytest.mark.unit
def test_a_reader_never_observes_a_partially_written_document(tmp_path: Path) -> None:
    """The temp file is a sibling, so a reader watching the target sees whole documents only.

    Asserted by looking at what is on disk *while* a write is in flight: the write goes to a
    differently named file until the rename, so the target still parses at every instant.
    """
    path = _grants(tmp_path)
    store = JsonFileGrantStore(path)
    store.grant(_role("support"), now=MONDAY)
    seen: list[int] = []

    original = Path.replace

    def watching(self: Path, target: str | Path) -> Path:
        # Mid-write: the target must still be the previous, complete document.
        document = _document(path)
        grants = document["grants"]
        assert isinstance(grants, list)
        seen.append(len(grants))
        return original(self, target)

    try:
        Path.replace = watching  # type: ignore[method-assign]
        store.grant(_role("admin"), now=TUESDAY)
    finally:
        Path.replace = original  # type: ignore[method-assign]

    assert seen == [1]
    assert len(JsonFileGrantStore(path).grants_for("alice")) == 2


@pytest.mark.unit
def test_flush_writes_the_current_state_out(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    store = JsonFileGrantStore(path)
    store.grant(_role(), now=MONDAY)
    path.unlink()

    store.flush()

    assert [record.spec.subject for record in JsonFileGrantStore(path).grants_for("alice")] == [
        "support"
    ]


# --- closing ---------------------------------------------------------------------------------


@pytest.mark.unit
def test_the_store_supports_close_and_closing_twice_is_harmless(tmp_path: Path) -> None:
    store = JsonFileGrantStore(_grants(tmp_path))

    assert isinstance(store, SupportsClose)

    store.close()
    store.close()


@pytest.mark.unit
def test_a_closed_store_refuses_a_write_rather_than_dropping_it(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    store = JsonFileGrantStore(path)
    store.grant(_role(), now=MONDAY)
    store.close()

    with pytest.raises(ConfigurationError, match="is closed"):
        store.grant(_role("auditor"), now=TUESDAY)

    # Reads still work, the same way a closed audit sink can still be queried.
    assert [record.spec.subject for record in store.grants_for("alice")] == ["support"]


# --- wiring ------------------------------------------------------------------------------------


@pytest.mark.unit
def test_the_store_satisfies_the_grant_store_contract(tmp_path: Path) -> None:
    assert isinstance(JsonFileGrantStore(_grants(tmp_path)), GrantStore)


@pytest.mark.unit
def test_the_dsn_builds_a_store_over_the_named_path(tmp_path: Path) -> None:
    path = _grants(tmp_path)

    store = build_grant_store(f"jsonfile://{path}")

    assert isinstance(store, JsonFileGrantStore)
    assert isinstance(store, GrantStore)
    assert store.path == path
    assert store.name == "jsonfile"
    assert store.namespace is None


@pytest.mark.unit
def test_the_dsn_carries_a_name_and_a_namespace(tmp_path: Path) -> None:
    path = _grants(tmp_path)

    store = JsonFileGrantStore.from_dsn(parse_dsn(f"jsonfile://{path}?namespace=tenant-a"))

    assert store.namespace == "tenant-a"
    # Named after the namespace, so a routed composite's members are distinguishable in an
    # error message rather than all being called "jsonfile".
    assert store.name == "tenant-a"
    assert JsonFileGrantStore.from_dsn(parse_dsn(f"jsonfile://{path}?name=grants")).name == (
        "grants"
    )


@pytest.mark.unit
def test_a_dsn_that_names_no_file_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="names no grant file"):
        build_grant_store("jsonfile://")


@pytest.mark.unit
def test_a_dsn_built_store_is_written_and_read_back_by_the_next_one(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    dsn = f"jsonfile://{path}"
    first = build_grant_store(dsn)
    assert isinstance(first, JsonFileGrantStore)
    first.grant(_role(), now=MONDAY)

    second = build_grant_store(dsn)

    assert second is not None
    principal = second.get_principal("alice", now=TUESDAY)
    assert principal is not None
    assert principal.roles == ("support",)


@pytest.mark.unit
def test_install_wires_the_store_and_its_entities_reach_the_engine(tmp_path: Path) -> None:
    path = _grants(tmp_path)
    seed = JsonFileGrantStore(path)
    seed.grant(_role(), now=MONDAY)

    governor = install(policies=POLICY, grant_store=f"jsonfile://{path}")

    store = governor.grants
    assert isinstance(store, JsonFileGrantStore)
    principal = store.get_principal("alice", now=TUESDAY)
    assert principal is not None
    assert principal.roles == ("support",)
    # The role the grant points at joined the stable entity graph, or no relationship policy
    # over Role::"support" could resolve.
    bundle = governor.bundle
    assert bundle is not None
    assert EntityRef("Role", "support") in {entity.uid for entity in bundle.entities}


@pytest.mark.unit
def test_a_grant_made_after_install_is_seen_by_the_installed_store(tmp_path: Path) -> None:
    """The CLI's shape: one process grants, another decides, neither reloads by hand."""
    path = _grants(tmp_path)
    governor = install(policies=POLICY, grant_store=f"jsonfile://{path}")
    admin = JsonFileGrantStore(path)

    admin.grant(_role(), now=MONDAY)

    store = governor.grants
    assert store is not None
    principal = store.get_principal("alice", now=TUESDAY)
    assert principal is not None
    assert principal.roles == ("support",)


@pytest.mark.unit
def test_the_store_is_reachable_through_the_stores_package(tmp_path: Path) -> None:
    from sentrykit import stores

    assert stores.JsonFileGrantStore is JsonFileGrantStore
    assert "JsonFileGrantStore" in dir(stores)
