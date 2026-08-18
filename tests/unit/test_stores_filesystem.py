"""Loading Cedar policy logic off disk: order, hashing, schema validation, provenance.

Sorted filename order is not a nicety. Cedar numbers static policies **positionally in the
text it parsed**, so the annotation index that joins a decision to its provenance is only
valid if the same directory always concatenates to the same string. A test that let the order
float would be testing a different bundle each run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentrykit.cedar import EntityRef
from sentrykit.errors import ConfigurationError
from sentrykit.registry import parse_dsn
from sentrykit.stores.base import PolicySource
from sentrykit.stores.filesystem import FilesystemPolicySource

FIRST = """
@id("first")
permit (principal, action == Action::"tool.first", resource);
"""

SECOND = """
@id("second")
@obligations("notify:secops, justify")
permit (principal, action == Action::"tool.second", resource);
"""

SCHEMA = """
entity User;
entity Resource;
action "tool.first" appliesTo { principal: [User], resource: [Resource] };
"""

UNKNOWN_ACTION = """
@id("names-an-action-the-schema-does-not-have")
permit (principal, action == Action::"tool.nonexistent", resource);
"""

ENTITIES_JSON = """
[
  {"uid": {"type": "Role", "id": "support"}, "attrs": {}, "parents": []},
  {"uid": {"type": "Tool", "id": "orders"}, "attrs": {}, "parents": []}
]
"""


def _populate(directory: Path) -> Path:
    """Write the two-policy fixture set, deliberately named out of order."""
    (directory / "20-second.cedar").write_text(SECOND, encoding="utf-8")
    (directory / "10-first.cedar").write_text(FIRST, encoding="utf-8")
    return directory


@pytest.mark.unit
def test_the_source_satisfies_the_policy_source_contract(tmp_path: Path) -> None:
    assert isinstance(FilesystemPolicySource(_populate(tmp_path)), PolicySource)


@pytest.mark.unit
def test_every_cedar_file_in_the_directory_is_loaded(tmp_path: Path) -> None:
    bundle = FilesystemPolicySource(_populate(tmp_path)).load()

    assert 'Action::"tool.first"' in bundle.policies
    assert 'Action::"tool.second"' in bundle.policies


@pytest.mark.unit
def test_policies_are_concatenated_in_sorted_filename_order(tmp_path: Path) -> None:
    bundle = FilesystemPolicySource(_populate(tmp_path)).load()

    declared = {entry.cedar_id: entry.policy_id for entry in bundle.provenance}

    assert declared["policy0"] == "first"
    assert declared["policy1"] == "second"


@pytest.mark.unit
def test_loading_the_same_directory_twice_produces_the_same_bundle(tmp_path: Path) -> None:
    source = FilesystemPolicySource(_populate(tmp_path))

    assert source.load().policies == source.load().policies
    assert source.load().bundle_hash == source.load().bundle_hash


@pytest.mark.unit
def test_a_file_pattern_narrows_what_is_loaded(tmp_path: Path) -> None:
    _populate(tmp_path)

    bundle = FilesystemPolicySource(tmp_path, pattern="10-*.cedar").load()

    assert 'Action::"tool.first"' in bundle.policies
    assert 'Action::"tool.second"' not in bundle.policies


@pytest.mark.unit
def test_the_current_hash_matches_the_bundle_it_would_load(tmp_path: Path) -> None:
    source = FilesystemPolicySource(_populate(tmp_path))

    assert source.current_hash() == source.load().bundle_hash
    assert source.current_hash()


@pytest.mark.unit
def test_the_hash_changes_when_a_policy_file_on_disk_changes(tmp_path: Path) -> None:
    source = FilesystemPolicySource(_populate(tmp_path))
    before = source.current_hash()

    (tmp_path / "10-first.cedar").write_text(
        FIRST.replace('Action::"tool.first"', 'Action::"tool.renamed"'), encoding="utf-8"
    )

    assert source.current_hash() != before


@pytest.mark.unit
def test_the_hash_changes_when_a_policy_file_is_added(tmp_path: Path) -> None:
    source = FilesystemPolicySource(_populate(tmp_path))
    before = source.current_hash()

    (tmp_path / "30-third.cedar").write_text(
        '@id("third")\npermit (principal, action == Action::"tool.third", resource);\n',
        encoding="utf-8",
    )

    assert source.current_hash() != before


@pytest.mark.unit
def test_a_missing_directory_is_a_configuration_error(tmp_path: Path) -> None:
    missing = tmp_path / "nowhere"

    with pytest.raises(ConfigurationError) as raised:
        FilesystemPolicySource(missing).load()

    assert "nowhere" in str(raised.value)


@pytest.mark.unit
def test_a_policy_file_that_does_not_parse_is_a_configuration_error(tmp_path: Path) -> None:
    _populate(tmp_path)
    (tmp_path / "40-broken.cedar").write_text("permit (this is not cedar", encoding="utf-8")

    with pytest.raises(ConfigurationError):
        FilesystemPolicySource(tmp_path).load()


@pytest.mark.unit
def test_the_entity_graph_is_loaded_alongside_the_policies(tmp_path: Path) -> None:
    _populate(tmp_path)
    (tmp_path / "entities.json").write_text(ENTITIES_JSON, encoding="utf-8")

    bundle = FilesystemPolicySource(tmp_path).load()

    assert {entity.uid for entity in bundle.entities} == {
        EntityRef("Role", "support"),
        EntityRef("Tool", "orders"),
    }


@pytest.mark.unit
def test_an_absent_entities_file_is_not_an_error(tmp_path: Path) -> None:
    bundle = FilesystemPolicySource(_populate(tmp_path)).load()

    assert bundle.entities == ()


@pytest.mark.unit
def test_provenance_names_the_source_and_the_file_each_policy_came_from(tmp_path: Path) -> None:
    bundle = FilesystemPolicySource(_populate(tmp_path), name="pack").load()

    by_id = {entry.policy_id: entry for entry in bundle.provenance}

    assert by_id["first"].source == "pack"
    assert "10-first.cedar" in by_id["first"].origin
    assert "20-second.cedar" in by_id["second"].origin
    assert by_id["first"].effect == "permit"


@pytest.mark.unit
def test_obligations_are_read_off_the_annotation(tmp_path: Path) -> None:
    bundle = FilesystemPolicySource(_populate(tmp_path)).load()

    by_id = {entry.policy_id: entry for entry in bundle.provenance}

    assert by_id["second"].obligations == ("notify:secops", "justify")
    assert by_id["first"].obligations == ()


@pytest.mark.unit
def test_a_schema_validation_failure_names_the_offending_policy(tmp_path: Path) -> None:
    (tmp_path / "10-first.cedar").write_text(FIRST, encoding="utf-8")
    (tmp_path / "20-unknown.cedar").write_text(UNKNOWN_ACTION, encoding="utf-8")
    schema = tmp_path / "policies.cedarschema"
    schema.write_text(SCHEMA, encoding="utf-8")

    with pytest.raises(ConfigurationError) as raised:
        FilesystemPolicySource(tmp_path, schema_path=schema).load()

    assert "names-an-action-the-schema-does-not-have" in str(raised.value)


@pytest.mark.unit
def test_validation_can_be_switched_off(tmp_path: Path) -> None:
    (tmp_path / "20-unknown.cedar").write_text(UNKNOWN_ACTION, encoding="utf-8")
    schema = tmp_path / "policies.cedarschema"
    schema.write_text(SCHEMA, encoding="utf-8")

    bundle = FilesystemPolicySource(tmp_path, schema_path=schema, validate=False).load()

    assert 'Action::"tool.nonexistent"' in bundle.policies


@pytest.mark.unit
def test_a_valid_policy_set_passes_schema_validation(tmp_path: Path) -> None:
    (tmp_path / "10-first.cedar").write_text(FIRST, encoding="utf-8")
    schema = tmp_path / "policies.cedarschema"
    schema.write_text(SCHEMA, encoding="utf-8")

    bundle = FilesystemPolicySource(tmp_path, schema_path=schema).load()

    assert bundle.schema is not None


@pytest.mark.unit
def test_a_missing_schema_file_is_a_configuration_error(tmp_path: Path) -> None:
    _populate(tmp_path)

    with pytest.raises(ConfigurationError):
        FilesystemPolicySource(tmp_path, schema_path=tmp_path / "absent.cedarschema").load()


@pytest.mark.unit
def test_the_loaded_bundle_builds_a_working_policy_engine(tmp_path: Path) -> None:
    bundle = FilesystemPolicySource(_populate(tmp_path)).load()

    engine = bundle.engine()

    assert engine.policies == bundle.policies


@pytest.mark.unit
def test_from_dsn_builds_the_source_the_registry_would(tmp_path: Path) -> None:
    _populate(tmp_path)

    source = FilesystemPolicySource.from_dsn(parse_dsn(f"file://{tmp_path.as_posix()}"))

    # Named after the directory, not the scheme: a composite namespaces policy ids by source
    # name and refuses two members sharing one, so two `file://` sources must differ.
    assert source.name == tmp_path.name
    assert source.path == tmp_path
    assert 'Action::"tool.first"' in source.load().policies


@pytest.mark.unit
def test_a_dsn_can_override_the_derived_source_name(tmp_path: Path) -> None:
    _populate(tmp_path)

    source = FilesystemPolicySource.from_dsn(
        parse_dsn(f"file://{tmp_path.as_posix()}?name=tenant-a")
    )

    assert source.name == "tenant-a"


@pytest.mark.unit
def test_a_dsn_that_names_no_directory_is_refused() -> None:
    with pytest.raises(ConfigurationError):
        FilesystemPolicySource.from_dsn(parse_dsn("file://"))


@pytest.mark.unit
def test_a_dsn_can_switch_validation_off(tmp_path: Path) -> None:
    (tmp_path / "20-unknown.cedar").write_text(UNKNOWN_ACTION, encoding="utf-8")
    (tmp_path / "policies.cedarschema").write_text(SCHEMA, encoding="utf-8")
    dsn = parse_dsn(f"file://{tmp_path.as_posix()}?validate=false")

    assert 'Action::"tool.nonexistent"' in FilesystemPolicySource.from_dsn(dsn).load().policies


@pytest.mark.unit
def test_a_directory_with_no_matching_policy_files_is_refused_at_wiring_time(
    tmp_path: Path,
) -> None:
    """An empty policy set denies everything — safely, and silently. Say so instead."""
    (tmp_path / "notes.txt").write_text("not a policy", encoding="utf-8")

    with pytest.raises(ConfigurationError) as raised:
        FilesystemPolicySource(tmp_path).load()

    assert "*.cedar" in str(raised.value)


@pytest.mark.unit
def test_a_schema_beside_the_policies_is_found_without_being_named(tmp_path: Path) -> None:
    (tmp_path / "10-first.cedar").write_text(FIRST, encoding="utf-8")
    (tmp_path / "policies.cedarschema").write_text(SCHEMA, encoding="utf-8")

    assert FilesystemPolicySource(tmp_path).load().schema is not None


@pytest.mark.unit
def test_two_schema_files_are_ambiguous_and_must_be_disambiguated(tmp_path: Path) -> None:
    _populate(tmp_path)
    (tmp_path / "a.cedarschema").write_text(SCHEMA, encoding="utf-8")
    (tmp_path / "b.cedarschema").write_text(SCHEMA, encoding="utf-8")

    with pytest.raises(ConfigurationError) as raised:
        FilesystemPolicySource(tmp_path).load()

    assert "schema_path" in str(raised.value)


@pytest.mark.unit
def test_an_entities_file_that_is_not_json_is_refused(tmp_path: Path) -> None:
    _populate(tmp_path)
    (tmp_path / "entities.json").write_text("{ not json", encoding="utf-8")

    with pytest.raises(ConfigurationError) as raised:
        FilesystemPolicySource(tmp_path).load()

    assert "entities.json" in str(raised.value)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ('{"uid": {"type": "Role", "id": "support"}}', "list"),
        ("[42]", "int"),
        ('[{"uid": {"type": "Role", "id": "support"}, "attrs": ["tier"]}]', "attrs"),
        ('[{"uid": {"type": "Role", "id": "support"}, "parents": {"a": 1}}]', "parents"),
        ('[{"uid": 7}]', "entity reference"),
    ],
)
def test_a_malformed_entity_graph_says_what_was_wrong_with_it(
    tmp_path: Path, document: str, expected: str
) -> None:
    _populate(tmp_path)
    (tmp_path / "entities.json").write_text(document, encoding="utf-8")

    with pytest.raises(ConfigurationError) as raised:
        FilesystemPolicySource(tmp_path).load()

    assert expected in str(raised.value)


@pytest.mark.unit
def test_an_entity_reference_may_be_written_in_either_cedar_spelling(tmp_path: Path) -> None:
    _populate(tmp_path)
    (tmp_path / "entities.json").write_text(
        '[{"uid": {"type": "Role", "id": "support"}, "parents": ["Role::\\"staff\\""]}]',
        encoding="utf-8",
    )

    entities = FilesystemPolicySource(tmp_path).load().entities

    assert entities[0].parents == (EntityRef("Role", "staff"),)
