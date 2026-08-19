"""DSN parsing and backend routing: the one mechanism everything pluggable goes through.

The claim under test: a backend is addressed by a DSN, the scheme picks the
implementation, and a third-party class registered in-process is indistinguishable from a
shipped one. The Windows drive-letter case has its own test because ``file://D:/policies`` is
exactly what a URL parser mangles, and this library ships for ``win-64``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from sentrykit.audit import AuthzAuditRecord
from sentrykit.errors import ConfigurationError
from sentrykit.registry import (
    DSN,
    available,
    build_audit_sink,
    build_context_provider,
    build_grant_store,
    build_policy_source,
    clear_registry,
    parse_dsn,
    register_audit_sink,
    registrations,
    resolve,
)
from sentrykit.stores.base import AuditWindow
from sentrykit.stores.composite import CompositeAuditSink
from sentrykit.stores.filesystem import FilesystemPolicySource
from sentrykit.stores.jsonl import JsonlAuditSink
from sentrykit.stores.memory import InMemoryAuditSink, InMemoryGrantStore

POLICY = 'permit (principal, action == Action::"tool.ping", resource);\n'


class _StubSink:
    """A minimal but *complete* audit sink, for tests about registration rather than storage.

    It satisfies the whole ``AuditSink`` protocol on purpose: the registry isinstance-checks
    what it builds, so a stub missing ``query`` would fail at wiring time and test the wrong
    thing.
    """

    name = "stub"

    @classmethod
    def from_dsn(cls, dsn: DSN) -> _StubSink:
        return cls()

    def write(self, record: AuthzAuditRecord) -> None:
        """Discard."""

    def query(self, window: AuditWindow) -> Iterator[AuthzAuditRecord]:
        return iter(())


# --- DSN parsing ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_windows_drive_letter_path_survives_dsn_parsing() -> None:
    dsn = parse_dsn("file://D:/policies")

    assert dsn.scheme == "file"
    assert dsn.target == "D:/policies"


@pytest.mark.unit
def test_a_windows_drive_letter_path_survives_alongside_options() -> None:
    dsn = parse_dsn("jsonl://D:/logs/audit.jsonl?fsync=true")

    assert dsn.target == "D:/logs/audit.jsonl"
    assert dsn.flag("fsync") is True


@pytest.mark.unit
def test_a_dsn_splits_into_a_scheme_a_target_and_its_options() -> None:
    dsn = parse_dsn("jsonl://./audit.jsonl?fsync=true&rotate=false")

    assert dsn.scheme == "jsonl"
    assert dsn.target == "./audit.jsonl"
    assert dsn.option("fsync") == "true"
    assert dsn.raw == "jsonl://./audit.jsonl?fsync=true&rotate=false"


@pytest.mark.unit
@pytest.mark.parametrize("literal", ["true", "1", "yes", "on", "TRUE", " On "])
def test_every_spelling_of_yes_reads_as_true(literal: str) -> None:
    assert parse_dsn(f"jsonl://./a.jsonl?fsync={literal}").flag("fsync") is True


@pytest.mark.unit
@pytest.mark.parametrize("literal", ["false", "0", "no", "off", "FALSE", " Off "])
def test_every_spelling_of_no_reads_as_false(literal: str) -> None:
    assert parse_dsn(f"jsonl://./a.jsonl?fsync={literal}").flag("fsync") is False


@pytest.mark.unit
def test_an_absent_flag_falls_back_to_its_default() -> None:
    dsn = parse_dsn("jsonl://./a.jsonl")

    assert dsn.flag("fsync") is False
    assert dsn.flag("fsync", default=True) is True


@pytest.mark.unit
@pytest.mark.parametrize("literal", ["ture", "maybe", "", "2"])
def test_a_flag_that_is_not_a_boolean_is_refused_rather_than_read_as_false(literal: str) -> None:
    dsn = parse_dsn(f"jsonl://./a.jsonl?fsync={literal}")

    with pytest.raises(ConfigurationError) as raised:
        dsn.flag("fsync")

    assert "fsync" in str(raised.value)


@pytest.mark.unit
def test_an_option_reads_as_an_integer_or_is_refused() -> None:
    assert parse_dsn("jsonl://./a.jsonl?rotate=100").integer("rotate") == 100
    assert parse_dsn("jsonl://./a.jsonl").integer("rotate", default=7) == 7

    with pytest.raises(ConfigurationError):
        parse_dsn("jsonl://./a.jsonl?rotate=lots").integer("rotate")


@pytest.mark.unit
def test_a_bare_backend_name_is_read_as_a_schemeless_dsn() -> None:
    dsn = parse_dsn("memory")

    assert dsn == DSN(scheme="memory", target="", options={}, raw="memory")


@pytest.mark.unit
@pytest.mark.parametrize("text", ["", "   ", "./policies", "?a=b", "D:/policies"])
def test_a_dsn_that_names_no_scheme_is_refused(text: str) -> None:
    with pytest.raises(ConfigurationError):
        parse_dsn(text)


# --- routing -------------------------------------------------------------------------------


@pytest.mark.unit
def test_the_memory_scheme_routes_to_the_in_memory_backends() -> None:
    assert isinstance(build_audit_sink("memory://"), InMemoryAuditSink)
    assert isinstance(build_grant_store("memory://"), InMemoryGrantStore)


@pytest.mark.unit
def test_the_jsonl_scheme_routes_to_the_file_sink(tmp_path: Path) -> None:
    sink = build_audit_sink(f"jsonl://{(tmp_path / 'audit.jsonl').as_posix()}")

    assert isinstance(sink, JsonlAuditSink)
    sink.close()


@pytest.mark.unit
def test_the_file_scheme_routes_to_the_filesystem_policy_source(tmp_path: Path) -> None:
    (tmp_path / "base.cedar").write_text(POLICY, encoding="utf-8")

    source = build_policy_source(f"file://{tmp_path.as_posix()}")

    assert isinstance(source, FilesystemPolicySource)
    assert source.load().policies.strip()


@pytest.mark.unit
def test_several_dsns_build_one_composite_that_is_still_a_sink(tmp_path: Path) -> None:
    sink = build_audit_sink(["memory://", f"jsonl://{(tmp_path / 'a.jsonl').as_posix()}"])

    assert isinstance(sink, CompositeAuditSink)


@pytest.mark.unit
def test_no_dsn_leaves_every_backend_unconfigured() -> None:
    assert build_audit_sink(None) is None
    assert build_grant_store(None) is None
    assert build_policy_source(None) is None
    assert build_context_provider(None) is None


@pytest.mark.unit
def test_an_unknown_scheme_names_the_backends_that_are_available() -> None:
    with pytest.raises(ConfigurationError) as raised:
        build_audit_sink("jsonl1://./audit.jsonl")

    message = str(raised.value)
    assert "jsonl1" in message
    assert "jsonl" in message
    assert "memory" in message


@pytest.mark.unit
def test_a_backend_that_rejects_its_own_dsn_reports_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError):
        build_audit_sink("jsonl://./audit.jsonl?fsync=ture")


# --- registration --------------------------------------------------------------------------


@pytest.mark.unit
def test_the_shipped_backends_are_available_under_their_documented_names() -> None:
    assert "jsonl" in available("audit_sink")
    assert "memory" in available("audit_sink")
    assert "memory" in available("grant_store")
    assert "file" in available("policy_source")


@pytest.mark.unit
def test_the_available_names_are_sorted() -> None:
    names = available("audit_sink")

    assert list(names) == sorted(names)


@pytest.mark.unit
def test_a_shipped_backend_reached_the_registry_the_way_a_plugin_would() -> None:
    registered = resolve("audit_sink", "jsonl")

    assert registered.kind == "audit_sink"
    assert registered.name == "jsonl"
    assert registered.source == "builtin"


@pytest.mark.unit
def test_resolving_an_unregistered_name_names_the_alternatives() -> None:
    with pytest.raises(ConfigurationError) as raised:
        resolve("grant_store", "postgres")

    assert "postgres" in str(raised.value)
    assert "memory" in str(raised.value)


@pytest.mark.unit
def test_a_third_party_sink_registered_in_process_is_routed_like_a_built_in(
    clean_registry: None,
) -> None:
    @register_audit_sink("probe")
    class ProbeSink:
        """A sink that exists only for this test, registered the built-in way."""

        name = "probe"

        def __init__(self, dsn: DSN) -> None:
            self.dsn = dsn

        @classmethod
        def from_dsn(cls, dsn: DSN) -> ProbeSink:
            return cls(dsn)

        def write(self, record: AuthzAuditRecord) -> None:
            """Discard."""

        def query(self, window: AuditWindow) -> Iterator[AuthzAuditRecord]:
            return iter(())

    assert "probe" in available("audit_sink")

    built = build_audit_sink("probe://somewhere?depth=2")

    assert isinstance(built, ProbeSink)
    assert built.dsn.target == "somewhere"
    assert built.dsn.option("depth") == "2"


@pytest.mark.unit
def test_a_class_with_no_from_dsn_cannot_be_registered(clean_registry: None) -> None:
    with pytest.raises(ConfigurationError) as raised:

        @register_audit_sink("headless")
        class Headless:
            name = "headless"

    assert "from_dsn" in str(raised.value)


@pytest.mark.unit
def test_two_different_classes_cannot_claim_the_same_name(clean_registry: None) -> None:
    @register_audit_sink("contested")
    class First(_StubSink):
        name = "contested"

    with pytest.raises(ConfigurationError) as raised:

        @register_audit_sink("contested")
        class Second(_StubSink):
            name = "contested"

    assert "contested" in str(raised.value)
    # The first registration still stands; the loser did not displace it.
    assert isinstance(build_audit_sink("contested://"), First)


@pytest.mark.unit
def test_registering_the_same_class_twice_is_harmless(clean_registry: None) -> None:
    class Repeated(_StubSink):
        name = "repeated"

    register_audit_sink("repeated")(Repeated)
    register_audit_sink("repeated")(Repeated)

    assert isinstance(build_audit_sink("repeated://"), Repeated)


@pytest.mark.unit
@pytest.mark.parametrize("name", ["", "   "])
def test_a_backend_cannot_be_registered_under_an_empty_name(name: str) -> None:
    with pytest.raises(ConfigurationError):
        register_audit_sink(name)


@pytest.mark.unit
def test_clearing_one_kind_leaves_the_others_registered(clean_registry: None) -> None:
    clear_registry("audit_sink")

    assert dict(registrations("audit_sink")) == {}
    assert "memory" in registrations("grant_store")


@pytest.mark.unit
def test_clearing_everything_empties_every_kind(clean_registry: None) -> None:
    clear_registry()

    assert all(not registrations(kind) for kind in ("audit_sink", "grant_store", "policy_source"))
