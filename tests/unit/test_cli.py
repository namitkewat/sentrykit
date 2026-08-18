"""The ``sentrykit`` command line, driven the way an operator drives it.

Every test calls :func:`~sentrykit.cli.main` in-process with an argument list and reads what
came back out of ``capsys``. That is the whole surface: an exit code and some text. One test
shells out, and only one — proving ``python -m sentrykit.cli`` reaches the same
:func:`~sentrykit.cli.main` is the one claim an in-process call cannot make.

## The store has to survive the call

``main`` builds its backends from DSNs, and ``memory://`` builds a *fresh* store every time —
that is deliberate, and it is what makes namespace routing testable. It also means a test
cannot inspect the store the command just wrote to. So the fixtures register two plugins,
through exactly the public :func:`~sentrykit.registry.register_grant_store` decorator a
third-party backend would use, that hand back a shared instance per DSN target. The command
under test sees an ordinary DSN; the test keeps the handle.

## What the admin commands are really being asked

`grant` and `revoke` are the reason this module is long. Each one has to prove three separate
things: that the mutation is *gated* (a policy that does not permit it refuses, and the store
is untouched), that it is *argument-filtered* (a constraint on the operator narrows which
grants they may make, and the narrowed value is the one that lands in the store), and that it
is *logged* — an allowed mutation writes exactly two records, a refused one exactly one.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from sentrykit import cli
from sentrykit.cedar import Entity, EntityRef
from sentrykit.cli import ADMIN_RESOURCE, EXIT_FAILED, EXIT_OK, build_parser, main
from sentrykit.constraints import ArgumentConstraint
from sentrykit.registry import DSN, register_audit_sink, register_grant_store
from sentrykit.stores.base import GrantSpec
from sentrykit.stores.memory import InMemoryAuditSink, InMemoryGrantStore

if TYPE_CHECKING:  # pragma: no cover - imported for annotations only
    from sentrykit.audit import AuthzAuditRecord

pytestmark = pytest.mark.unit

ROOT = EntityRef("User", "root")
"""The operator every admin test acts as."""

ANA = EntityRef("User", "ana")
"""The principal the grants are made to."""

ADMIN_POLICY = """
@id("root-may-administer-grants")
permit (
  principal == User::"root",
  action in [Action::"admin.grant", Action::"admin.revoke"],
  resource == Resource::"admin.grants"
);
"""
"""Permits both admin actions for one named operator, and nothing else."""

LOCKED_POLICY = """
@id("nobody-may-administer-grants")
permit (
  principal == User::"root",
  action == Action::"tool.unrelated",
  resource == Resource::"admin.grants"
);
"""
"""Parses, names the resource, and permits neither admin action -- so the refusal is a
default deny rather than a policy set that could not be built at all."""

FROZEN_POLICY = (
    ADMIN_POLICY
    + """
@id("grants-are-frozen")
forbid (
  principal,
  action in [Action::"admin.grant", Action::"admin.revoke"],
  resource == Resource::"admin.grants"
);
"""
)
"""Permits, then forbids. Forbid wins, and unlike a default deny it *names* the policy that
decided -- which is what a refusal report has to be able to show."""

SHARED_STORES: dict[str, InMemoryGrantStore] = {}
"""Grant stores keyed by DSN target, so ``shared://a`` twice is the same store."""

SHARED_SINKS: dict[str, InMemoryAuditSink] = {}
"""Audit sinks keyed by DSN target, likewise."""


class SharedGrantStore:
    """A ``shared://<name>`` DSN resolving to one in-memory store per target.

    Exists only so a test can hold the store the command under test mutates. It reaches the
    registry through the ordinary :func:`~sentrykit.registry.register_grant_store` decorator
    and returns an ordinary :class:`~sentrykit.stores.memory.InMemoryGrantStore`, so nothing
    about the code path being exercised is special-cased for tests.
    """

    @classmethod
    def from_dsn(cls, dsn: DSN) -> InMemoryGrantStore:
        """Return the store this DSN target names, creating it on first use."""
        return SHARED_STORES.setdefault(dsn.target, InMemoryGrantStore(name=dsn.target or "shared"))


class SharedAuditSink:
    """A ``shared://<name>`` DSN resolving to one in-memory sink per target."""

    @classmethod
    def from_dsn(cls, dsn: DSN) -> InMemoryAuditSink:
        """Return the sink this DSN target names, creating it on first use."""
        return SHARED_SINKS.setdefault(dsn.target, InMemoryAuditSink(name=dsn.target or "shared"))


@pytest.fixture(autouse=True)
def shared_backends(clean_registry: None) -> Iterator[None]:
    """Register the shared backends for one test, and leave the registry as it was found.

    Registered here rather than at import time on purpose: ``register_*`` writes into a
    process-wide dict, so a module-level decorator would add ``shared`` to
    :func:`~sentrykit.registry.available` for every test in the session — including the one
    that asserts the documented backend list is exactly what ships. ``clean_registry``
    snapshots before and restores after, so the registration lives exactly as long as the
    test does.
    """
    register_grant_store("shared")(SharedGrantStore)
    register_audit_sink("shared")(SharedAuditSink)
    SHARED_STORES.clear()
    SHARED_SINKS.clear()
    yield
    SHARED_STORES.clear()
    SHARED_SINKS.clear()


@pytest.fixture
def store(shared_backends: None) -> InMemoryGrantStore:
    """The store behind ``shared://grants``, seeded with the entities the policy names."""
    built = SHARED_STORES.setdefault("grants", InMemoryGrantStore(name="grants"))
    built.add_entity(Entity(EntityRef("Resource", "admin.grants")))
    built.add_entity(Entity(ROOT))
    return built


@pytest.fixture
def sink(shared_backends: None) -> InMemoryAuditSink:
    """The sink behind ``shared://log``."""
    return SHARED_SINKS.setdefault("log", InMemoryAuditSink(name="log"))


@pytest.fixture
def policy_dir(tmp_path: Path) -> Path:
    """A directory holding the admin policy, addressable as ``file://<dir>``."""
    directory = tmp_path / "policies"
    directory.mkdir()
    (directory / "admin.cedar").write_text(ADMIN_POLICY, encoding="utf-8")
    return directory


@pytest.fixture
def locked_policy_dir(tmp_path: Path) -> Path:
    """A directory whose policy permits neither admin action."""
    directory = tmp_path / "locked"
    directory.mkdir()
    (directory / "locked.cedar").write_text(LOCKED_POLICY, encoding="utf-8")
    return directory


@pytest.fixture
def frozen_policy_dir(tmp_path: Path) -> Path:
    """A directory whose ``forbid`` overrides the admin permit, and names itself."""
    directory = tmp_path / "frozen"
    directory.mkdir()
    (directory / "frozen.cedar").write_text(FROZEN_POLICY, encoding="utf-8")
    return directory


def admin_argv(policy_dir: Path, *rest: str) -> list[str]:
    """Build the wiring flags every admin invocation shares."""
    return [
        *rest,
        "--store",
        "shared://grants",
        "--policy",
        f"file://{policy_dir}",
        "--sink",
        "shared://log",
        "--as",
        str(ROOT),
    ]


def kinds(records: tuple[AuthzAuditRecord, ...]) -> list[tuple[str, str]]:
    """Reduce a run of records to the (kind, outcome) pairs the contract is written in."""
    return [(record.kind, record.outcome) for record in records]


# --- policy validate ---------------------------------------------------------------------


SCHEMA = """
entity User;
entity Tool;
action "read" appliesTo { principal: [User], resource: [Tool] };
"""

VALID = '@id("valid")\npermit (\n  principal,\n  action == Action::"read",\n  resource\n);\n'
"""Formatted exactly as ``cedarpy.format_policies`` writes it, so it raises no warning."""

TYPE_ERROR = (
    '@id("mistyped")\npermit (\n  principal,\n  action == Action::"nope",\n  resource\n);\n'
)
"""Names an action the schema does not declare -- Cedar's validator reports two errors."""


@pytest.fixture
def valid_pack(tmp_path: Path) -> Path:
    """A directory that validates clean and lints clean."""
    directory = tmp_path / "clean"
    directory.mkdir()
    (directory / "app.cedarschema").write_text(SCHEMA, encoding="utf-8")
    (directory / "app.cedar").write_text(VALID, encoding="utf-8")
    return directory


def test_validating_the_shipped_pack_with_no_argument_passes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from sentrykit.policy.loader import pack_root

    if not list(pack_root().glob("*.cedar")):
        pytest.skip("the shipped policy pack has not landed yet")

    code = main(["policy", "validate"])

    out = capsys.readouterr().out
    assert code == EXIT_OK, out
    assert "validation: passed" in out


def test_a_type_error_names_the_offending_policy_id_and_the_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = tmp_path / "typed"
    directory.mkdir()
    (directory / "app.cedarschema").write_text(SCHEMA, encoding="utf-8")
    (directory / "app.cedar").write_text(TYPE_ERROR, encoding="utf-8")

    code = main(["policy", "validate", str(directory)])

    out = capsys.readouterr().out
    assert code == EXIT_FAILED
    assert "policy 'mistyped'" in out
    assert "unrecognized action" in out
    assert "validation: failed" in out


def test_one_policy_producing_several_errors_is_reported_as_one_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Grouping is not cosmetic: an unrecognized action yields two messages, not two faults."""
    directory = tmp_path / "grouped"
    directory.mkdir()
    (directory / "app.cedarschema").write_text(SCHEMA, encoding="utf-8")
    (directory / "app.cedar").write_text(TYPE_ERROR, encoding="utf-8")

    code = main(["policy", "validate", str(directory), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_FAILED
    assert list(payload["policy_errors"]) == ["mistyped"]
    assert len(payload["policy_errors"]["mistyped"]) == 2


def test_a_parse_failure_is_reported_at_file_level_and_never_as_a_policy_called_parse(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = tmp_path / "broken"
    directory.mkdir()
    (directory / "app.cedarschema").write_text(SCHEMA, encoding="utf-8")
    (directory / "broken.cedar").write_text("this is not cedar at all\n", encoding="utf-8")

    code = main(["policy", "validate", str(directory)])

    out = capsys.readouterr().out
    assert code == EXIT_FAILED
    assert "<parse>" not in out
    assert "the policy set does not parse" in out
    assert "broken.cedar does not parse" in out


def test_a_directory_with_no_schema_reports_validation_as_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = tmp_path / "schemaless"
    directory.mkdir()
    (directory / "app.cedar").write_text(VALID, encoding="utf-8")

    code = main(["policy", "validate", str(directory), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["validated"] is False
    assert payload["passed"] is None
    assert payload["schema"] is None


def test_a_badly_formatted_file_warns_but_does_not_fail_the_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = tmp_path / "untidy"
    directory.mkdir()
    (directory / "app.cedarschema").write_text(SCHEMA, encoding="utf-8")
    (directory / "app.cedar").write_text('@id("untidy")\npermit(principal,action,resource);\n')

    code = main(["policy", "validate", str(directory)])

    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "warning: app.cedar is not formatted" in out
    assert "validation: passed" in out


def test_a_clean_directory_raises_no_formatting_warning(
    valid_pack: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["policy", "validate", str(valid_pack)])

    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "warning" not in out


def test_the_formatting_comparison_can_be_switched_off(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = tmp_path / "untidy2"
    directory.mkdir()
    (directory / "app.cedarschema").write_text(SCHEMA, encoding="utf-8")
    (directory / "app.cedar").write_text('@id("untidy")\npermit(principal,action,resource);\n')

    code = main(["policy", "validate", str(directory), "--no-format-check"])

    assert code == EXIT_OK
    assert "warning" not in capsys.readouterr().out


def test_validating_never_rewrites_the_file_it_is_reviewing(tmp_path: Path) -> None:
    directory = tmp_path / "untouched"
    directory.mkdir()
    (directory / "app.cedarschema").write_text(SCHEMA, encoding="utf-8")
    original = '@id("untidy")\npermit(principal,action,resource);\n'
    policy = directory / "app.cedar"
    policy.write_text(original, encoding="utf-8")

    main(["policy", "validate", str(directory)])

    assert policy.read_text(encoding="utf-8") == original


def test_a_schema_can_be_named_explicitly_from_outside_the_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = tmp_path / "policies-only"
    directory.mkdir()
    (directory / "app.cedar").write_text(VALID, encoding="utf-8")
    schema = tmp_path / "shared.cedarschema"
    schema.write_text(SCHEMA, encoding="utf-8")

    code = main(["policy", "validate", str(directory), "--schema", str(schema)])

    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "schema:   shared.cedarschema" in out
    assert "validation: passed" in out


def test_a_schema_that_does_not_exist_is_a_message_not_a_traceback(
    valid_pack: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["policy", "validate", str(valid_pack), "--schema", str(tmp_path / "gone")])

    assert code == EXIT_FAILED
    assert "is not a file" in capsys.readouterr().err


def test_a_directory_that_does_not_exist_is_a_message_not_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["policy", "validate", str(tmp_path / "nowhere")])

    assert code == EXIT_FAILED
    assert "is not a directory" in capsys.readouterr().err


def test_a_directory_matching_no_policy_files_is_a_failure_not_a_silent_pass(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "empty").mkdir()

    code = main(["policy", "validate", str(tmp_path / "empty")])

    assert code == EXIT_FAILED
    assert "matches '*.cedar'" in capsys.readouterr().err


# --- grant -------------------------------------------------------------------------------


def test_a_permitted_grant_lands_in_the_store_and_writes_two_audit_records(
    store: InMemoryGrantStore,
    sink: InMemoryAuditSink,
    policy_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(admin_argv(policy_dir, "grant", str(ANA), "--role", "oncall", "--reason", "shift"))

    out = capsys.readouterr().out
    assert code == EXIT_OK, out
    held = store.grants_for(ANA)
    assert [(record.spec.kind, record.spec.subject) for record in held] == [("role", "oncall")]
    assert held[0].spec.granted_by == str(ROOT)
    assert kinds(sink.records) == [("decision", "allowed"), ("mutation", "granted")]


def test_the_mutation_record_carries_the_grant_it_describes(
    store: InMemoryGrantStore,
    sink: InMemoryAuditSink,
    policy_dir: Path,
) -> None:
    main(admin_argv(policy_dir, "grant", str(ANA), "--role", "oncall", "--reason", "shift"))

    mutation = sink.records[1]
    assert mutation.grant is not None
    assert mutation.grant["principal"] == str(ANA)
    assert mutation.grant["subject"] == "oncall"
    assert mutation.principal.uid == str(ROOT)
    assert mutation.reason == "shift"


def test_a_grant_the_policy_does_not_permit_leaves_the_store_untouched(
    store: InMemoryGrantStore,
    sink: InMemoryAuditSink,
    locked_policy_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(admin_argv(locked_policy_dir, "grant", str(ANA), "--role", "oncall"))

    err = capsys.readouterr().err
    assert code == EXIT_FAILED
    assert store.grants_for(ANA) == ()
    assert kinds(sink.records) == [("decision", "denied")]
    assert "refused" in err
    assert "The grant store was not touched." in err


def test_an_argument_constraint_narrows_which_grants_the_operator_may_make(
    store: InMemoryGrantStore,
    sink: InMemoryAuditSink,
    policy_dir: Path,
) -> None:
    """The point of routing the admin surface through ``@protect``: not just who, but what.

    The operator holds a constraint restricting ``subject`` to ``oncall``. They ask for
    ``admin``; the filter rejects it and the constraint's own default takes its place, so the
    value that reaches the store came from policy rather than from ``argv``.
    """
    store.grant(
        GrantSpec(
            principal=ROOT,
            kind="constraint",
            subject="subject",
            action='Action::"admin.grant"',
            constraint=ArgumentConstraint(
                allow=("oncall",), default="oncall", policy="grant-oncall-only"
            ),
        )
    )

    code = main(admin_argv(policy_dir, "grant", str(ANA), "--role", "admin"))

    assert code == EXIT_OK
    held = store.grants_for(ANA)
    assert [record.spec.subject for record in held] == ["oncall"]
    assert kinds(sink.records) == [("decision", "allowed"), ("mutation", "granted")]


def test_a_constraint_with_no_default_refuses_rather_than_substituting_one(
    store: InMemoryGrantStore,
    sink: InMemoryAuditSink,
    policy_dir: Path,
) -> None:
    store.grant(
        GrantSpec(
            principal=ROOT,
            kind="constraint",
            subject="subject",
            action='Action::"admin.grant"',
            constraint=ArgumentConstraint(allow=("oncall",), policy="grant-oncall-only"),
        )
    )

    code = main(admin_argv(policy_dir, "grant", str(ANA), "--role", "admin"))

    assert code == EXIT_FAILED
    assert store.grants_for(ANA) == ()
    assert len(sink.records) == 1


def test_an_expiry_given_as_a_bare_date_is_read_as_midnight_utc(
    store: InMemoryGrantStore, policy_dir: Path
) -> None:
    main(admin_argv(policy_dir, "grant", str(ANA), "--role", "oncall", "--expires", "2026-09-01"))

    expires_at = store.grants_for(ANA, include_inactive=True)[0].spec.expires_at
    assert expires_at == datetime(2026, 9, 1, tzinfo=UTC)


def test_an_expiry_given_as_a_timestamp_is_used_exactly(
    store: InMemoryGrantStore, policy_dir: Path
) -> None:
    main(
        admin_argv(
            policy_dir,
            "grant",
            str(ANA),
            "--role",
            "oncall",
            "--expires",
            "2026-09-01T17:30:00+00:00",
        )
    )

    expires_at = store.grants_for(ANA, include_inactive=True)[0].spec.expires_at
    assert expires_at == datetime(2026, 9, 1, 17, 30, tzinfo=UTC)


def test_an_unparseable_expiry_is_a_message_not_a_traceback(
    store: InMemoryGrantStore, policy_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(admin_argv(policy_dir, "grant", str(ANA), "--role", "x", "--expires", "soon"))

    assert code == EXIT_FAILED
    assert "--expires is 'soon'" in capsys.readouterr().err


def test_an_attribute_grant_carries_its_value(store: InMemoryGrantStore, policy_dir: Path) -> None:
    code = main(admin_argv(policy_dir, "grant", str(ANA), "--attribute", "clearance=high"))

    assert code == EXIT_OK
    spec = store.grants_for(ANA)[0].spec
    assert (spec.kind, spec.subject, spec.value) == ("attribute", "clearance", "high")


def test_an_attribute_that_is_not_spelled_key_equals_value_is_refused(
    store: InMemoryGrantStore, policy_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(admin_argv(policy_dir, "grant", str(ANA), "--attribute", "clearance"))

    assert code == EXIT_FAILED
    assert "is not spelled key=value" in capsys.readouterr().err


def test_a_parent_edge_can_be_granted(store: InMemoryGrantStore, policy_dir: Path) -> None:
    code = main(admin_argv(policy_dir, "grant", str(ANA), "--parent", 'Team::"eu-west"'))

    assert code == EXIT_OK
    spec = store.grants_for(ANA)[0].spec
    assert (spec.kind, spec.subject) == ("parent", 'Team::"eu-west"')


def test_a_refusal_names_the_policy_that_decided_it_at_debug_verbosity(
    store: InMemoryGrantStore,
    frozen_policy_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A default deny names no policy; a ``forbid`` does, and the operator needs to see it."""
    monkeypatch.setenv("SENTRYKIT_VERBOSITY", "debug")

    code = main(admin_argv(frozen_policy_dir, "grant", str(ANA), "--role", "oncall"))

    err = capsys.readouterr().err
    assert code == EXIT_FAILED
    assert "determining policies: grants-are-frozen" in err
    assert store.grants_for(ANA) == ()


def test_a_mutation_with_no_configured_sink_warns_but_still_happens(
    store: InMemoryGrantStore,
    policy_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unrecorded mutation is the one an auditor cannot find, so it is never silent."""
    monkeypatch.delenv("SENTRYKIT_AUDIT_SINK", raising=False)

    code = main(
        [
            "grant",
            str(ANA),
            "--role",
            "oncall",
            "--store",
            "shared://grants",
            "--policy",
            f"file://{policy_dir}",
            "--as",
            str(ROOT),
        ]
    )

    err = capsys.readouterr().err
    assert code == EXIT_OK
    assert "no audit sink is configured" in err
    assert "SENTRYKIT_AUDIT_SINK" in err
    assert len(store.grants_for(ANA)) == 1


def test_grant_emits_json_when_asked(
    store: InMemoryGrantStore, policy_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(admin_argv(policy_dir, "grant", str(ANA), "--role", "oncall", "--json"))

    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["outcome"] == "granted"
    assert payload["grant"]["subject"] == "oncall"


# --- fail-closed actor resolution --------------------------------------------------------


def test_no_actor_and_no_environment_variable_fails_closed_and_writes_nothing(
    store: InMemoryGrantStore,
    sink: InMemoryAuditSink,
    policy_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SENTRYKIT_ACTOR", raising=False)

    code = main(
        [
            "grant",
            str(ANA),
            "--role",
            "oncall",
            "--store",
            "shared://grants",
            "--policy",
            f"file://{policy_dir}",
            "--sink",
            "shared://log",
        ]
    )

    err = capsys.readouterr().err
    assert code == EXIT_FAILED
    assert "SENTRYKIT_ACTOR" in err
    assert "Refusing to administer grants as nobody." in err
    assert store.grants_for(ANA) == ()
    assert sink.records == ()


def test_the_actor_can_come_from_the_environment_variable(
    store: InMemoryGrantStore,
    policy_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTRYKIT_ACTOR", str(ROOT))

    code = main(
        [
            "grant",
            str(ANA),
            "--role",
            "oncall",
            "--store",
            "shared://grants",
            "--policy",
            f"file://{policy_dir}",
            "--sink",
            "shared://log",
        ]
    )

    assert code == EXIT_OK
    assert len(store.grants_for(ANA)) == 1


def test_an_actor_the_store_has_never_heard_of_is_refused(
    store: InMemoryGrantStore,
    sink: InMemoryAuditSink,
    policy_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    argv = admin_argv(policy_dir, "grant", str(ANA), "--role", "oncall")

    code = main([*argv[:-1], 'User::"ghost"'])

    err = capsys.readouterr().err
    assert code == EXIT_FAILED
    assert "holds no principal" in err
    assert sink.records == ()


# --- revoke ------------------------------------------------------------------------------


def test_a_permitted_revocation_marks_the_grant_and_writes_two_audit_records(
    store: InMemoryGrantStore,
    sink: InMemoryAuditSink,
    policy_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    granted = store.grant(GrantSpec(principal=ANA, kind="role", subject="oncall"))

    code = main(admin_argv(policy_dir, "revoke", granted.id, "--reason", "shift ended"))

    out = capsys.readouterr().out
    assert code == EXIT_OK, out
    withdrawn = store.grants_for(ANA, include_inactive=True)[0]
    assert withdrawn.revoked_at is not None
    assert withdrawn.revoked_by == str(ROOT)
    assert withdrawn.revoked_reason == "shift ended"
    assert kinds(sink.records) == [("decision", "allowed"), ("mutation", "revoked")]


def test_a_revocation_the_policy_does_not_permit_leaves_the_grant_standing(
    store: InMemoryGrantStore,
    sink: InMemoryAuditSink,
    locked_policy_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    granted = store.grant(GrantSpec(principal=ANA, kind="role", subject="oncall"))

    code = main(admin_argv(locked_policy_dir, "revoke", granted.id))

    assert code == EXIT_FAILED
    assert store.grants_for(ANA)[0].revoked_at is None
    assert kinds(sink.records) == [("decision", "denied")]
    assert "The grant store was not touched." in capsys.readouterr().err


def test_revoking_an_unknown_grant_is_a_message_not_a_traceback(
    store: InMemoryGrantStore, policy_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(admin_argv(policy_dir, "revoke", "no-such-grant"))

    assert code == EXIT_FAILED
    assert "holds no grant with id" in capsys.readouterr().err


# --- grants ------------------------------------------------------------------------------


def test_listing_grants_shows_the_id_revoke_needs(
    store: InMemoryGrantStore, capsys: pytest.CaptureFixture[str]
) -> None:
    granted = store.grant(GrantSpec(principal=ANA, kind="role", subject="oncall"))

    code = main(["grants", str(ANA), "--store", "shared://grants"])

    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert granted.id in out
    assert "holds 1 grant(s)" in out


def test_listing_grants_hides_revoked_ones_unless_asked(
    store: InMemoryGrantStore, capsys: pytest.CaptureFixture[str]
) -> None:
    granted = store.grant(GrantSpec(principal=ANA, kind="role", subject="oncall"))
    store.revoke(granted.id, revoked_by=str(ROOT), reason="done")

    main(["grants", str(ANA), "--store", "shared://grants", "--json"])
    active = json.loads(capsys.readouterr().out)
    main(["grants", str(ANA), "--store", "shared://grants", "--include-inactive", "--json"])
    everything = json.loads(capsys.readouterr().out)

    assert active["grants"] == []
    assert [entry["id"] for entry in everything["grants"]] == [granted.id]


def test_the_listing_shows_only_what_a_grant_record_already_exposes(
    store: InMemoryGrantStore, capsys: pytest.CaptureFixture[str]
) -> None:
    """A read-only command is still a disclosure surface; it must add nothing of its own."""
    granted = store.grant(
        GrantSpec(
            principal=ANA,
            kind="constraint",
            subject="customer_id",
            constraint=ArgumentConstraint(allow=("c-1",), default="c-1", policy="grant-customers"),
        )
    )

    main(["grants", str(ANA), "--store", "shared://grants", "--json"])

    listed = json.loads(capsys.readouterr().out)["grants"][0]
    assert listed == json.loads(json.dumps(granted.as_record(), default=str))


def test_an_unknown_store_scheme_is_a_message_not_a_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["grants", str(ANA), "--store", "nowhere://"])

    assert code == EXIT_FAILED
    assert "no grant_store is registered" in capsys.readouterr().err


# --- the parser and the entry points -----------------------------------------------------


def test_the_parser_can_be_inspected_without_running_anything() -> None:
    parsed = build_parser().parse_args(["policy", "validate"])

    assert parsed.command == "policy"
    assert parsed.policy_command == "validate"
    assert parsed.directory is None
    assert parsed.pattern == "*.cedar"
    assert parsed.format_check is True


def test_the_admin_resource_is_the_one_both_commands_are_decided_against() -> None:
    parser = build_parser()

    grant = parser.parse_args(["grant", str(ANA), "--role", "x", "--store", "memory://"])
    revoke = parser.parse_args(["revoke", "abc", "--store", "memory://"])

    assert grant.policy == "pack://"
    assert revoke.policy == "pack://"
    assert ADMIN_RESOURCE == 'Resource::"admin.grants"'


def test_naming_no_command_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as raised:
        main([])

    assert raised.value.code == 2


def test_the_module_entry_point_reaches_the_same_main() -> None:
    """The one test that shells out: nothing in-process can prove ``python -m`` works."""
    completed = subprocess.run(
        [sys.executable, "-m", "sentrykit.cli", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("sentrykit ")


@pytest.mark.unit
def test_every_line_the_cli_prints_is_ascii() -> None:
    """A cp1252 console renders anything else as a replacement character.

    The audit *report* is a file and may hold whatever markdown wants; this is about the
    lines that go to a terminal. Asserted structurally rather than by eye, because the
    tempting characters -- an em-dash, a curly quote -- are exactly the ones that look
    right in a source file and wrong in a Windows console.
    """
    import ast
    from pathlib import Path

    source = Path(cli.__file__).read_text(encoding="utf-8")
    offenders: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id != "print":
            continue
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Constant)
                and isinstance(inner.value, str)
                and any(ord(character) > 127 for character in inner.value)
            ):
                offenders.append((inner.lineno, inner.value))

    assert offenders == []
