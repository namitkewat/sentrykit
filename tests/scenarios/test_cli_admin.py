"""The admin surface governing itself, through ``sentrykit.cli.main``.

``grant`` and ``revoke`` are not back doors into the store. Each is a ``@protect``-ed callable
decided by the same governor the application uses, which is what lets a policy say who may
administer grants — and, because the proposed subject is an ordinary argument, *which* grants
they may make.

The counts are the assertion that matters. An allowed mutation writes **two** records — the
decision that permitted it, then the mutation that happened — because a log that answers "was
it allowed" without answering "did it occur" is not an audit trail. A refused one writes
**one**, and the store is not touched at all.

The store and the sink are addressed as ``scenario://cli``, a backend registered in
``conftest.py`` exactly the way a third-party one registers. It exists because ``memory://``
builds a fresh store per DSN by design, so two ``main()`` calls could otherwise never see each
other's work — which is the whole of a grant-then-revoke round trip.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from sentrykit.audit import verify_chain
from sentrykit.cedar import EntityRef
from sentrykit.cli import main
from sentrykit.stores.base import GrantSpec

if TYPE_CHECKING:  # pragma: no cover - annotations only; pytest supplies the fixtures
    from conftest import AuditLog, SharedGrantStore

CLI_DSN = "scenario://cli"
"""One DSN for both the grant store and the audit sink, as a deployment would use one each."""

ROOT = 'User::"root"'
ANA = 'User::"ana"'

ADMIN_POLICY = """
@id("root-may-administer-grants")
permit (
  principal == User::"root",
  action in [Action::"admin.grant", Action::"admin.revoke"],
  resource == Resource::"admin.grants"
);
"""
"""Deliberately identity-scoped: `mallory` is a real operator with a real role, and still has
no business administering grants."""


@pytest.fixture
def policies(tmp_path: Path) -> str:
    """A policy directory deciding the admin actions, as a ``file://`` DSN."""
    directory = tmp_path / "admin"
    directory.mkdir()
    (directory / "admin.cedar").write_text(ADMIN_POLICY, encoding="utf-8")
    return f"file://{directory.as_posix()}"


@pytest.fixture
def operators(shared_store: SharedGrantStore) -> SharedGrantStore:
    """Seed the two operators the scenarios act as.

    Both have to exist in the store: ``--as`` is resolved by materializing the principal, and
    an actor the store has never heard of is refused before any policy is consulted, because
    an admin surface that invents its own caller has no admin surface at all.
    """
    shared_store.grant(GrantSpec(principal=EntityRef("User", "root"), kind="role", subject="admin"))
    shared_store.grant(
        GrantSpec(principal=EntityRef("User", "mallory"), kind="role", subject="support")
    )
    return shared_store


def _grant_argv(policies: str, *, actor: str) -> list[str]:
    """Build a ``grant`` command line, differing only in who runs it."""
    return [
        "grant",
        ANA,
        "--role",
        "oncall",
        "--reason",
        "on-call rotation",
        "--store",
        CLI_DSN,
        "--sink",
        CLI_DSN,
        "--policy",
        policies,
        "--as",
        actor,
    ]


@pytest.mark.scenario
def test_an_entitled_operator_grants_a_role(
    policies: str, operators: SharedGrantStore, shared_log: AuditLog
) -> None:
    code = main(_grant_argv(policies, actor=ROOT))

    assert code == 0
    held = operators.grants_for(ANA)
    assert len(held) == 1
    assert held[0].spec.kind == "role"
    assert held[0].spec.subject == "oncall"
    assert held[0].spec.granted_by == ROOT
    assert held[0].spec.reason == "on-call rotation"
    # Two records: the decision that permitted the mutation, and the mutation itself.
    assert shared_log.outcomes == [("decision", "allowed"), ("mutation", "granted")]


@pytest.mark.scenario
def test_an_unentitled_operator_is_refused_and_the_store_is_untouched(
    policies: str, operators: SharedGrantStore, shared_log: AuditLog
) -> None:
    code = main(_grant_argv(policies, actor='User::"mallory"'))

    assert code == 1
    assert operators.grants_for(ANA) == ()
    # One record. There was no mutation to record, and recording one would be a lie.
    assert shared_log.outcomes == [("decision", "denied")]


@pytest.mark.scenario
def test_a_grant_can_be_revoked_and_both_verbs_are_logged(
    policies: str, operators: SharedGrantStore, shared_log: AuditLog
) -> None:
    assert main(_grant_argv(policies, actor=ROOT)) == 0
    grant_id = operators.grants_for(ANA)[0].id

    code = main(
        [
            "revoke",
            grant_id,
            "--reason",
            "shift ended",
            "--store",
            CLI_DSN,
            "--sink",
            CLI_DSN,
            "--policy",
            policies,
            "--as",
            ROOT,
        ]
    )

    assert code == 0
    # Revocation marks the record rather than deleting it: "who had what, when" has to survive.
    assert operators.grants_for(ANA) == ()
    withdrawn = operators.grants_for(ANA, include_inactive=True)
    assert len(withdrawn) == 1
    assert withdrawn[0].revoked_by == ROOT
    assert withdrawn[0].revoked_reason == "shift ended"
    assert shared_log.outcomes == [
        ("decision", "allowed"),
        ("mutation", "granted"),
        ("decision", "allowed"),
        ("mutation", "revoked"),
    ]


@pytest.mark.scenario
def test_a_refused_revocation_leaves_the_grant_standing(
    policies: str, operators: SharedGrantStore, shared_log: AuditLog
) -> None:
    assert main(_grant_argv(policies, actor=ROOT)) == 0
    grant_id = operators.grants_for(ANA)[0].id

    code = main(
        [
            "revoke",
            grant_id,
            "--store",
            CLI_DSN,
            "--sink",
            CLI_DSN,
            "--policy",
            policies,
            "--as",
            'User::"mallory"',
        ]
    )

    assert code == 1
    assert len(operators.grants_for(ANA)) == 1
    assert shared_log.outcomes == [
        ("decision", "allowed"),
        ("mutation", "granted"),
        ("decision", "denied"),
    ]


@pytest.mark.scenario
def test_the_mutations_extend_one_unbroken_chain_across_commands(
    policies: str, operators: SharedGrantStore, shared_log: AuditLog
) -> None:
    assert main(_grant_argv(policies, actor=ROOT)) == 0
    grant_id = operators.grants_for(ANA)[0].id
    assert (
        main(
            [
                "revoke",
                grant_id,
                "--store",
                CLI_DSN,
                "--sink",
                CLI_DSN,
                "--policy",
                policies,
                "--as",
                ROOT,
            ]
        )
        == 0
    )

    records = shared_log.records
    assert [record.sequence for record in records] == [0, 1, 2, 3]
    assert verify_chain(records).ok is True


@pytest.mark.scenario
def test_an_actor_the_store_has_never_heard_of_is_refused_before_any_policy_runs(
    policies: str, operators: SharedGrantStore, shared_log: AuditLog
) -> None:
    code = main(_grant_argv(policies, actor='User::"nobody"'))

    assert code == 1
    assert operators.grants_for(ANA) == ()
    # Nothing was decided, so nothing was recorded: this is fail-closed wiring, not a denial.
    assert shared_log.outcomes == []


@pytest.mark.scenario
def test_the_listing_shows_what_the_grant_command_wrote(
    policies: str,
    operators: SharedGrantStore,
    shared_log: AuditLog,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(_grant_argv(policies, actor=ROOT)) == 0
    capsys.readouterr()

    code = main(["grants", ANA, "--store", CLI_DSN])

    assert code == 0
    listing = capsys.readouterr().out
    assert f"{ANA} holds 1 grant(s)." in listing
    assert "subject=oncall" in listing
    # `grants` is read-only, so it is not governed and writes nothing.
    assert shared_log.outcomes == [("decision", "allowed"), ("mutation", "granted")]
