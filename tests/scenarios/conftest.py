"""What every policy-pack scenario needs: a governor over the shipped pack, and a countable log.

The scenarios are the acceptance test for ``src/sentrykit/policy/pack/``. Each one wires a real
governor with ``install(policy_source="pack://", ...)``, establishes a real principal, calls a
real ``@protect``-ed function, and then asserts two things: what the pack decided, and **how
many audit records the decision wrote**.

The second half is not decoration. In phase 4 a double-write of the audit record satisfied every
behavioural assertion in the suite — the call was allowed, the envelope was right, the record
was there — and was caught only by counting. So every scenario ends on
:attr:`AuditLog.outcomes`, which reads the log back through the public query path and returns
the exact ``(kind, outcome)`` sequence. One governed call through ``@protect`` is one record.

Nothing here freezes the clock. Time-dependent scenarios freeze it themselves with
``freezegun``, so the moment a decision was made is written in the test that depends on it
rather than hidden in a fixture.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator, Sequence

import pytest

from sentrykit.audit import GENESIS_HASH, AuthzAuditRecord
from sentrykit.cedar import Entity
from sentrykit.engine import Governor, install
from sentrykit.registry import (
    DSN,
    ENTRY_POINT_GROUPS,
    clear_registry,
    register_audit_sink,
    register_grant_store,
    registrations,
    remember,
)
from sentrykit.stores.base import AuditWindow, GrantStore
from sentrykit.stores.memory import InMemoryAuditSink, InMemoryGrantStore

PACK = "pack://"
"""How the shipped pack is addressed: an ordinary policy-source DSN, with no special casing.

Spelled here so that "the pack is not privileged" stays visible — every scenario reaches it
through the same registry lookup a third-party source goes through, and dropping the DSN would
leave the governor with no pack at all.
"""


class AuditLog:
    """The scenario's audit trail, as the thing a scenario asserts about.

    Wraps the sink rather than being it, because what a scenario needs is not "the records" but
    *the shape of the log*: how many, in what order, with which outcome. Reading them back
    through :meth:`~sentrykit.stores.memory.InMemoryAuditSink.query` rather than off the sink's
    ``records`` attribute means a scenario exercises the same path
    :func:`~sentrykit.cli.build_report` uses.

    Args:
        sink: The sink the scenario's governor writes to.
    """

    def __init__(self, sink: InMemoryAuditSink) -> None:
        self._sink = sink

    @property
    def sink(self) -> InMemoryAuditSink:
        """The underlying sink, for the scenarios that pass it somewhere."""
        return self._sink

    @property
    def records(self) -> list[AuthzAuditRecord]:
        """Every record, oldest first."""
        return list(self._sink.query(AuditWindow()))

    @property
    def outcomes(self) -> list[tuple[str, str]]:
        """The ``(kind, outcome)`` of every record, in write order.

        The assertion every scenario ends on. Comparing the whole list — rather than a length,
        or the last record — pins the count *and* the shape at once, so a missing record and a
        duplicated one both fail, with a diff a reader can act on.
        """
        return [(record.kind, record.outcome) for record in self.records]

    def determining(self, index: int = 0) -> tuple[str, ...]:
        """Return the determining policy ids recorded on one record.

        These are Cedar's own names — the ``@id`` annotation as declared, *not* the namespaced
        ``pack/<id>`` spelling. Namespacing is applied to sentrykit's provenance index rather
        than to the policy text, so the namespaced form lives on
        :attr:`~sentrykit.audit.AuthzAuditRecord.provenance`.

        Args:
            index: Which record, oldest first.

        Returns:
            The determining policy ids.
        """
        return self.records[index].determining_policies

    def obligations(self, index: int = 0) -> tuple[str, ...]:
        """Return the obligations recorded on one record.

        Args:
            index: Which record, oldest first.

        Returns:
            The obligations the determining policies attached.
        """
        return self.records[index].obligations

    def provenance(self, index: int = 0) -> list[tuple[str, str]]:
        """Return ``(source, policy_id)`` for each policy that decided one record.

        Args:
            index: Which record, oldest first.

        Returns:
            One pair per determining policy, with the ids in their namespaced spelling.
        """
        return [
            (str(entry.get("source", "")), str(entry.get("policy_id", "")))
            for entry in self.records[index].provenance
        ]


@pytest.fixture
def sink() -> InMemoryAuditSink:
    """A fresh audit sink per test, so a count is a count of *this* scenario."""
    return InMemoryAuditSink()


@pytest.fixture
def log(sink: InMemoryAuditSink) -> AuditLog:
    """The scenario's audit trail, ready to assert about."""
    return AuditLog(sink)


@pytest.fixture
def store() -> InMemoryGrantStore:
    """A fresh grant store per test, for the scenarios that materialize their principal."""
    return InMemoryGrantStore()


Install = Callable[..., Governor]
"""``(*entities, policy_source=..., grant_store=...) -> Governor`` — see :func:`govern`."""


@pytest.fixture
def govern(sink: InMemoryAuditSink) -> Install:
    """Return a factory that installs a governor over the shipped pack.

    The entity graph is the scenario's own subject matter — the resource that declares what it
    requires, and the roles and groups its edges point at — so it is passed positionally rather
    than fixed in a fixture: a reader sees the whole world the decision was made in, in the
    test that depends on it.

    Args:
        sink: The audit sink every scenario counts.

    Returns:
        A callable taking the scenario's stable entities, plus an optional ``policy_source``
        (defaulting to :data:`PACK`) and ``grant_store``, and returning the installed governor.
    """

    def _install(
        *entities: Entity,
        policy_source: str | Sequence[str] = PACK,
        grant_store: GrantStore | None = None,
    ) -> Governor:
        return install(
            policy_source=policy_source,
            entities=entities,
            grant_store=grant_store,
            audit_sink=sink,
        )

    return _install


# --- shared backends, for the scenarios that cross a command boundary -------------------------
#
# ``memory://`` builds a *separate* store per DSN by design, which is what makes namespace
# routing testable. It also means two ``sentrykit.cli.main()`` calls addressing ``memory://``
# are two unrelated worlds, so a ``grant`` followed by a ``revoke`` could never be asserted end
# to end. These two backends are the same in-memory implementations reached through a DSN that
# resolves to one instance per target, registered exactly the way a third-party backend
# registers (ADR-004). The CLI cannot tell them apart from ``memory://``, which is the point.
#
# Registration happens per test, in :func:`shared_backends`, and is undone afterwards. It is
# process-global state, and a unit test elsewhere asserts that the documented backend list is
# exactly what ships — so a scheme registered at import time would make this directory's
# fixtures decide whether an unrelated test passes.

SCENARIO_SCHEME = "scenario"
"""The DSN scheme both shared backends answer to."""

CLI_DSN = f"{SCENARIO_SCHEME}://cli"
"""The DSN the CLI scenario passes for both its grant store and its audit sink."""


class SharedGrantStore(InMemoryGrantStore):
    """An in-memory grant store that ``scenario://<name>`` resolves to one instance of."""

    _instances: dict[str, SharedGrantStore] = {}  # noqa: RUF012 - a DSN index, not shared data
    _instances_lock = threading.Lock()

    @classmethod
    def from_dsn(cls, dsn: DSN) -> SharedGrantStore:
        """Return the instance for ``dsn``'s target, creating it on first reference.

        Args:
            dsn: ``scenario://<name>``; the target names the shared instance.

        Returns:
            The store. Two calls with the same target return the *same* object.
        """
        key = dsn.target.strip() or "default"
        with cls._instances_lock:
            return cls._instances.setdefault(key, cls(name=f"scenario:{key}"))

    @classmethod
    def forget_all(cls) -> None:
        """Drop every shared instance, so the next test starts from an empty world."""
        with cls._instances_lock:
            cls._instances.clear()


class SharedAuditSink(InMemoryAuditSink):
    """An in-memory audit sink that ``scenario://<name>`` resolves to one instance of.

    Reports its chain tail, as a durable sink does. Without it a second
    :class:`~sentrykit.audit.AuditTrail` over the same log would restart the hash chain at
    :data:`~sentrykit.audit.GENESIS_HASH` and sequence zero, and the CLI scenario — two
    ``main()`` calls, two trails, one log — would be asserting against a chain that could only
    ever look broken.
    """

    _instances: dict[str, SharedAuditSink] = {}  # noqa: RUF012 - a DSN index, not shared data
    _instances_lock = threading.Lock()

    @classmethod
    def from_dsn(cls, dsn: DSN) -> SharedAuditSink:
        """Return the instance for ``dsn``'s target, creating it on first reference.

        Args:
            dsn: ``scenario://<name>``; the target names the shared instance.

        Returns:
            The sink. Two calls with the same target return the *same* object.
        """
        key = dsn.target.strip() or "default"
        with cls._instances_lock:
            return cls._instances.setdefault(key, cls(name=f"scenario:{key}"))

    @classmethod
    def forget_all(cls) -> None:
        """Drop every shared instance, so the next test starts from an empty log."""
        with cls._instances_lock:
            cls._instances.clear()

    @property
    def tail_hash(self) -> str:
        """The last written record's hash, or the genesis hash for an empty log."""
        records = self.records
        return records[-1].record_hash if records else GENESIS_HASH

    @property
    def tail_sequence(self) -> int:
        """The last written record's sequence number, or ``-1`` for an empty log."""
        records = self.records
        return records[-1].sequence if records else -1


@pytest.fixture(autouse=True)
def shared_backends() -> Iterator[None]:
    """Register the shared backends for one scenario, then put the registry back as it was.

    Autouse for the reason the process-state reset in ``tests/conftest.py`` is autouse: the
    plugin registry and a shared instance are both exactly the hidden state the testing
    standards forbid, and undoing them by hand is exactly what a suite eventually forgets.

    Restored the way ``tests/unit/conftest.py`` restores it — snapshot, clear, and
    :func:`~sentrykit.registry.remember` each entry back — so a shipped backend keeps its
    ``builtin`` provenance rather than being rediscovered as an entry point.

    Yields:
        Nothing; the value of this fixture is its teardown.
    """
    saved = {kind: dict(registrations(kind)) for kind in ENTRY_POINT_GROUPS}
    SharedGrantStore.forget_all()
    SharedAuditSink.forget_all()
    register_grant_store(SCENARIO_SCHEME)(SharedGrantStore)
    register_audit_sink(SCENARIO_SCHEME)(SharedAuditSink)
    try:
        yield
    finally:
        clear_registry()
        for plugins in saved.values():
            for plugin in plugins.values():
                remember(plugin)
        SharedGrantStore.forget_all()
        SharedAuditSink.forget_all()


CLI_ADDRESS = DSN(SCENARIO_SCHEME, "cli", {}, CLI_DSN)
""":data:`CLI_DSN`, already parsed — the same address the CLI's own lookup produces."""


@pytest.fixture
def shared_store(shared_backends: None) -> SharedGrantStore:
    """The grant store behind :data:`CLI_DSN`, so a test can seed and inspect it.

    Depends on :func:`shared_backends` explicitly rather than relying on autouse ordering:
    that fixture empties the shared instances on setup, and an instance created before it ran
    would be thrown away underneath the test holding it.
    """
    return SharedGrantStore.from_dsn(CLI_ADDRESS)


@pytest.fixture
def shared_log(shared_backends: None) -> AuditLog:
    """The audit trail behind :data:`CLI_DSN`, so a test can count what a command wrote."""
    return AuditLog(SharedAuditSink.from_dsn(CLI_ADDRESS))
