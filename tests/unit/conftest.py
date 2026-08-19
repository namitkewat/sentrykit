"""Plugin-registry and audit-record fixtures, additive to ``tests/conftest.py``.

Two kinds of shared state the store and audit suites have to think about:

* **The plugin registry.** ``register_*`` writes into a process-wide dict and built-ins reach
  it by importing their module — so a test that calls
  :func:`~sentrykit.registry.clear_registry` and then returns would leave every later test
  without ``jsonl``, because re-importing an already-imported module re-runs no decorator.
  :func:`clean_registry` snapshots the registrations and puts them back through the public
  :func:`~sentrykit.registry.remember`, so registry tests stay destructive *inside* their own
  test and nowhere else.
* **Audit records.** Building one by hand takes nine required fields that say nothing about
  the behaviour under test, so :func:`make_record` supplies the boring ones and
  :func:`chained` turns a run of them into an actual hash chain.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime
from itertools import count
from typing import Any

import pytest

from sentrykit.audit import GENESIS_HASH, AuthzAuditRecord, PrincipalSnapshot
from sentrykit.registry import ENTRY_POINT_GROUPS, clear_registry, registrations, remember

FIXED_TIME = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
"""The instant every generated record is stamped with unless a test says otherwise."""

ALICE_SNAPSHOT = PrincipalSnapshot(
    uid='User::"alice"',
    type="User",
    id="alice",
    roles=("support",),
)
"""A principal snapshot matching the ``entitled_principal`` fixture in ``tests/conftest.py``."""


@pytest.fixture
def clean_registry() -> Iterator[None]:
    """Let a test register, clear and rebuild the plugin registry without leaking.

    Yields nothing; the value is the teardown.
    """
    saved = {kind: dict(registrations(kind)) for kind in ENTRY_POINT_GROUPS}
    try:
        yield
    finally:
        clear_registry()
        for plugins in saved.values():
            for plugin in plugins.values():
                remember(plugin)


@pytest.fixture
def make_record() -> Callable[..., AuthzAuditRecord]:
    """Return a factory for unchained :class:`AuthzAuditRecord` s with sane defaults."""
    counter = count()

    def build(**overrides: Any) -> AuthzAuditRecord:
        index = next(counter)
        fields: dict[str, Any] = {
            "record_id": f"rec-{index:04d}",
            "timestamp": FIXED_TIME,
            "invocation_id": f"inv-{index:04d}",
            "principal": ALICE_SNAPSHOT,
            "action": 'Action::"tool.search_orders"',
            "resource": 'Tool::"orders"',
            "callable_name": "tests.search_orders",
            "decision": "allow",
            "outcome": "allowed",
        }
        fields.update(overrides)
        return AuthzAuditRecord(**fields)

    return build


@pytest.fixture
def chained() -> Callable[[Sequence[AuthzAuditRecord]], tuple[AuthzAuditRecord, ...]]:
    """Return a helper that links a run of records into one intact hash chain."""

    def link(records: Sequence[AuthzAuditRecord]) -> tuple[AuthzAuditRecord, ...]:
        previous = GENESIS_HASH
        linked: list[AuthzAuditRecord] = []
        for sequence, record in enumerate(records):
            entry = record.chained(prev_hash=previous, sequence=sequence)
            linked.append(entry)
            previous = entry.record_hash
        return tuple(linked)

    return link
