"""Audit-record fixtures, additive to ``tests/conftest.py``.

Building an :class:`~sentrykit.audit.AuthzAuditRecord` by hand takes nine required fields that
say nothing about the behaviour under test, so :func:`make_record` supplies the boring ones
and :func:`chained` turns a run of them into an actual hash chain.

The plugin registry is the other piece of shared state this suite touches; its snapshot-and-
restore fixture is ``clean_registry`` in ``tests/conftest.py``, shared with the scenarios.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from itertools import count
from typing import Any

import pytest

from sentrykit.audit import GENESIS_HASH, AuthzAuditRecord, PrincipalSnapshot

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
