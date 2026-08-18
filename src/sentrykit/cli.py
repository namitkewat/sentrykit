"""``sentrykit`` — the maintenance and audit command line.

Three things an operator needs that a library API is the wrong shape for: checking that a
policy directory is sound *before* it is deployed, moving a grant, and turning a year of
decisions into a document somebody can read.

```bash
sentrykit policy validate ./policies
sentrykit grant 'User::"ana"' --role oncall --expires 2026-09-01 \
    --store memory:// --as 'User::"root"'
sentrykit revoke 4f2c... --reason "shift ended" --store memory:// --as 'User::"root"'
sentrykit audit-report --from 2026-01-01 --to 2026-12-31 \
    --out audit.md --sink jsonl://./audit.jsonl
```

Reachable as the ``sentrykit`` console script and as ``python -m sentrykit.cli``; both call
:func:`main`.

## No CLI framework

:mod:`argparse` from the standard library, and nothing else. Three command groups over a
stdlib parser is a few dozen lines of wiring, and a dependency bought with every install of a
library whose entire pitch is that it is thin is a bad trade. Nothing here imports a web
framework or an agent SDK either — the CLI is core (CLAUDE.md §2).

## The admin surface governs itself

``grant`` and ``revoke`` are not privileged back doors into the store. Each one is a
``@protect``-ed callable, decided by the same :class:`~sentrykit.engine.Governor` the
application uses, against ``Action::"admin.grant"`` / ``Action::"admin.revoke"`` on
``Resource::"admin.grants"`` — so a policy can say who may administer grants, *and which
grants they may make*, because the proposed subject and role are ordinary arguments subject to
ordinary argument filtering. The mutation is then written to the audit sink as its own
record (architecture §5).

That means an allowed ``grant`` writes **two** audit records — the decision that permitted it,
and the mutation that happened — and a refused one writes **one**, the refusal. The scenario
tests assert those counts, because a decision that is right and a log that is wrong is still
a failure for an audit-first library.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Final

from sentrykit.audit import AuthzAuditRecord, ChainVerdict
from sentrykit.stores.base import AuditWindow

if TYPE_CHECKING:  # pragma: no cover - imported for annotations only
    from collections.abc import Iterable, Mapping, Sequence

__all__ = [
    "ADMIN_RESOURCE",
    "GRANT_ACTION",
    "REVOKE_ACTION",
    "AuditReport",
    "build_parser",
    "build_report",
    "main",
    "render_markdown",
]

GRANT_ACTION: Final = 'Action::"admin.grant"'
"""The Cedar action a ``sentrykit grant`` asks permission for."""

REVOKE_ACTION: Final = 'Action::"admin.revoke"'
"""The Cedar action a ``sentrykit revoke`` asks permission for."""

ADMIN_RESOURCE: Final = 'Resource::"admin.grants"'
"""The resource both admin actions are decided against."""

EXIT_OK: Final = 0
"""Everything asked for succeeded."""

EXIT_FAILED: Final = 1
"""The command ran and reported a failure — invalid policies, a refusal, a missing grant."""


# --- report model --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditReport:
    """A period's decisions, aggregated — ADR-006's "the yearly report is a query", realized.

    Aggregated by **outcome** rather than by decision, because ``allow``/``deny`` collapses
    six materially different refusals (and both admin mutations) into two buckets, and an
    auditor asking "how often did a call fail validation" cannot get that back out again.

    Attributes:
        window: The query this report answers.
        sink: The name of the sink that answered it.
        generated_at: When the report was built.
        total: How many records the window matched.
        decisions: How many of them were authorization decisions.
        mutations: How many were admin grant mutations.
        allowed: Decisions that permitted the call.
        denied: Decisions that refused it.
        by_outcome: Record count per :data:`~sentrykit.audit.AuditOutcome`, descending.
        by_action: Record count per action uid, descending.
        by_principal: Record count per principal uid, descending.
        by_policy: Refusal *and* allow count per determining policy id, descending — the
            column that answers "which rule is actually doing the work".
        by_obligation: How often each obligation was raised.
        refusals: The refusals themselves, newest first, capped by the caller's ``--top``.
        chain: The tamper-evidence verdict over the matched records, or ``None`` when the
            window filtered by identity and the records are therefore a non-contiguous slice
            of the chain rather than a run of it.
        verified: How many records' own ``record_hash`` recomputed correctly. Always
            meaningful, filtered window or not.
    """

    window: AuditWindow
    sink: str = ""
    generated_at: datetime | None = None
    total: int = 0
    decisions: int = 0
    mutations: int = 0
    allowed: int = 0
    denied: int = 0
    by_outcome: Mapping[str, int] = field(default_factory=dict)
    by_action: Mapping[str, int] = field(default_factory=dict)
    by_principal: Mapping[str, int] = field(default_factory=dict)
    by_policy: Mapping[str, int] = field(default_factory=dict)
    by_obligation: Mapping[str, int] = field(default_factory=dict)
    refusals: tuple[AuthzAuditRecord, ...] = ()
    chain: ChainVerdict | None = None
    verified: int = 0


def build_report(
    records: Iterable[AuthzAuditRecord],
    *,
    window: AuditWindow,
    sink: str = "",
    generated_at: datetime | None = None,
    top: int = 20,
) -> AuditReport:
    """Aggregate a window's worth of records.

    Pure: it reads an iterable and returns a value, touching no sink and no clock. That is
    what lets the report be asserted exactly in a test over a seeded log.

    Args:
        records: The records, oldest first, as :meth:`~sentrykit.stores.base.AuditSink.query`
            returns them.
        window: The query they answer, carried onto the report.
        sink: The sink's name, for the report header.
        generated_at: The report timestamp. Pass one to make a test deterministic.
        top: How many refusals to carry through to :attr:`AuditReport.refusals`.

    Returns:
        The aggregate.
    """
    raise NotImplementedError


def render_markdown(report: AuditReport) -> str:
    """Render a report as markdown.

    Markdown rather than PDF: it is diffable, it renders in every forge and doc site, and it
    costs no dependency. Anyone who needs a PDF runs the markdown through the converter they
    already have.

    Args:
        report: The aggregate.

    Returns:
        The document, ending in a newline.
    """
    raise NotImplementedError


# --- commands ------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for every command.

    Separated from :func:`main` so a test can assert the surface — flags, defaults, help —
    without running anything.

    Returns:
        The parser. Sub-commands are dispatched through the ``command`` destination.
    """
    raise NotImplementedError


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI.

    Args:
        argv: The arguments, defaulting to :data:`sys.argv` ``[1:]``.

    Returns:
        :data:`EXIT_OK` when everything asked for succeeded, :data:`EXIT_FAILED` when the
        command ran and reported a failure. A usage error exits ``2`` through argparse, and a
        :class:`~sentrykit.errors.ConfigurationError` is reported as a message on stderr
        rather than as a traceback — an operator mistyping a DSN has made a mistake, not
        found a bug.
    """
    raise NotImplementedError


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
