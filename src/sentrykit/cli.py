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
framework or an agent SDK either: the CLI is part of the core, and the core stays
framework-free.

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
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, cast

from sentrykit import __version__
from sentrykit.audit import AuthzAuditRecord, ChainVerdict, verify_chain
from sentrykit.cedar import EntityRef, format_policies, validate_policies
from sentrykit.config import ENV_PREFIX, get_settings
from sentrykit.context import establish
from sentrykit.decorator import protect
from sentrykit.engine import install
from sentrykit.envelope import ENVELOPE_KEY, last_envelope
from sentrykit.errors import ConfigurationError, SentrykitError
from sentrykit.policy.loader import pack_root
from sentrykit.registry import build_audit_sink, build_grant_store
from sentrykit.stores.base import WILDCARD_ACTION, AuditWindow, GrantSpec, SupportsClose

if TYPE_CHECKING:  # pragma: no cover - imported for annotations only
    from collections.abc import Iterable, Mapping, Sequence

    from sentrykit.context import Principal
    from sentrykit.engine import Governor
    from sentrykit.stores.base import GrantKind, GrantRecord, GrantStore

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

ACTOR_ENV: Final = "SENTRYKIT_ACTOR"
"""Environment variable naming the operator, when ``--as`` is omitted."""

DEFAULT_POLICY_GLOB: Final = "*.cedar"
"""Which files ``policy validate`` reads, unless ``--pattern`` says otherwise."""

SCHEMA_GLOB: Final = "*.cedarschema"
"""Which files supply the schema a directory is validated against."""

PARSE_SENTINEL: Final = "<parse>"
"""``policy_id`` Cedar reports when a failure could not be attributed to a policy.

:func:`~sentrykit.cedar.validate_policies` uses it for a parse error, which by definition has
no ``@id`` to name. Printing "policy ``<parse>`` failed" would tell an operator nothing, so
these are reported at file level instead.
"""

CHANNEL: Final = "cli"
"""``context.channel`` the admin decisions are made under, so a policy can require it."""

_DATE_ONLY: Final = re.compile(r"^\d{4}-\d{2}-\d{2}$")
"""A bare date, as opposed to a full timestamp. The two are windowed differently."""

_GRANT_COLUMNS: Final = ("id", "kind", "subject", "value", "action", "expires_at", "revoked_at")
"""Fields ``sentrykit grants`` prints, all of them read off
:meth:`~sentrykit.stores.base.GrantRecord.as_record` so the listing cannot show anything a
grant record does not already expose."""


# --- report model --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditReport:
    """A period's decisions, aggregated — the yearly audit report as a query, not as manual
    log-reading.

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
    matched = tuple(records)

    outcomes: Counter[str] = Counter()
    actions: Counter[str] = Counter()
    principals: Counter[str] = Counter()
    policies: Counter[str] = Counter()
    obligations: Counter[str] = Counter()

    decisions = mutations = allowed = denied = verified = 0
    refusals: list[AuthzAuditRecord] = []

    for record in matched:
        outcomes[record.outcome] += 1
        if record.action:
            actions[record.action] += 1
        principals[record.principal.uid] += 1
        policies.update(record.determining_policies)
        obligations.update(record.obligations)
        if record.verify():
            verified += 1
        if record.kind == "mutation":
            # Counted here and nowhere else. Folding a grant into "allowed" would collapse
            # two different things: an admin conferring a role is not a call that was
            # permitted, it is a change to what will be permitted next.
            mutations += 1
            continue
        decisions += 1
        if record.decision == "allow":
            allowed += 1
        else:
            denied += 1
            refusals.append(record)

    return AuditReport(
        window=window,
        sink=sink,
        generated_at=generated_at,
        total=len(matched),
        decisions=decisions,
        mutations=mutations,
        allowed=allowed,
        denied=denied,
        by_outcome=_ranked(outcomes),
        by_action=_ranked(actions),
        by_principal=_ranked(principals),
        by_policy=_ranked(policies),
        by_obligation=_ranked(obligations),
        # Newest first, so the section an operator reads top-down opens on what just happened.
        refusals=tuple(reversed(refusals))[: max(top, 0)],
        chain=verify_chain(matched) if _spans_the_chain(window) else None,
        verified=verified,
    )


def _ranked(counts: Counter[str]) -> dict[str, int]:
    """Order a tally by descending count, ties broken by key.

    Deterministic on purpose: ``Counter.most_common`` leaves ties in insertion order, which
    depends on the order records happened to be written, and a report a test cannot assert
    exactly is a report nobody can diff between two periods either.
    """
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return dict(ordered)


def _spans_the_chain(window: AuditWindow) -> bool:
    """Whether ``window``'s records are a contiguous run of the log rather than a slice.

    Time bounds keep a run contiguous; every other filter picks records out of the middle. A
    ``broken_at`` over a filtered set would mean "you filtered", not "somebody tampered", and
    a tamper-evidence line that cries wolf is worse than none — so
    :attr:`AuditReport.chain` is left unset instead.
    """
    return (
        window.principal is None
        and window.action is None
        and window.resource is None
        and window.decision is None
        and window.kind is None
    )


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
    return _document(report)


def _document(report: AuditReport, title: str | None = None) -> str:
    """Render ``report``, optionally under an operator-supplied title.

    :class:`AuditReport` carries no title of its own — it is the aggregate, not the
    presentation — so ``--title`` is threaded through here rather than onto the value object,
    and :func:`render_markdown` stays a pure function of the report.

    Args:
        report: The aggregate.
        title: The document heading. Defaults to one naming the window.

    Returns:
        The document, ending in a newline.
    """
    window = report.window
    lines: list[str] = [
        f"# {title or _default_title(window)}",
        "",
        f"- Window: {_moment(window.start)} to {_moment(window.end)} (end exclusive)",
        f"- Sink: {report.sink or 'unknown'}",
        f"- Generated: {_moment(report.generated_at)}",
        f"- Filters: {_describe_filters(window)}",
        "",
        "## Summary",
        "",
        "| Measure | Count |",
        "| --- | ---: |",
        f"| Records | {report.total} |",
        f"| Decisions | {report.decisions} |",
        f"| Mutations | {report.mutations} |",
        f"| Allowed | {report.allowed} |",
        f"| Denied | {report.denied} |",
        "",
    ]
    lines += _counts("Outcomes", "Outcome", report.by_outcome)
    lines += _counts("Actions", "Action", report.by_action)
    lines += _counts("Principals", "Principal", report.by_principal)
    lines += _counts("Determining policies", "Policy", report.by_policy)
    lines += _counts("Obligations", "Obligation", report.by_obligation)
    lines += _mutations(report)
    lines += _refusals(report)
    lines += _tamper_evidence(report)
    return "\n".join(lines).rstrip("\n") + "\n"


def _default_title(window: AuditWindow) -> str:
    """Name the report after the period it covers, or say it covers everything."""
    if window.start is None or window.end is None:
        return "Audit report"
    return f"Audit report: {window.start.date().isoformat()} to {window.end.date().isoformat()}"


def _moment(value: datetime | None) -> str:
    """Render a timestamp for the report header, or ``unbounded`` when there is none."""
    return "unbounded" if value is None else value.isoformat()


def _describe_filters(window: AuditWindow) -> str:
    """List the identity filters in force, so a reader knows what the counts exclude."""
    named = {
        "principal": window.principal,
        "action": window.action,
        "resource": window.resource,
        "decision": window.decision,
        "kind": window.kind,
    }
    applied = [f"{key}={value}" for key, value in named.items() if value is not None]
    return ", ".join(applied) if applied else "none"


def _cell(value: object) -> str:
    """Render one table cell, escaping the pipe that would otherwise split the row."""
    return str(value).replace("|", "\\|")


def _counts(heading: str, column: str, counts: Mapping[str, int]) -> list[str]:
    """Render one aggregate as its own section, saying so when it is empty."""
    lines = [f"## {heading}", ""]
    if not counts:
        return [*lines, "None recorded in this window.", ""]
    lines += [f"| {column} | Count |", "| --- | ---: |"]
    lines += [f"| {_cell(key)} | {value} |" for key, value in counts.items()]
    lines.append("")
    return lines


def _mutations(report: AuditReport) -> list[str]:
    """Render admin mutations as their own section.

    Separate from the decisions, because a grant is not a permitted call, and a report that
    showed one as an "allow" would understate both.
    """
    lines = ["## Mutations", ""]
    counted = {
        outcome: count
        for outcome, count in report.by_outcome.items()
        if outcome in ("granted", "revoked")
    }
    if not counted:
        return [*lines, "No grants were made or withdrawn in this window.", ""]
    lines += ["| Mutation | Count |", "| --- | ---: |"]
    lines += [f"| {_cell(outcome)} | {count} |" for outcome, count in counted.items()]
    lines.append("")
    return lines


def _refusals(report: AuditReport) -> list[str]:
    """Render the refusals, newest first, saying so when the list was capped."""
    lines = ["## Refusals", ""]
    if not report.refusals:
        return [*lines, "No call was refused in this window.", ""]
    if report.denied > len(report.refusals):
        lines += [
            f"Showing the {len(report.refusals)} most recent of {report.denied} refusals.",
            "",
        ]
    lines += [
        "| Time | Principal | Action | Outcome | Reason |",
        "| --- | --- | --- | --- | --- |",
    ]
    lines += [
        "| "
        + " | ".join(
            (
                _cell(record.timestamp.isoformat()),
                _cell(record.principal.uid),
                _cell(record.action),
                _cell(record.outcome),
                _cell(record.reason or ""),
            )
        )
        + " |"
        for record in report.refusals
    ]
    lines.append("")
    return lines


def _tamper_evidence(report: AuditReport) -> list[str]:
    """Render what can be said about tampering, and be explicit about what cannot.

    The per-record check is always meaningful. The chain check is only meaningful over a
    contiguous run, so a filtered window says why it was skipped rather than reporting an
    intact chain it did not verify.
    """
    lines = [
        "## Tamper evidence",
        "",
        f"- Records whose own hash recomputes: {report.verified} of {report.total}.",
    ]
    verdict = report.chain
    if verdict is None:
        lines.append(
            "- Chain: not verified. This window filters by identity, so its records are a "
            "non-contiguous slice of the log rather than a run of it."
        )
    elif verdict.ok:
        lines.append("- Chain: intact across the window.")
    else:
        lines.append(f"- Chain: BROKEN at record {verdict.broken_at}. {verdict.reason}.")
    lines.append("")
    return lines


# --- the self-governed admin surface ---------------------------------------------------------


@protect(action=GRANT_ACTION, resource=ADMIN_RESOURCE)
def _propose_grant(
    *,
    principal: str,
    kind: str,
    subject: str,
    value: str | None = None,
    action: str = WILDCARD_ACTION,
    expires_at: datetime | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    """Ask the policy whether this grant may be made, and in what shape.

    The body is deliberately a mirror: everything it returns came *back* through the
    pipeline, so the caller builds its :class:`~sentrykit.stores.base.GrantSpec` from what
    policy processed rather than from ``argv``. That is what makes the admin surface
    argument-*filtered* and not merely gated — an operator entitled to grant ``oncall`` and
    nothing else has their proposal narrowed here, by the same constraint machinery that
    narrows any other protected call.

    Args:
        principal: Who is to receive the grant, as a Cedar uid or a bare id.
        kind: ``role``, ``parent`` or ``attribute``.
        subject: The role name, parent uid or attribute name.
        value: The attribute value, for ``kind="attribute"``.
        action: Which action the grant applies to; ``*`` for every action.
        expires_at: When the grant stops applying.
        reason: The justification recorded on the grant and in the audit trail.

    Returns:
        The same fields, as policy processed them.
    """
    return {
        "principal": principal,
        "kind": kind,
        "subject": subject,
        "value": value,
        "action": action,
        "expires_at": expires_at,
        "reason": reason,
    }


@protect(action=REVOKE_ACTION, resource=ADMIN_RESOURCE)
def _propose_revoke(*, grant_id: str, reason: str | None = None) -> dict[str, object]:
    """Ask the policy whether this grant may be withdrawn.

    Args:
        grant_id: The grant to withdraw.
        reason: Why.

    Returns:
        The same fields, as policy processed them.
    """
    return {"grant_id": grant_id, "reason": reason}


def _processed(proposal: Mapping[str, object]) -> dict[str, object]:
    """Strip the ``_authz`` envelope the decorator attached to a mapping result.

    The envelope is a report *about* the call; treating it as one of the call's fields would
    put it into the grant spec.
    """
    return {name: value for name, value in proposal.items() if name != ENVELOPE_KEY}


# --- shared wiring -----------------------------------------------------------------------


def _resolve_sink_dsn(requested: str | None) -> str | None:
    """Decide which audit sink to use: the flag, else ``SENTRYKIT_AUDIT_SINK``."""
    return requested or get_settings().audit_sink


def _resolve_actor(store: GrantStore, requested: str | None) -> Principal:
    """Resolve the operator this command acts as, refusing when there is none.

    Fails closed twice over, because both halves are ways to end up acting as nobody: an
    unnamed actor, and a named actor the grant store has never heard of. Neither is allowed
    to fall back on a synthesized principal — an admin surface that invents its own caller
    has no admin surface at all.

    Args:
        store: The grant store the actor is materialized from.
        requested: Whatever ``--as`` carried, or ``None``.

    Returns:
        The materialized principal.

    Raises:
        ConfigurationError: If no actor was named, or the store holds nothing for them.
    """
    named = requested or os.environ.get(ACTOR_ENV) or ""
    if not named.strip():
        raise ConfigurationError(
            f"no actor was named; pass --as 'User::\"you\"' or set {ACTOR_ENV}. "
            "Refusing to administer grants as nobody."
        )
    actor = store.get_principal(named)
    if actor is None:
        raise ConfigurationError(
            f"grant store {store.name!r} holds no principal {named!r}; refusing (fail-closed)"
        )
    return actor


def _report_refusal(exc: SentrykitError) -> int:
    """Print a refusal the way an operator needs to read it, and fail the command.

    The envelope carries the decision and the one-sentence reason; the exception carries the
    typed detail. Printing both means a denial and an argument rejection do not read alike.

    Args:
        exc: The refusal raised by the protected callable.

    Returns:
        :data:`EXIT_FAILED`, so the caller can ``return`` this directly.
    """
    envelope = last_envelope()
    print(f"sentrykit: refused: {exc}", file=sys.stderr)
    if envelope is not None:
        print(f"  decision: {envelope.decision}", file=sys.stderr)
        if envelope.reason:
            print(f"  reason: {envelope.reason}", file=sys.stderr)
        if envelope.determining_policies:
            print(
                f"  determining policies: {', '.join(envelope.determining_policies)}",
                file=sys.stderr,
            )
        else:
            # No determining policy means nothing permitted it, which is a default deny —
            # and the overwhelmingly likely cause is that no policy for the admin actions
            # has been written yet. The shipped pack deliberately contains none: a permit
            # for the action that hands out authority is not something a library gets to
            # ship on your behalf. Saying so here saves an operator staring at an empty
            # list wondering which rule refused them.
            print(
                # ASCII only: this goes to a terminal, and a cp1252 console renders an
                # em-dash as a replacement character. Every other line the CLI prints is
                # already ASCII, and a test keeps it that way.
                "  no policy permitted this action. The shipped pack does not include one "
                "for the admin actions, by design. Write a permit for "
                f"{GRANT_ACTION} / {REVOKE_ACTION} on {ADMIN_RESOURCE} and point --policy "
                "at it. See docs/policies.md, 'Administering grants'.",
                file=sys.stderr,
            )
    print("The grant store was not touched.", file=sys.stderr)
    return EXIT_FAILED


def _close(backend: object) -> None:
    """Release a backend that holds a resource, and leave the rest alone."""
    if isinstance(backend, SupportsClose):
        backend.close()


def _emit(payload: Mapping[str, object], *, as_json: bool, lines: Sequence[str]) -> None:
    """Print either the JSON document or the human lines, never both."""
    if as_json:
        print(json.dumps(dict(payload), indent=2, sort_keys=True, default=str))
        return
    for line in lines:
        print(line)


def _parse_instant(value: str, flag: str) -> tuple[datetime, bool]:
    """Read a bare date or a full ISO-8601 timestamp, as UTC.

    Args:
        value: What the operator typed.
        flag: The flag it came from, for the error message.

    Returns:
        The instant, and whether it was written as a bare date — which is what decides
        whether an exclusive upper bound has to be nudged to the following day.

    Raises:
        ConfigurationError: If the value is neither.
    """
    text = value.strip()
    bare = bool(_DATE_ONLY.match(text))
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ConfigurationError(
            f"{flag} is {value!r}; expected a date (2026-09-01) or an ISO-8601 timestamp"
        ) from exc
    # Naive means UTC, for the reason ``coerce_value`` gives: which records a report covers
    # must not depend on the timezone of the host that happened to run it.
    return (parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)), bare


# --- policy validate ---------------------------------------------------------------------


def _validate_policies(args: argparse.Namespace) -> int:
    """Validate and lint a policy directory.

    Args:
        args: The parsed ``policy validate`` arguments.

    Returns:
        :data:`EXIT_FAILED` when validation failed, :data:`EXIT_OK` otherwise. Formatting
        warnings never fail the command: reviewed policy text that is merely untidy still
        decides correctly, and a gate that failed on it would be turned off.

    Raises:
        ConfigurationError: If the directory does not exist or matches no policy files.
    """
    requested: str | None = args.directory
    pattern: str = args.pattern
    requested_schema: str | None = args.schema
    format_check: bool = args.format_check
    as_json: bool = args.json
    directory = Path(requested) if requested else pack_root()
    if not directory.is_dir():
        raise ConfigurationError(f"{str(directory)!r} is not a directory")

    files = sorted(path for path in directory.glob(pattern) if path.is_file())
    if not files:
        raise ConfigurationError(f"no file in {str(directory)!r} matches {pattern!r}")

    schema_path = _schema_for(directory, requested_schema)
    combined = "\n\n".join(path.read_text(encoding="utf-8") for path in files)

    # Always probed, even with --no-format-check: this is the only thing that can attribute
    # a parse failure to a *file*, since validation sees one concatenated policy set.
    unparseable, unformatted = _lint(files)

    file_errors: list[str] = []
    policy_errors: dict[str, list[str]] = {}
    validated = schema_path is not None
    passed = False
    if schema_path is not None:
        outcome = validate_policies(combined, schema_path.read_text(encoding="utf-8"))
        passed = outcome.passed
        for policy_id, messages in sorted(outcome.grouped().items()):
            if policy_id == PARSE_SENTINEL:
                file_errors.extend(messages)
            else:
                policy_errors[policy_id] = messages

    lines = [
        f"policy validate: {directory}",
        f"  policies: {len(files)} file(s) matching {pattern!r}",
        f"  schema:   {schema_path.name if schema_path is not None else 'none found'}",
    ]
    lines += [f"  error: the policy set does not parse: {message}" for message in file_errors]
    lines += [f"  error: {name} does not parse" for name in unparseable]
    lines += [
        f"  error: policy {policy_id!r}: {message}"
        for policy_id, messages in sorted(policy_errors.items())
        for message in messages
    ]
    if format_check:
        lines += [
            f"  warning: {name} is not formatted as cedar would write it (not rewritten)"
            for name in unformatted
        ]

    if not validated:
        lines.append(
            f"  validation: skipped - no {SCHEMA_GLOB} in the directory and no --schema; "
            "nothing was type-checked"
        )
        exit_code = EXIT_OK
    elif passed:
        lines.append("  validation: passed")
        exit_code = EXIT_OK
    else:
        counted = sum(len(messages) for messages in policy_errors.values())
        parts: list[str] = []
        if policy_errors:
            parts.append(f"{counted} error(s) in {len(policy_errors)} policy/policies")
        if file_errors:
            parts.append(f"{len(file_errors)} file-level error(s)")
        lines.append(f"  validation: failed - {' and '.join(parts)}")
        exit_code = EXIT_FAILED

    _emit(
        {
            "directory": str(directory),
            "pattern": pattern,
            "files": [path.name for path in files],
            "schema": schema_path.name if schema_path is not None else None,
            "validated": validated,
            "passed": passed if validated else None,
            "file_errors": file_errors,
            "unparseable": list(unparseable),
            "policy_errors": policy_errors,
            "unformatted": list(unformatted) if format_check else [],
            "exit_code": exit_code,
        },
        as_json=as_json,
        lines=lines,
    )
    return exit_code


def _schema_for(directory: Path, requested: str | None) -> Path | None:
    """Find the schema a directory is validated against.

    Args:
        directory: The policy directory.
        requested: An explicit ``--schema`` path, or ``None``.

    Returns:
        The schema file, or ``None`` when the directory ships none — which is a finding the
        caller reports, not a pass.

    Raises:
        ConfigurationError: If an explicitly named schema is missing.
    """
    if requested:
        path = Path(requested)
        if not path.is_file():
            raise ConfigurationError(f"--schema {requested!r} is not a file")
        return path
    found = sorted(path for path in directory.glob(SCHEMA_GLOB) if path.is_file())
    return found[0] if found else None


def _lint(files: Sequence[Path]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Compare each file against Cedar's own formatting.

    Args:
        files: The policy files, in the order they were concatenated.

    Returns:
        The names of the files that do not parse, and of the ones that parse but are not
        formatted the way Cedar would write them. Never rewrites anything: a validation
        command that edited reviewed policy text would be editing the thing under review.
    """
    unparseable: list[str] = []
    unformatted: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        try:
            formatted = format_policies(text)
        except ConfigurationError:
            unparseable.append(path.name)
            continue
        if formatted.strip() != text.strip():
            unformatted.append(path.name)
    return tuple(unparseable), tuple(unformatted)


# --- grant / revoke ----------------------------------------------------------------------


def _install_from(args: argparse.Namespace) -> tuple[Governor, GrantStore]:
    """Wire the governor the admin commands are decided by, and hand back its store.

    Wired with :func:`~sentrykit.engine.install` rather than by hand, so the admin surface
    runs against exactly the substrate the application does — same policy union, same store,
    same sink — and a policy that works in the service works here.

    Args:
        args: The parsed ``grant``/``revoke`` arguments.

    Returns:
        The installed governor and the grant store the mutation will be applied to.

    Raises:
        ConfigurationError: If a DSN names an unknown backend or the store cannot be built.
    """
    store_dsn: str = args.store
    policy_dsn: str = args.policy
    sink_dsn = _resolve_sink_dsn(args.sink)
    governor = install(policy_source=policy_dsn, grant_store=store_dsn, audit_sink=sink_dsn)
    store = governor.grants
    if store is None:  # pragma: no cover - build_grant_store raises before this can happen
        raise ConfigurationError(f"--store {store_dsn!r} built no grant store")
    if sink_dsn is None:
        # Not fatal -- a developer against ``memory://`` has no sink and needs the command to
        # work -- but never silent: an unrecorded mutation is the one an auditor cannot find.
        print(
            f"sentrykit: warning: no audit sink is configured (--sink or "
            f"{ENV_PREFIX}AUDIT_SINK); this mutation will not be recorded.",
            file=sys.stderr,
        )
    return governor, store


def _run_grant(args: argparse.Namespace) -> int:
    """Confer a grant, governed by the same engine the application is.

    Returns:
        :data:`EXIT_OK` when the grant was made, :data:`EXIT_FAILED` when policy refused it.
    """
    principal: str = args.principal
    action: str = args.action or WILDCARD_ACTION
    expires: str | None = args.expires
    reason: str | None = args.reason
    actor_uid: str | None = args.actor
    as_json: bool = args.json

    kind, subject, value = _grant_target(args)
    expires_at = _parse_instant(expires, "--expires")[0] if expires else None
    governor, store = _install_from(args)
    actor = _resolve_actor(store, actor_uid)

    with establish(actor, channel=CHANNEL):
        try:
            proposal = _propose_grant(
                principal=principal,
                kind=kind,
                subject=subject,
                value=value,
                action=action,
                expires_at=expires_at,
                reason=reason,
            )
        except SentrykitError as exc:
            return _report_refusal(exc)

    # Built from what came *back*, never from argv: an argument the policy narrowed or filled
    # in has to be the one that lands in the store, or the filtering was theatre.
    processed = _processed(proposal)
    spec = GrantSpec(
        principal=EntityRef.parse(str(processed["principal"]), default_type="User"),
        kind=cast("GrantKind", processed["kind"]),
        subject=str(processed["subject"]),
        value=processed["value"],
        action=str(processed["action"]),
        granted_by=str(actor.uid),
        expires_at=cast("datetime | None", processed["expires_at"]),
        reason=cast("str | None", processed["reason"]),
    )
    record = store.grant(spec)
    _record_mutation(governor, record, actor=actor, outcome="granted", reason=spec.reason)

    rendered = record.as_record()
    _emit(
        {"outcome": "granted", "grant": rendered},
        as_json=as_json,
        lines=[
            f"Granted {spec.kind} {spec.subject!r} to {spec.principal}.",
            f"  grant id: {record.id}",
            f"  expires:  {rendered['expires_at'] or 'never'}",
            f"  reason:   {rendered['reason'] or 'none given'}",
        ],
    )
    return EXIT_OK


def _grant_target(args: argparse.Namespace) -> tuple[str, str, str | None]:
    """Read the mutually exclusive ``--role``/``--parent``/``--attribute`` triple.

    Args:
        args: The parsed ``grant`` arguments.

    Returns:
        The grant kind, its subject, and the attribute value where there is one.

    Raises:
        ConfigurationError: If ``--attribute`` is not spelled ``key=value``.
    """
    role: str | None = args.role
    parent: str | None = args.parent
    attribute: str | None = args.attribute
    if role:
        return "role", role, None
    if parent:
        return "parent", parent, None
    name, separator, value = (attribute or "").partition("=")
    if not separator or not name.strip():
        raise ConfigurationError(f"--attribute {attribute!r} is not spelled key=value")
    return "attribute", name.strip(), value


def _run_revoke(args: argparse.Namespace) -> int:
    """Withdraw a grant, governed and logged exactly as conferring one is.

    Returns:
        :data:`EXIT_OK` when the grant was withdrawn, :data:`EXIT_FAILED` when policy refused.
    """
    requested_id: str = args.grant_id
    requested_reason: str | None = args.reason
    actor_uid: str | None = args.actor
    as_json: bool = args.json

    governor, store = _install_from(args)
    actor = _resolve_actor(store, actor_uid)

    with establish(actor, channel=CHANNEL):
        try:
            proposal = _propose_revoke(grant_id=requested_id, reason=requested_reason)
        except SentrykitError as exc:
            return _report_refusal(exc)

    processed = _processed(proposal)
    grant_id = str(processed["grant_id"])
    reason = cast("str | None", processed["reason"])
    record = store.revoke(grant_id, revoked_by=str(actor.uid), reason=reason)
    _record_mutation(governor, record, actor=actor, outcome="revoked", reason=reason)

    rendered = record.as_record()
    _emit(
        {"outcome": "revoked", "grant": rendered},
        as_json=as_json,
        lines=[
            f"Revoked {record.spec.kind} {record.spec.subject!r} from {record.spec.principal}.",
            f"  grant id: {record.id}",
            f"  revoked:  {rendered['revoked_at']}",
            f"  reason:   {rendered['revoked_reason'] or 'none given'}",
        ],
    )
    return EXIT_OK


def _record_mutation(
    governor: Governor,
    record: GrantRecord,
    *,
    actor: Principal,
    outcome: Literal["granted", "revoked"],
    reason: str | None,
) -> None:
    """Write the mutation half of the trail — the second of the two records.

    The decision that permitted the mutation was recorded by the governor when
    :func:`_propose_grant` ran; this records that the change actually happened. Both, or the
    log answers "was it allowed" without answering "did it occur".

    Args:
        governor: The governor whose trail the record goes to.
        record: The stored grant.
        actor: Who made the change.
        outcome: ``granted`` or ``revoked``.
        reason: The justification.
    """
    trail = governor.audit
    if trail is None:  # pragma: no cover - install always wires a trail
        return
    trail.record_mutation(record.as_record(), actor=actor, outcome=outcome, reason=reason)


# --- grants ------------------------------------------------------------------------------


def _run_grants(args: argparse.Namespace) -> int:
    """List a principal's grants.

    Read-only, and therefore *not* governed: there is nothing to authorize when nothing
    changes. It exists because :func:`_run_revoke` takes an id, and an operator who has lost
    one would otherwise have to grep the audit log for it.

    Returns:
        :data:`EXIT_OK`.

    Raises:
        ConfigurationError: If the store DSN names an unknown backend.
    """
    store_dsn: str = args.store
    principal: str = args.principal
    include_inactive: bool = args.include_inactive
    as_json: bool = args.json
    store = build_grant_store(store_dsn)
    if store is None:  # pragma: no cover - build_grant_store raises before this can happen
        raise ConfigurationError(f"--store {store_dsn!r} built no grant store")
    try:
        held = store.grants_for(principal, include_inactive=include_inactive)
        # Everything printed comes off ``as_record``, the same rendering the audit trail
        # writes, so this listing cannot expose anything a grant record does not already.
        rendered = [record.as_record() for record in held]
    finally:
        _close(store)

    lines = [f"{principal} holds {len(rendered)} grant(s)."]
    lines += [
        "  " + "  ".join(f"{column}={entry.get(column) or '-'}" for column in _GRANT_COLUMNS)
        for entry in rendered
    ]
    _emit({"principal": principal, "grants": rendered}, as_json=as_json, lines=lines)
    return EXIT_OK


# --- audit-report ------------------------------------------------------------------------


def _run_audit_report(args: argparse.Namespace) -> int:
    """Aggregate a window of the audit log into a markdown document.

    Returns:
        :data:`EXIT_OK`.

    Raises:
        ConfigurationError: If no sink is configured, or a bound will not parse.
    """
    principal: str | None = args.principal
    action: str | None = args.action
    top: int = args.top
    title: str | None = args.title
    out: str | None = args.out

    start, _ = _parse_instant(args.start, "--from")
    end, bare = _parse_instant(args.end, "--to")
    if bare:
        # ``AuditWindow`` bounds are half-open, and an operator writing ``--to 2026-12-31``
        # means "including that day". A timestamp is used exactly, because someone who wrote
        # one meant it.
        end += timedelta(days=1)

    window = AuditWindow(start=start, end=end, principal=principal, action=action)
    sink_dsn = _resolve_sink_dsn(args.sink)
    if sink_dsn is None:
        raise ConfigurationError(
            f"no audit sink is configured; pass --sink or set {ENV_PREFIX}AUDIT_SINK"
        )
    sink = build_audit_sink(sink_dsn)
    if sink is None:  # pragma: no cover - build_audit_sink raises before this can happen
        raise ConfigurationError(f"--sink {sink_dsn!r} built no audit sink")
    try:
        report = build_report(
            sink.query(window),
            window=window,
            sink=sink.name,
            generated_at=datetime.now(UTC),
            top=top,
        )
    finally:
        _close(sink)

    # The heading echoes what the operator typed, not the half-open bound the window
    # carries: someone who asked for "--to 2026-12-31" should not read a title saying
    # 2027-01-01 and wonder whether they got a day too many. The header line below the
    # title still states the exact bounds, marked exclusive.
    document = _document(report, title or f"Audit report: {args.start} to {args.end}")
    if out is None:
        print(document, end="")
        return EXIT_OK
    destination = Path(out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(document, encoding="utf-8")
    print(f"Wrote {report.total} record(s) to {destination}.")
    return EXIT_OK


# --- parser ------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for every command.

    Separated from :func:`main` so a test can assert the surface — flags, defaults, help —
    without running anything.

    Returns:
        The parser. Sub-commands are dispatched through the ``command`` destination.
    """
    parser = argparse.ArgumentParser(
        prog="sentrykit",
        description="Validate policies, administer grants, and report on the audit log.",
    )
    parser.add_argument("--version", action="version", version=f"sentrykit {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="<command>", required=True)

    policy = commands.add_parser("policy", help="Inspect a policy directory.")
    policy_commands = policy.add_subparsers(
        dest="policy_command", metavar="<subcommand>", required=True
    )
    validate = policy_commands.add_parser(
        "validate",
        help="Type-check and lint a policy directory.",
        description=(
            "Type-checks the directory's policies against its Cedar schema and reports "
            "files that differ from cedar's own formatting. Formatting is a warning, never a "
            "failure, and no file is ever rewritten. With no directory, validates the "
            "shipped policy pack."
        ),
    )
    validate.add_argument(
        "directory", nargs="?", default=None, help="Policy directory (default: the shipped pack)."
    )
    validate.add_argument(
        "--schema", default=None, help=f"Schema file (default: the {SCHEMA_GLOB})."
    )
    validate.add_argument(
        "--pattern",
        default=DEFAULT_POLICY_GLOB,
        help="Glob for policy files (default: %(default)s).",
    )
    validate.add_argument(
        "--no-format-check",
        dest="format_check",
        action="store_false",
        help="Skip the formatting comparison.",
    )
    validate.add_argument("--json", action="store_true", help="Emit the findings as JSON.")

    grant = commands.add_parser(
        "grant",
        help="Confer a grant. Governed by the policy set and written to the audit log.",
        description=(
            "Confers a grant. The mutation is itself authorized against "
            f"{GRANT_ACTION} on {ADMIN_RESOURCE}, so a policy decides both who may "
            "administer grants and which grants they may make; the proposed role, subject "
            "and expiry are ordinary arguments and are filtered like any others."
        ),
    )
    grant.add_argument("principal", help="Who receives the grant, e.g. 'User::\"ana\"'.")
    target = grant.add_mutually_exclusive_group(required=True)
    target.add_argument("--role", default=None, help="Grant a role.")
    target.add_argument("--parent", default=None, help="Grant a parent edge, e.g. 'Team::\"eu\"'.")
    target.add_argument("--attribute", default=None, metavar="K=V", help="Grant an attribute.")
    grant.add_argument(
        "--action",
        default=WILDCARD_ACTION,
        help="Action the grant applies to (default: %(default)s, meaning every action).",
    )
    grant.add_argument(
        "--expires",
        default=None,
        help="When the grant stops applying: a date (2026-09-01, read as 00:00 UTC) or an "
        "ISO-8601 timestamp. A naive value is read as UTC.",
    )
    grant.add_argument("--reason", default=None, help="Why the grant is being made.")
    _add_admin_arguments(grant)

    revoke = commands.add_parser(
        "revoke",
        help="Withdraw a grant. Governed and logged exactly as conferring one is.",
        description=(
            f"Withdraws a grant. Authorized against {REVOKE_ACTION} on {ADMIN_RESOURCE} and "
            "recorded as a mutation in the audit log. Revocation marks the grant rather than "
            "deleting it, so 'who had what, when' survives."
        ),
    )
    revoke.add_argument("grant_id", metavar="GRANT_ID", help="The id `sentrykit grants` lists.")
    revoke.add_argument("--reason", default=None, help="Why the grant is being withdrawn.")
    _add_admin_arguments(revoke)

    grants = commands.add_parser(
        "grants",
        help="List a principal's grants.",
        description=(
            "Lists the grants a principal holds. Read-only, so it is not governed - it "
            "exists because `revoke` takes an id, and every column comes off the grant "
            "record's own audit rendering."
        ),
    )
    grants.add_argument("principal", help="Whose grants to list, e.g. 'User::\"ana\"'.")
    grants.add_argument("--store", required=True, metavar="DSN", help="Grant store DSN.")
    grants.add_argument(
        "--include-inactive", action="store_true", help="Include revoked and expired grants."
    )
    grants.add_argument("--json", action="store_true", help="Emit the listing as JSON.")

    report = commands.add_parser(
        "audit-report",
        help="Aggregate a window of the audit log into markdown.",
        description=(
            "Queries the audit sink for a period and aggregates it by outcome, action, "
            "principal, determining policy and obligation. --to is INCLUSIVE of the day it "
            "names: the window's upper bound is exclusive, so a bare date has one day added "
            "to it. A value carrying a time is used exactly."
        ),
    )
    report.add_argument(
        "--from",
        dest="start",
        required=True,
        metavar="DATE",
        help="Start of the window, inclusive: a date or an ISO-8601 timestamp.",
    )
    report.add_argument(
        "--to",
        dest="end",
        required=True,
        metavar="DATE",
        help="End of the window. A bare date INCLUDES that whole day; a timestamp is exact.",
    )
    report.add_argument("--out", default=None, metavar="PATH", help="Write here (default: stdout).")
    report.add_argument(
        "--sink",
        default=None,
        metavar="DSN",
        help="Audit sink DSN (default: SENTRYKIT_AUDIT_SINK).",
    )
    report.add_argument("--principal", default=None, help="Only this principal's records.")
    report.add_argument("--action", default=None, help="Only this action's records.")
    report.add_argument(
        "--top", type=int, default=20, help="How many refusals to list (default: %(default)s)."
    )
    report.add_argument("--title", default=None, help="Document title.")
    return parser


def _add_admin_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the wiring flags both admin commands share.

    Shared rather than repeated because the two commands are the same operation over
    different verbs, and a ``--store`` that meant something subtly different on one of them
    would be a trap.
    """
    parser.add_argument(
        "--as",
        dest="actor",
        default=None,
        metavar="ACTOR",
        help=f"Who is acting (default: ${ACTOR_ENV}). Refused when neither is set.",
    )
    parser.add_argument("--store", required=True, metavar="DSN", help="Grant store DSN.")
    # Required, with no default. The obvious default is the shipped pack, and the shipped
    # pack deliberately contains no permit for the admin actions -- so defaulting to it makes
    # every mutation refuse, and the operator reads a refusal about their entitlement when
    # the truth is that they never named a policy source. A usage error says what is actually
    # missing, at the only moment it is cheap to fix.
    parser.add_argument(
        "--policy",
        required=True,
        metavar="DSN",
        help=(
            "Policy source deciding the mutation, e.g. file://./policies. The shipped "
            f"pack:// contains no permit for {GRANT_ACTION} / {REVOKE_ACTION}; write one "
            "and name it here."
        ),
    )
    parser.add_argument(
        "--sink",
        default=None,
        metavar="DSN",
        help="Audit sink DSN (default: SENTRYKIT_AUDIT_SINK).",
    )
    parser.add_argument("--json", action="store_true", help="Emit the result as JSON.")


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
    args = build_parser().parse_args(argv)
    command: str = args.command
    try:
        if command == "policy":
            subcommand: str = args.policy_command
            if subcommand == "validate":
                return _validate_policies(args)
        if command == "grant":
            return _run_grant(args)
        if command == "revoke":
            return _run_revoke(args)
        if command == "grants":
            return _run_grants(args)
        if command == "audit-report":
            return _run_audit_report(args)
    except SentrykitError as exc:
        # Every failure an operator can cause -- a mistyped DSN, an unknown grant id, a sink
        # that will not open -- arrives here as a typed error and leaves as one line on
        # stderr. A traceback would suggest they had found a bug.
        print(f"sentrykit: {exc}", file=sys.stderr)
        return EXIT_FAILED
    # Unreachable: argparse rejects an unknown command before dispatch.
    raise ConfigurationError(f"unknown command {command!r}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
