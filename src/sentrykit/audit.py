"""The audit record, the hash chain, and the one path from a decision to a sink.

ADR-006 asks for a log that survives scrutiny, which means four properties this module owns:

* **Reproducible.** The record pins ``policy_set_hash`` and snapshots the principal's
  *effective* attributes at decision time, so a replay is possible even after the policy set
  and the grants have both moved on.
* **Attributable.** Per-policy provenance names which source and which artifact produced each
  determining policy — not just its id.
* **Tamper-evident.** Each record carries the previous record's hash, so altering any record
  invalidates every record after it. Detection, not prevention; prevention is the sink's job
  (S3 Object Lock, WORM).
* **Safe to keep forever.** Sensitive values are masked *before* the write (ADR-007), never
  after.

That last property is structural rather than conventional: :class:`AuditTrail` is the only
thing in sentrykit that calls :meth:`~sentrykit.stores.base.AuditSink.write`, and it masks on
the way in. A unit test asserts that statically — the audit-side analogue of the phase 1
import scan — so a future caller that reaches around it fails the suite rather than the
compliance review.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final, Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from sentrykit.cedar import CedarDecision
from sentrykit.constraints import RejectedArgument
from sentrykit.context import Invocation, Principal
from sentrykit.masking import Masker, MaskStrategyName
from sentrykit.stores.base import AuditSink, AuditWindow, PolicyBundle

__all__ = [
    "GENESIS_HASH",
    "AuditKind",
    "AuditOutcome",
    "AuditTrail",
    "AuthzAuditRecord",
    "ChainVerdict",
    "DecisionFacts",
    "PrincipalSnapshot",
    "canonical_json",
    "verify_chain",
]

GENESIS_HASH: Final = "0" * 64
"""The ``prev_hash`` of the first record in a chain. Fixed width, so a chain is scannable."""

AuditKind = Literal["decision", "mutation"]
"""Whether a record describes an authorization decision or an admin grant mutation."""

AuditOutcome = Literal[
    "allowed",
    "denied",
    "engine-error",
    "arguments-rejected",
    "no-valid-arguments",
    "default-unavailable",
    "validation-failed",
    "granted",
    "revoked",
]
"""What actually happened.

Finer-grained than ``decision`` on purpose. "Cedar permitted the call but every argument the
caller proposed was refused" and "no policy permitted the call" are both denials to the
caller and completely different events to an auditor.
"""


def canonical_json(payload: Mapping[str, object]) -> bytes:
    """Render a payload to the exact bytes the chain hashes.

    Determinism is the whole requirement: sorted keys, no insignificant whitespace, UTF-8,
    and no dependence on dict insertion order or platform. Anything unrenderable falls back
    to its ``repr`` rather than raising — an audit record must not be able to fail the
    decision it describes.

    Args:
        payload: The record payload, already JSON-normalized.

    Returns:
        The canonical encoding.
    """
    raise NotImplementedError


class PrincipalSnapshot(BaseModel):
    """The acting principal exactly as the decision saw them.

    A snapshot, not a reference. Grants change, roles are revoked, attributes are corrected —
    and a record that merely *pointed* at a principal would silently start describing a
    different one. This is what makes ADR-006's reproducibility claim hold.

    Attributes:
        uid: The principal's Cedar uid.
        type: Entity type.
        id: Entity id.
        roles: Role names, expanded to ``Role::"..."`` edges at decision time.
        parents: Every other parent edge, as uids — the teams, projects and delegation edges
            a multi-hop relationship was resolved through.
        attributes: Effective Cedar attributes, masked.
        constraints: The argument constraints in force, by action, as
            :meth:`~sentrykit.constraints.ConstraintSet.describe` renders them. Values are
            described rather than dumped, so a constraint's allow-set does not smuggle raw
            data into the record.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    uid: str
    type: str
    id: str
    roles: tuple[str, ...] = ()
    parents: tuple[str, ...] = ()
    attributes: dict[str, object] = Field(default_factory=dict)
    constraints: dict[str, object] = Field(default_factory=dict)

    @classmethod
    def of(cls, principal: Principal) -> PrincipalSnapshot:
        """Snapshot a principal. Does **not** mask — :class:`AuditTrail` does that."""
        raise NotImplementedError


class AuthzAuditRecord(BaseModel):
    """One decision, or one admin mutation, as it is written to a sink.

    Every field is either something an auditor asks for or something a replay needs. The
    record is frozen: chaining produces a new record rather than mutating this one, so a
    record that has been written can never be edited in place by construction.

    Attributes:
        record_id: Unique id for this record.
        sequence: Position in the chain, starting at 0.
        timestamp: When the decision was made.
        invocation_id: Correlation id, shared with the Cedar result, the ``_authz`` envelope
            and the operational logs.
        kind: ``decision`` or ``mutation``.
        principal: The effective-principal snapshot.
        action: The action uid.
        resource: The resource uid.
        callable_name: Qualified name of the protected callable.
        channel: ``http``, ``agent`` or ``internal``.
        environment: The Cedar request context, masked. The proposed arguments are stripped
            from it — they are carried in :attr:`proposed`, and duplicating them would mean
            masking the same values twice, in two shapes, with two chances to miss one.
        decision: ``allow`` or ``deny``, as the caller experienced it.
        outcome: The finer-grained reason, see :data:`AuditOutcome`.
        reason: One sentence, for a human reading the log.
        proposed: What the caller asked for, masked. Untrusted input, recorded as evidence.
        processed: What the callable actually ran with, masked.
        rejected: Arguments the policy refused, with reasons and masked values.
        defaults_applied: Arguments filled in from the principal's grants, masked.
        obligations: Obligations the determining policies attached (ADR-012).
        determining_policies: The policies that decided it.
        provenance: Where each determining policy came from.
        policy_set_hash: Digest of the policy logic evaluated, so the decision replays.
        engine_errors: Cedar errors, when the engine failed rather than decided.
        masked: Which fields were masked and with which strategy. Without this an auditor
            cannot tell an ``hmac:...`` string from a value that genuinely looked like one.
        grant: The grant record, for ``kind="mutation"``.
        prev_hash: The previous record's :attr:`record_hash`, or :data:`GENESIS_HASH`.
        record_hash: This record's digest, over everything above.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    record_id: str
    sequence: int = 0
    timestamp: datetime
    invocation_id: str
    kind: AuditKind = "decision"

    principal: PrincipalSnapshot
    action: str = ""
    resource: str = ""
    callable_name: str = ""
    channel: str = "internal"
    environment: dict[str, object] = Field(default_factory=dict)

    decision: Literal["allow", "deny"]
    outcome: AuditOutcome
    reason: str | None = None

    proposed: dict[str, object] = Field(default_factory=dict)
    processed: dict[str, object] = Field(default_factory=dict)
    rejected: tuple[RejectedArgument, ...] = ()
    defaults_applied: dict[str, object] = Field(default_factory=dict)

    obligations: tuple[str, ...] = ()
    determining_policies: tuple[str, ...] = ()
    provenance: tuple[dict[str, object], ...] = ()
    policy_set_hash: str = ""
    engine_errors: tuple[str, ...] = ()

    masked: dict[str, MaskStrategyName] = Field(default_factory=dict)
    grant: dict[str, object] | None = None

    prev_hash: str = GENESIS_HASH
    record_hash: str = ""

    def payload(self) -> dict[str, object]:
        """Render everything the hash covers — that is, every field but :attr:`record_hash`.

        :attr:`prev_hash` **is** covered, which is what binds the chain: re-pointing a record
        at a different predecessor changes its own hash too.
        """
        raise NotImplementedError

    def compute_hash(self) -> str:
        """Compute this record's digest from :meth:`payload`."""
        raise NotImplementedError

    def chained(self, *, prev_hash: str, sequence: int) -> AuthzAuditRecord:
        """Return a copy positioned in a chain, with :attr:`record_hash` computed.

        Args:
            prev_hash: The predecessor's hash, or :data:`GENESIS_HASH` for the first record.
            sequence: Position in the chain.

        Returns:
            The chained record, ready to write.
        """
        raise NotImplementedError

    def verify(self) -> bool:
        """Whether :attr:`record_hash` still matches this record's content."""
        raise NotImplementedError


class ChainVerdict(NamedTuple):
    """The result of verifying a chain.

    Attributes:
        ok: Whether the chain is intact.
        broken_at: Sequence number of the first bad record, or ``None``.
        reason: What was wrong — a rewritten record, a broken link, a gap in the sequence.
    """

    ok: bool
    broken_at: int | None = None
    reason: str | None = None


def verify_chain(records: Iterable[AuthzAuditRecord]) -> ChainVerdict:
    """Verify a run of records: each hash matches its content, and each link matches.

    Checks both, because they catch different attacks. Re-hashing catches an edited record;
    link checking catches a *deleted* one, which would otherwise leave every remaining record
    individually valid.

    Args:
        records: The records, in write order.

    Returns:
        The verdict, naming the first record that fails.
    """
    raise NotImplementedError


@dataclass(frozen=True, slots=True)
class DecisionFacts:
    """Everything the engine knows about one decision, handed to the trail.

    A value object rather than the ``Plan`` itself, so :mod:`sentrykit.audit` does not import
    :mod:`sentrykit.engine` — the dependency runs one way, and the trail stays testable
    without a governor.

    Attributes:
        invocation: The normalized invocation, including the raw proposed arguments.
        decision: What Cedar returned.
        outcome: What happened, finer-grained than allow/deny.
        allowed: Whether the call proceeded.
        reason: One-sentence explanation, matching the envelope's.
        processed: The final argument set, when the call proceeded.
        rejected: Arguments the policy refused.
        defaults_applied: Arguments filled from the principal's grants.
        obligations: Obligations from the determining policies.
        declared_sensitive: :func:`~sentrykit.masking.sensitive_fields` for the protected
            callable, so a signature-level ``Sensitive`` marker is honored.
        engine_errors: Cedar errors, when the engine failed.
    """

    invocation: Invocation
    decision: CedarDecision
    outcome: AuditOutcome
    allowed: bool
    reason: str | None = None
    processed: Mapping[str, object] = field(default_factory=dict)
    rejected: tuple[RejectedArgument, ...] = ()
    defaults_applied: Mapping[str, object] = field(default_factory=dict)
    obligations: tuple[str, ...] = ()
    declared_sensitive: Mapping[str, MaskStrategyName | None] = field(default_factory=dict)
    engine_errors: tuple[str, ...] = ()


class AuditTrail:
    """Masks, chains, and writes — the only path from a decision to an
    :class:`~sentrykit.stores.base.AuditSink`.

    Funnelling every write through one object is what makes ADR-007 enforceable rather than
    aspirational. Nothing else in sentrykit calls ``sink.write``, so "masking runs before the
    write" is a property of one function instead of a rule every future caller has to
    remember.

    Args:
        sink: Where records go. ``None`` disables auditing entirely — the trail then builds
            no records at all, which is what keeps an unaudited governor as cheap as it was
            before this hook existed.
        masker: How sensitive values are masked. Defaults to a masker built from the
            process settings.
        bundle: The loaded policy bundle, for per-policy provenance and obligations. Omitted
            when the governor was wired from raw policy text rather than from a source.
        strict: Whether a sink failure refuses the governed call. Defaults to the effective
            ``fail_mode`` — "can't prove it, don't do it".
    """

    __slots__ = ("_bundle", "_masker", "_prev_hash", "_sequence", "_sink", "_strict")

    def __init__(
        self,
        sink: AuditSink | None = None,
        *,
        masker: Masker | None = None,
        bundle: PolicyBundle | None = None,
        strict: bool = True,
    ) -> None:
        raise NotImplementedError

    @property
    def sink(self) -> AuditSink | None:
        """The configured sink, or ``None`` when auditing is off."""
        raise NotImplementedError

    @property
    def enabled(self) -> bool:
        """Whether a sink is configured. False means :meth:`record` does no work at all."""
        raise NotImplementedError

    def record(self, facts: DecisionFacts) -> AuthzAuditRecord | None:
        """Build, mask, chain and write one decision record.

        Args:
            facts: What the engine decided.

        Returns:
            The written record, or ``None`` when auditing is disabled.

        Raises:
            AuditUnavailable: If the sink refused the write and ``strict`` is set.
        """
        raise NotImplementedError

    def record_mutation(
        self,
        grant: Mapping[str, object],
        *,
        actor: Principal,
        outcome: AuditOutcome,
        invocation_id: str | None = None,
        reason: str | None = None,
    ) -> AuthzAuditRecord | None:
        """Write a record for an admin grant mutation.

        The admin surface is governed by the same engine and logged into the same sink
        (architecture §5), so a role assignment is as auditable as the call it later permits.

        Args:
            grant: The :meth:`~sentrykit.stores.base.GrantRecord.as_record` rendering.
            actor: Who made the change.
            outcome: ``granted`` or ``revoked``.
            invocation_id: Correlation id; generated when omitted.
            reason: The justification.

        Returns:
            The written record, or ``None`` when auditing is disabled.
        """
        raise NotImplementedError

    def query(self, window: AuditWindow) -> Iterable[AuthzAuditRecord]:
        """Read records back from the sink.

        Args:
            window: The filter.

        Returns:
            The matching records, oldest first. Empty when auditing is disabled.
        """
        raise NotImplementedError

    def _mask(self, facts: DecisionFacts) -> tuple[AuthzAuditRecord, dict[str, object]]:
        """Build the record with every sensitive value already masked.

        Private, and the only place raw values are touched. Kept as one method so the
        masking step cannot be bypassed by a future overload of :meth:`record`.
        """
        raise NotImplementedError

    def _append(self, record: AuthzAuditRecord) -> AuthzAuditRecord:
        """Chain ``record`` onto the trail and hand it to the sink."""
        raise NotImplementedError


def build_facts(
    *,
    invocation: Invocation,
    decision: CedarDecision,
    outcome: AuditOutcome,
    allowed: bool,
    reason: str | None = None,
    processed: Mapping[str, object] | None = None,
    rejected: Sequence[RejectedArgument] = (),
    defaults_applied: Mapping[str, object] | None = None,
    obligations: Sequence[str] = (),
    declared_sensitive: Mapping[str, MaskStrategyName | None] | None = None,
) -> DecisionFacts:
    """Assemble :class:`DecisionFacts`, filling the engine-error list from ``decision``.

    A convenience so the governor's five exit points each read as one call rather than ten
    keyword arguments, and so ``engine_errors`` cannot be forgotten at one of them.
    """
    raise NotImplementedError
