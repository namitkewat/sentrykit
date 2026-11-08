"""The audit record, the hash chain, and the one path from a decision to a sink.

An audit log has to survive scrutiny, which means four properties this module owns:

* **Reproducible.** The record pins ``policy_set_hash`` and snapshots the principal's
  *effective* attributes at decision time, so a replay is possible even after the policy set
  and the grants have both moved on.
* **Attributable.** Per-policy provenance names which source and which artifact produced each
  determining policy — not just its id.
* **Tamper-evident.** Each record carries the previous record's hash, so altering any record
  invalidates every record after it. Detection, not prevention; prevention is the sink's job
  (S3 Object Lock, WORM).
* **Safe to keep forever.** A *decision's* sensitive values are masked before the write and
  never after: its arguments, the principal's attributes, and the allow-sets, deny-sets and
  patterns of the constraints that governed it. A grant mutation is the exception, and is
  written as it stands — nothing on that path declares which of its fields are sensitive, so
  there is no plan to mask by, and an attribute grant's value reaches the sink in the clear.

Masking is structural rather than conventional: :class:`AuditTrail` is the only thing in
sentrykit that calls :meth:`~sentrykit.stores.base.AuditSink.write`, and it masks on the way
in. A unit test asserts that statically — the audit-side analogue of the import scan that
keeps web frameworks out of the core — so a future caller that reaches around it fails the
suite rather than the compliance review.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final, Literal, NamedTuple, TypeGuard
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from sentrykit.cedar import CedarDecision
from sentrykit.config import get_settings
from sentrykit.constraints import RejectedArgument
from sentrykit.context import Invocation, Principal
from sentrykit.errors import AuditUnavailable
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

_LOGGER: Final = logging.getLogger("sentrykit.audit")
"""The *operational* logger. Audit records never travel through it — see the logging
standards' "two channels, never conflated". It reports on the trail, not from it."""

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

_MUTATION_ACTIONS: Final[dict[str, str]] = {
    "granted": 'Action::"grant"',
    "revoked": 'Action::"revoke"',
}
"""The Cedar action a grant mutation is recorded under.

Spelled as a uid so an :class:`~sentrykit.stores.base.AuditWindow` filtering on ``action``
treats a mutation exactly like a decision — the admin surface is governed by the same engine
and belongs in the same query (architecture §5).
"""

_VALUE_BEARING_RULES: Final[frozenset[str]] = frozenset({"allow", "deny", "pattern"})
"""The rules of a described constraint that hold values rather than describe a shape.

An allow-set enumerates the very values the constraint exists to fence off — a permitted
peer's tenant id is as sensitive as the caller's own — and a per-principal ``pattern`` can
embed one as a literal, so both are masked before the write.

``minimum`` and ``maximum`` are deliberately absent: a bound is a rule, not a value, and an
auditor has to be able to read what the principal was permitted to pass as well as what they
tried to. So are ``policy``, ``required`` and ``has_default``, which carry no caller data in
the first place.
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
    return json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=repr,
    ).encode("utf-8")


class PrincipalSnapshot(BaseModel):
    """The acting principal exactly as the decision saw them.

    A snapshot, not a reference. Grants change, roles are revoked, attributes are corrected —
    and a record that merely *pointed* at a principal would silently start describing a
    different one. This is what makes a decision replayable long after the fact.

    Attributes:
        uid: The principal's Cedar uid.
        type: Entity type.
        id: Entity id.
        roles: Role names, expanded to ``Role::"..."`` edges at decision time.
        parents: Every other parent edge, as uids — the teams, projects and delegation edges
            a multi-hop relationship was resolved through.
        attributes: Effective Cedar attributes, masked.
        constraints: The argument constraints in force, by action, as
            :meth:`~sentrykit.constraints.ConstraintSet.describe` renders them — which
            withholds the default *value* but emits every other rule as written.
            :meth:`of` therefore does not mask them; :class:`AuditTrail` does, masking the
            rules that carry values — the allow-set, the deny-set and the pattern — under
            the name of the argument they govern. ``minimum`` and ``maximum`` reach the sink
            as written, because a bound is a rule rather than a value.
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
        """Snapshot a principal. Does **not** mask — :class:`AuditTrail` does that.

        That includes the constraints. They arrive *described* rather than dumped, which
        withholds the default value, but an allow-set, a deny-set and a pattern still hold
        the very values the constraint exists to fence off. :class:`AuditTrail` masks those
        three on the way to the sink and leaves the bounds as written — so a caller using
        this snapshot for anything else is holding raw values and has to treat them as such.
        """
        return cls(
            uid=str(principal.uid),
            type=principal.type,
            id=principal.id,
            roles=principal.roles,
            parents=tuple(str(parent) for parent in principal.parents),
            attributes=dict(principal.attributes),
            constraints={
                action: constraints.describe()
                for action, constraints in principal.constraints.items()
            },
        )


class AuthzAuditRecord(BaseModel):
    """One decision, or one admin mutation, as it is written to a sink.

    Every field is either something an auditor asks for or something a replay needs. The
    record is frozen: chaining produces a new record rather than mutating this one, so a
    record that has been written can never be edited in place by construction.

    One field is there to contradict the others. The chain advances solely on a successful
    write, so the records either side of a sink outage link perfectly and :func:`verify_chain`
    calls the run intact — which is true, nothing was altered, and is also exactly what a
    caller probing the policy boundary while the sink was down would want it to say. So a
    contiguous chain across a record does **not** mean nothing happened before it;
    :attr:`dropped_since_last_write` says how much did. It is inside :attr:`record_hash`
    whenever it is set, which puts the admission on the channel that counts as evidence rather
    than in an operational log nobody can prove anything from afterwards.

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
        obligations: Obligations the determining policies attached.
        determining_policies: The policies that decided it.
        provenance: Where each determining policy came from.
        policy_set_hash: Digest of the policy logic evaluated, so the decision replays.
        engine_errors: Cedar errors, when the engine failed rather than decided.
        masked: Which fields were masked and with which strategy. Without this an auditor
            cannot tell an ``hmac:...`` string from a value that genuinely looked like one.
        grant: The grant record, for ``kind="mutation"``.
        dropped_since_last_write: How many records were built, masked and then refused by the
            sink between the previous record that landed and this one — the only thing that
            tells a quiet log from a log with a hole in it. Zero on all but a vanishing
            number of records, and covered by :attr:`record_hash` whenever it is not.
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
    dropped_since_last_write: int = 0

    prev_hash: str = GENESIS_HASH
    record_hash: str = ""

    def payload(self) -> dict[str, object]:
        """Render everything the hash covers — that is, every field but :attr:`record_hash`.

        :attr:`prev_hash` **is** covered, which is what binds the chain: re-pointing a record
        at a different predecessor changes its own hash too.

        :attr:`dropped_since_last_write` is covered only when it is set, and that asymmetry
        is deliberate. A log written before the field existed hashed a payload without the
        key, so a key that always appeared — even at its default — would change every one of
        those digests and make an existing log fail re-verification. Omitting it at zero is
        still tamper-evident in both directions: forging a count to zero drops the key and
        forging one onto a clean record adds it, and either way the payload, and so the
        hash, is no longer the one that was written.
        """
        # ``warnings=False`` because a record must never raise or nag about the decision it
        # describes; anything pydantic cannot render in JSON mode is caught by
        # :func:`canonical_json`'s ``default=repr`` instead.
        rendered: dict[str, object] = self.model_dump(mode="json", warnings=False)
        rendered.pop("record_hash", None)
        if not self.dropped_since_last_write:
            rendered.pop("dropped_since_last_write", None)
        return rendered

    def compute_hash(self) -> str:
        """Compute this record's digest from :meth:`payload`."""
        return hashlib.sha256(canonical_json(self.payload())).hexdigest()

    def chained(
        self,
        *,
        prev_hash: str,
        sequence: int,
        dropped_since_last_write: int = 0,
    ) -> AuthzAuditRecord:
        """Return a copy positioned in a chain, with :attr:`record_hash` computed.

        All three arguments are the record's position in the log rather than anything the
        decision knew, which is why the loss count arrives here and not at build time: it is
        only knowable once the preceding writes have been attempted. Carrying it through this
        method is what keeps it inside the digest — a count applied after the hash was
        computed could be stripped off without trace, and a count applied by a second
        ``model_copy`` at the call site would put chain state in two places.

        Args:
            prev_hash: The predecessor's hash, or :data:`GENESIS_HASH` for the first record.
            sequence: Position in the chain.
            dropped_since_last_write: Records the sink refused since the last one it accepted.

        Returns:
            The chained record, ready to write.
        """
        # Two copies rather than one mutation: the model is frozen, and it has to stay that
        # way for "a written record cannot be edited in place" to be a property of the type.
        positioned = self.model_copy(
            update={
                "prev_hash": prev_hash,
                "sequence": sequence,
                "dropped_since_last_write": dropped_since_last_write,
                "record_hash": "",
            }
        )
        return positioned.model_copy(update={"record_hash": positioned.compute_hash()})

    def verify(self) -> bool:
        """Whether :attr:`record_hash` still matches this record's content."""
        return bool(self.record_hash) and self.record_hash == self.compute_hash()


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
        The verdict, naming the first record that fails. An empty run is intact by
        definition. The first record's ``prev_hash`` is not required to be
        :data:`GENESIS_HASH`, because a run is often a window over a longer log rather than
        the log itself.
    """
    previous: AuthzAuditRecord | None = None
    for record in records:
        if not record.verify():
            return ChainVerdict(False, record.sequence, "Record hash does not match its content")
        if previous is not None:
            if record.prev_hash != previous.record_hash:
                return ChainVerdict(
                    False,
                    record.sequence,
                    "Record does not link to its predecessor; a record was removed or altered",
                )
            if record.sequence != previous.sequence + 1:
                return ChainVerdict(
                    False,
                    record.sequence,
                    "Sequence numbers are not contiguous; a record is missing",
                )
        previous = record
    return ChainVerdict(True)


def _probe(sink: AuditSink, attribute: str) -> object:
    """Read an optional tail attribute off a sink, tolerating either shape.

    A sink may expose its tail as a method (``tail_hash()``) or as a property
    (``next_sequence``); neither is part of the :class:`~sentrykit.stores.base.AuditSink`
    contract, because a sink that posts to an HTTP endpoint has no tail to report. Absent
    means "cannot say", which leaves the trail starting a fresh chain.
    """
    value = getattr(sink, attribute, None)
    return value() if callable(value) else value


def _is_sequence_number(value: object) -> TypeGuard[int]:
    """Whether a probed value is usable as a chain position.

    ``bool`` is excluded explicitly: it is an ``int`` in Python, and a sink that returned
    ``False`` would otherwise silently reset the chain to sequence zero.
    """
    return isinstance(value, int) and not isinstance(value, bool)


def _mask_described_rules(
    argument: str,
    rules: Mapping[str, object],
    masker: Masker,
    strategy: MaskStrategyName,
) -> dict[str, object]:
    """Mask the value-bearing rules of one described constraint, leaving the rest alone.

    Every value is masked under ``argument`` rather than under the rule's name, which is what
    keeps an allow-set comparable with the same value masked as an argument: a digest in the
    set still answers "was what the caller proposed something they were permitted to pass"
    long after neither string can be read.

    A rule whose value is not the list :meth:`~sentrykit.constraints.ConstraintSet.describe`
    renders is masked whole rather than member by member. The value ends up unreadable either
    way, so that is the direction a shape surprise should fall in.
    """
    masked: dict[str, object] = {}
    for rule, value in rules.items():
        if rule not in _VALUE_BEARING_RULES:
            masked[rule] = value
        elif isinstance(value, list):
            masked[rule] = [masker.mask_value(argument, member, strategy) for member in value]
        else:
            masked[rule] = masker.mask_value(argument, value, strategy)
    return masked


def _mask_described_constraints(
    constraints: Mapping[str, object],
    masker: Masker,
    plan: Mapping[str, MaskStrategyName],
) -> dict[str, object]:
    """Mask every described constraint whose argument ``plan`` names.

    ``describe`` renders ``{action: {argument: {rule: value}}}`` and a masking plan is keyed
    by argument name, so the rules governing an argument and the argument itself mask under
    the same key with nothing in between.

    Anything not shaped that way falls through unchanged, for the reason
    :func:`canonical_json` falls back to ``repr``: an audit record must not be able to fail
    the decision it describes.
    """
    masked: dict[str, object] = {}
    for action, described in constraints.items():
        if not isinstance(described, Mapping):
            masked[action] = described
            continue
        masked[action] = {
            argument: (
                _mask_described_rules(argument, rules, masker, plan[argument])
                if argument in plan and isinstance(rules, Mapping)
                else rules
            )
            for argument, rules in described.items()
        }
    return masked


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

    Funnelling every write through one object is what makes masking-before-the-write
    enforceable rather than aspirational. Nothing else in sentrykit calls ``sink.write``, so
    "masking runs before the write" is a property of one function instead of a rule every
    future caller has to remember.

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

    __slots__ = (
        "_bundle",
        "_dropped",
        "_lock",
        "_masker",
        "_prev_hash",
        "_sequence",
        "_sink",
        "_strict",
    )

    def __init__(
        self,
        sink: AuditSink | None = None,
        *,
        masker: Masker | None = None,
        bundle: PolicyBundle | None = None,
        strict: bool = True,
    ) -> None:
        self._sink = sink
        self._masker = masker
        self._bundle = bundle
        self._strict = strict
        self._prev_hash: str = GENESIS_HASH
        self._sequence: int = 0
        # Starts at zero and is never resumed from the sink: a dropped record by definition
        # never reached it, so there is nothing there to read. The consequence is worth being
        # plain about — a process that dies while its sink is down takes its unreported count
        # with it. This narrows the window in which a loss is invisible; it does not close it.
        self._dropped: int = 0
        # One trail is shared by every thread the host serves a request on, and advancing the
        # chain is read-modify-write state. Taken in :meth:`_append` only: nothing can reach a
        # trail before its constructor returns, so :meth:`_resume` needs no protection.
        self._lock = threading.Lock()
        if sink is not None:
            self._resume(sink)

    def _resume(self, sink: AuditSink) -> None:
        """Pick the chain up where a previous process left it, when the sink can say.

        Probed with :func:`getattr` rather than by importing a concrete backend: a chain that
        restarts at :data:`GENESIS_HASH` on every process start is not a chain, but only some
        sinks can cheaply report their tail, and the core must not know which ones. Both
        halves matter — ``tail_hash`` alone would keep the links intact while the sequence
        restarted at zero, which :func:`verify_chain` reads as a deleted record.

        Two spellings of the sequence half are accepted: ``tail_sequence`` reports the last
        record written (``-1`` for an empty log) and ``next_sequence`` reports the one to
        write next. Both are optional, and a sink that offers neither simply starts at zero.
        """
        resumed = _probe(sink, "tail_hash")
        if isinstance(resumed, str) and resumed:
            self._prev_hash = resumed
        last = _probe(sink, "tail_sequence")
        if _is_sequence_number(last) and last >= 0:
            self._sequence = last + 1
            return
        following = _probe(sink, "next_sequence")
        if _is_sequence_number(following) and following >= 0:
            self._sequence = following

    @property
    def sink(self) -> AuditSink | None:
        """The configured sink, or ``None`` when auditing is off."""
        return self._sink

    @property
    def enabled(self) -> bool:
        """Whether a sink is configured. False means :meth:`record` does no work at all."""
        return self._sink is not None

    def _require_masker(self) -> Masker:
        """Return the masker, building the settings-derived default on first use.

        Deferred so that constructing a trail reads no configuration — and so a host that
        calls :func:`~sentrykit.config.configure` after wiring still gets the key it set.
        """
        masker = self._masker
        if masker is None:
            masker = Masker.from_settings(get_settings())
            self._masker = masker
        return masker

    def record(self, facts: DecisionFacts) -> AuthzAuditRecord | None:
        """Build, mask, chain and write one decision record.

        Args:
            facts: What the engine decided.

        Returns:
            The written record, or ``None`` when auditing is disabled.

        Raises:
            AuditUnavailable: If the sink refused the write and ``strict`` is set.
        """
        if self._sink is None:
            # Disabled: return before anything is built. An unaudited governor pays nothing.
            return None
        record, context = self._mask(facts)
        written = self._append(record)
        _LOGGER.debug("Recorded an authorization decision", extra=context)
        return written

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

        Raises:
            AuditUnavailable: If the sink refused the write and ``strict`` is set.
        """
        if self._sink is None:
            return None
        masker = self._require_masker()
        # A mutation has no callable signature and no determining policies, so nothing
        # declares which of its fields are sensitive and this plan comes back empty every
        # time. The consequence, stated rather than left to be discovered: a mutation record
        # reaches the sink unmasked -- an attribute grant's raw ``value``, the actor's own
        # snapshot attributes, the grant's own described constraint. The values still pass
        # through the masker rather than around it, so the day a plan can be derived here
        # this call site is already the one that applies it; deriving one is a design change,
        # not an oversight at this line.
        plan = masker.plan()
        record = AuthzAuditRecord(
            record_id=uuid4().hex,
            timestamp=datetime.now(UTC),
            invocation_id=invocation_id or uuid4().hex,
            kind="mutation",
            principal=self._snapshot(actor, masker, plan),
            action=_MUTATION_ACTIONS.get(outcome, ""),
            channel="internal",
            decision="allow",
            outcome=outcome,
            reason=reason,
            grant=masker.mask_mapping(grant, plan),
            masked=dict(plan),
        )
        return self._append(record)

    def query(self, window: AuditWindow) -> Iterable[AuthzAuditRecord]:
        """Read records back from the sink.

        Args:
            window: The filter.

        Returns:
            The matching records, oldest first. Empty when auditing is disabled.
        """
        if self._sink is None:
            return ()
        return self._sink.query(window)

    @staticmethod
    def _snapshot(
        principal: Principal,
        masker: Masker,
        plan: Mapping[str, MaskStrategyName],
    ) -> PrincipalSnapshot:
        """Snapshot a principal with its attributes and its constraints masked.

        :meth:`PrincipalSnapshot.of` deliberately does not mask, so that the masking step
        lives on this side of the sink boundary with every other one.

        Both halves run off the same plan and in the same copy. An attribute and the
        allow-set that governs the argument of the same name are the same secret in two
        shapes, and masking one without the other writes it in the clear two fields from its
        own digest — into a sink where it cannot be withdrawn.
        """
        snapshot = PrincipalSnapshot.of(principal)
        if not plan:
            # Nothing was declared sensitive, so there is nothing either half could mask.
            return snapshot
        return snapshot.model_copy(
            update={
                "attributes": masker.mask_mapping(snapshot.attributes, plan),
                "constraints": _mask_described_constraints(snapshot.constraints, masker, plan),
            }
        )

    def _mask(self, facts: DecisionFacts) -> tuple[AuthzAuditRecord, dict[str, object]]:
        """Build the record with every sensitive value already masked.

        Private, and the only place raw values are touched. Kept as one method so the
        masking step cannot be bypassed by a future overload of :meth:`record`.

        Returns:
            The unchained record, and the operational-log context describing it — correlation
            id, action, outcome, and which fields were masked. The context carries no values,
            only names, so it is safe for the ephemeral channel.
        """
        masker = self._require_masker()
        plan = masker.plan(declared=facts.declared_sensitive, obligations=facts.obligations)
        invocation = facts.invocation
        decision = facts.decision
        determining = tuple(decision.determining_policies)

        # The proposed arguments are already carried in ``proposed``; leaving Cedar's copy of
        # them in the environment would mean masking the same values twice, in two shapes,
        # with two chances to miss one.
        environment = {
            name: value for name, value in invocation.environment.items() if name != "args"
        }

        provenance: tuple[dict[str, object], ...] = ()
        if self._bundle is not None:
            provenance = tuple(
                entry.as_record() for entry in self._bundle.provenance_for(determining)
            )

        record = AuthzAuditRecord(
            record_id=uuid4().hex,
            # The decision's own ``now`` where the environment established one, so the record
            # and the Cedar evaluation agree on when this happened.
            timestamp=invocation.now or datetime.now(UTC),
            invocation_id=invocation.id,
            kind="decision",
            principal=self._snapshot(invocation.principal, masker, plan),
            action=str(invocation.action),
            resource=str(invocation.resource),
            callable_name=invocation.callable_name,
            channel=invocation.channel,
            environment=masker.mask_mapping(environment, plan),
            decision="allow" if facts.allowed else "deny",
            outcome=facts.outcome,
            reason=facts.reason,
            proposed=masker.mask_mapping(invocation.proposed, plan),
            processed=masker.mask_mapping(facts.processed, plan),
            rejected=masker.mask_rejections(facts.rejected, plan),
            defaults_applied=masker.mask_mapping(facts.defaults_applied, plan),
            obligations=facts.obligations,
            determining_policies=determining,
            provenance=provenance,
            policy_set_hash=decision.policy_set_hash,
            engine_errors=facts.engine_errors,
            masked=dict(plan),
        )
        context: dict[str, object] = {
            "invocation_id": invocation.id,
            "action": str(invocation.action),
            "outcome": facts.outcome,
            "masked": sorted(plan),
        }
        return record, context

    def _append(self, record: AuthzAuditRecord) -> AuthzAuditRecord:
        """Chain ``record`` onto the trail and hand it to the sink.

        The single ``sink.write`` call in sentrykit. Everything upstream of this line has
        already masked; nothing downstream of it is allowed to unmask.

        Serialized on one lock, because the chain is read-modify-write state and a host puts
        concurrent requests on threads sharing one trail.

        Also counts what the sink would not take. A refused record is lost, and because the
        chain advances only on success the records either side of the loss link cleanly — so
        the next record to land carries the count out in
        :attr:`AuthzAuditRecord.dropped_since_last_write`, and the hole stops being invisible
        to everyone but whoever was reading the operational log at the time.

        Returns:
            The chained record. It is returned even when a non-strict write failed, because
            the record still describes the decision — but the chain does not advance, so the
            next record links to the last one that actually landed.

        Raises:
            AuditUnavailable: If the sink refused the record and ``strict`` is set.
        """
        sink = self._sink
        if sink is None:  # pragma: no cover - callers check ``enabled`` first
            return record
        # Chaining and writing are one critical section, not two, and that choice has a price:
        # audit writes are fully serialized, so a sink that forces a durability call per record
        # — ``jsonl://path?fsync=true`` — puts every authorization decision in the process
        # behind that call. It is still the right boundary. Holding the lock only long enough
        # to reserve ``(prev_hash, sequence)`` would buy the concurrency back at the cost of
        # both properties the chain has: records would land in an order their links do not
        # describe, and a refused write could no longer leave the chain where it was, because
        # the next record would already have linked past it.
        with self._lock:
            chained = record.chained(
                prev_hash=self._prev_hash,
                sequence=self._sequence,
                dropped_since_last_write=self._dropped,
            )
            try:
                sink.write(chained)
            except AuditUnavailable as exc:
                # Counted under both fail modes. Strict refuses the governed call as well, but
                # a strict failure on a decision that was *already* being refused is swallowed
                # by the caller rather than surfaced — it must not replace the precise refusal
                # the caller needs — and that is exactly the loss this count exists to carry.
                self._dropped += 1
                self._report_failure(chained, exc)
                if self._strict:
                    raise
                return chained
            except Exception as exc:
                # A sink is third-party code. Whatever it raises, the decision path has to
                # classify it as "this could not be proven" rather than let it surface as an
                # unrelated failure of the protected call.
                failure = AuditUnavailable(getattr(sink, "name", "unknown"), str(exc) or repr(exc))
                self._dropped += 1
                self._report_failure(chained, failure)
                if self._strict:
                    raise failure from exc
                return chained
            # Advanced only on success: a record the sink refused is not in the log, so the
            # next one must link to the last that actually landed rather than to a phantom.
            # The count clears here and only here, so it reads "since the last record that
            # landed" and no loss is reported by two records.
            self._prev_hash = chained.record_hash
            self._sequence += 1
            self._dropped = 0
        return chained

    @staticmethod
    def _report_failure(record: AuthzAuditRecord, failure: AuditUnavailable) -> None:
        """Report a sink failure on the *operational* channel, naming no values.

        Logged under both fail modes, per the logging standards: under ``strict`` the call is
        refused as well, but the operator still needs to see why the sink is down.
        """
        _LOGGER.error(
            "Audit sink could not accept the record",
            extra={
                "invocation_id": record.invocation_id,
                "action": record.action,
                "outcome": record.outcome,
                "sink": failure.sink,
                "error": failure.reason,
            },
        )


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

    Args:
        invocation: The normalized invocation.
        decision: What Cedar returned; its ``errors`` become ``engine_errors``.
        outcome: What happened, finer-grained than allow/deny.
        allowed: Whether the call proceeded.
        reason: One-sentence explanation, matching the envelope's.
        processed: The final argument set, when the call proceeded.
        rejected: Arguments the policy refused.
        defaults_applied: Arguments filled from the principal's grants.
        obligations: Obligations from the determining policies.
        declared_sensitive: The callable's ``Sensitive`` markers.

    Returns:
        The assembled facts, with every collection copied so a later mutation of the
        governor's working state cannot rewrite what was recorded.
    """
    return DecisionFacts(
        invocation=invocation,
        decision=decision,
        outcome=outcome,
        allowed=allowed,
        reason=reason,
        processed=dict(processed or {}),
        rejected=tuple(rejected),
        defaults_applied=dict(defaults_applied or {}),
        obligations=tuple(obligations),
        declared_sensitive=dict(declared_sensitive or {}),
        engine_errors=tuple(decision.errors),
    )
