"""The three store contracts, and the value objects that cross them.

Architecture §4 insists on *three* stores rather than one, because they have three different
change profiles and three different guarantees:

* :class:`PolicySource` — Cedar policy **logic**. Read-mostly, authored in git, distributed
  as a versioned artifact. Multiple sources compose by **union**; ordering them cannot change
  a decision, because an override is expressed as a Cedar ``forbid`` and forbid always wins.
* :class:`GrantStore` — roles, group edges, per-argument constraints, expiries. **Mutable**;
  the only thing an admin surface ever writes. Multiple stores merge by precedence or route
  by namespace.
* :class:`AuditSink` — the decision log. **Append-only and tamper-evident.** Multiple sinks
  fan out.

They are :class:`~typing.Protocol` s, not base classes, so a third-party backend satisfies
them structurally without importing anything from sentrykit — the discovery half of the
plugin mechanism.
Every reference implementation in this package registers through the same decorator a
third-party package would use, so the core cannot tell them apart.

This module holds only contracts and value objects. It deliberately imports no backend, so
``registry.py`` can talk about a sink it has not yet loaded.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from sentrykit.cedar import Entity, EntityRef, PolicyAnnotation, PolicyEngine, policy_annotations
from sentrykit.constraints import ArgumentConstraint
from sentrykit.context import Principal

if TYPE_CHECKING:  # pragma: no cover - imported for annotations only, and audit imports us
    from sentrykit.audit import AuthzAuditRecord

__all__ = [
    "OBLIGATIONS_ANNOTATION",
    "WILDCARD_ACTION",
    "AuditSink",
    "AuditWindow",
    "ContextProvider",
    "GrantKind",
    "GrantRecord",
    "GrantSpec",
    "GrantStore",
    "NullAuditSink",
    "PolicyBundle",
    "PolicyEffect",
    "PolicyProvenance",
    "PolicySource",
    "SupportsClose",
]

PolicyEffect = Literal["permit", "forbid"]
"""Whether a policy permits or forbids."""

GrantKind = Literal["role", "parent", "attribute", "constraint"]
"""What a grant confers.

``role`` and ``parent`` are both parent edges — ``role`` is the shorthand that becomes
``Role::"<subject>"`` — and they are what make a multi-hop relationship resolvable by Cedar.
``attribute`` sets a principal attribute. ``constraint`` attaches an
:class:`~sentrykit.constraints.ArgumentConstraint` for one argument of one action.
"""

OBLIGATIONS_ANNOTATION: Final = "obligations"
"""The Cedar annotation obligations are declared in.

One comma-separated value, because Cedar rejects a repeated annotation key outright
(``ValueError: duplicate annotation``).
"""

WILDCARD_ACTION: Final = "*"
"""Constraint key meaning "every action", matching :mod:`sentrykit.context`'s spelling."""


# --- policy source -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PolicyProvenance:
    """Where one policy came from, and what it declares.

    One of these per static policy in a loaded bundle. The audit record carries the entries
    matching a decision's determining policies, which is what lets an auditor answer "which
    file, at which version, in which store, produced this denial" without re-deriving it.

    Attributes:
        cedar_id: Cedar's generated id (``policy0``), positional in the bundle's policy text.
        policy_id: The ``@id`` annotation, namespaced by the composite when more than one
            source contributes. Falls back to :attr:`cedar_id`. This is the spelling
            :attr:`~sentrykit.cedar.CedarDecision.determining_policies` reports.
        effect: ``permit`` or ``forbid``.
        source: Name of the :class:`PolicySource` that contributed it.
        origin: Artifact-level provenance — a file path, an S3 version id, a git commit.
        annotations: Every annotation on the policy.
        obligations: The parsed ``@obligations`` annotation, split and stripped.
    """

    cedar_id: str
    policy_id: str
    effect: PolicyEffect
    source: str = ""
    origin: str = ""
    annotations: Mapping[str, str | None] = field(default_factory=dict)
    obligations: tuple[str, ...] = ()

    def as_record(self) -> dict[str, object]:
        """Render for the audit record's ``provenance`` list.

        The declaring annotations are carried through when the policy has any, because
        ``@risk("high")`` on the policy that refused a call is exactly the kind of thing an
        auditor reads the provenance for. Empty collections are omitted so a record stays
        readable.
        """
        rendered: dict[str, object] = {
            "cedar_id": self.cedar_id,
            "policy_id": self.policy_id,
            "effect": self.effect,
            "source": self.source,
            "origin": self.origin,
        }
        if self.obligations:
            rendered["obligations"] = list(self.obligations)
        if self.annotations:
            rendered["annotations"] = dict(self.annotations)
        return rendered


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    """Everything a :class:`PolicySource` load produced, ready to become a policy engine.

    The bundle owns the join between a decision and the policies that made it. Cedar numbers
    policies positionally in the text it parsed, so :attr:`provenance` is only meaningful
    alongside the *exact* :attr:`policies` string it was derived from — which is why the two
    travel together in one immutable object rather than being reassembled by a caller.

    Attributes:
        policies: The concatenated Cedar policy text.
        schema: Cedar schema text, when the source supplies one.
        entities: The stable entity graph the source contributes — roles, teams, resources.
            Principals come from a :class:`GrantStore`, never from here.
        provenance: One entry per static policy, in Cedar's numbering order.
        bundle_hash: Digest pinning the exact logic a decision was made against, so the
            decision replays.
        source: Name of the source (or composite) that produced this bundle.
    """

    policies: str
    schema: str | None = None
    entities: tuple[Entity, ...] = ()
    provenance: tuple[PolicyProvenance, ...] = ()
    bundle_hash: str = ""
    source: str = ""

    def engine(self) -> PolicyEngine:
        """Build the Cedar engine for this bundle.

        Returns:
            An engine over :attr:`policies`, :attr:`entities` and :attr:`schema`.

        Raises:
            ConfigurationError: If any of the three fail to parse.
        """
        return PolicyEngine(self.policies, self.entities, schema=self.schema)

    def _index(self) -> dict[str, PolicyProvenance]:
        """Key every provenance entry by each name a decision could report it under.

        Three keys per entry, in precedence order: the (possibly namespaced)
        :attr:`~PolicyProvenance.policy_id`, Cedar's generated id, and — the awkward one —
        the *raw* ``@id`` annotation. The third is needed because namespacing happens on our
        side of Cedar: a bundle loaded with ``namespace="hr"`` records ``hr/btg-read`` while
        Cedar keeps reporting ``btg-read``, and without the raw key the join would silently
        find nothing exactly when a composite is in play.

        Earlier entries win, so a duplicate ``@id`` across two sources resolves to the first
        one rather than raising — the namespaced key already distinguishes them for anyone
        who asks precisely.
        """
        index: dict[str, PolicyProvenance] = {}
        for entry in self.provenance:
            index.setdefault(entry.policy_id, entry)
        for entry in self.provenance:
            index.setdefault(entry.cedar_id, entry)
        for entry in self.provenance:
            declared = entry.annotations.get("id")
            if isinstance(declared, str) and declared:
                index.setdefault(declared, entry)
        return index

    def provenance_for(self, determining: Sequence[str]) -> tuple[PolicyProvenance, ...]:
        """Resolve the provenance of the policies that decided a request.

        Args:
            determining: :attr:`~sentrykit.cedar.CedarDecision.determining_policies`, which
                names policies by their ``@id`` where they declare one and by Cedar's
                generated id otherwise — so both spellings are looked up.

        Returns:
            The matching entries, in the order given. Names with no match are skipped rather
            than raising: an audit record must never fail the decision it describes.
        """
        if not determining or not self.provenance:
            return ()
        index = self._index()
        resolved = [index[name] for name in determining if name in index]
        return tuple(resolved)

    def obligations_for(self, determining: Sequence[str], *, allowed: bool) -> tuple[str, ...]:
        """Collect the obligations attached to the policies that decided a request.

        Only the determining **permit** policies contribute obligations to a call that
        proceeds — an obligation on a ``forbid`` describes what must happen about a
        refusal, and belongs to the denial record instead.

        Args:
            determining: The determining policy names from the decision.
            allowed: Whether the decision permitted the call. Selects ``permit`` policies
                when true and ``forbid`` policies when false.

        Returns:
            The obligations, de-duplicated, first-seen order preserved.
        """
        wanted: PolicyEffect = "permit" if allowed else "forbid"
        # A dict deduplicates while preserving first-seen order, which matters because
        # obligations are discharged in the order they are reported.
        collected: dict[str, None] = {}
        for entry in self.provenance_for(determining):
            if entry.effect != wanted:
                continue
            for obligation in entry.obligations:
                collected.setdefault(obligation, None)
        return tuple(collected)

    @classmethod
    def from_text(
        cls,
        policies: str,
        *,
        schema: str | None = None,
        entities: Sequence[Entity] = (),
        source: str = "",
        origin: str = "",
        namespace: str | None = None,
    ) -> PolicyBundle:
        """Build a bundle from policy text, reading the annotation index out of it.

        Args:
            policies: Cedar policy text.
            schema: Cedar schema text, if any.
            entities: The stable entity graph.
            source: Name of the contributing source, recorded on every provenance entry.
            origin: Artifact-level provenance, recorded on every provenance entry.
            namespace: When set, declared ids are rewritten as ``<namespace>/<id>`` so that
                two sources declaring the same ``@id`` stay distinguishable. Cedar does not
                enforce ``@id`` uniqueness, so this is sentrykit's hygiene, not Cedar's.

        Returns:
            The bundle, with :attr:`bundle_hash` computed.

        Raises:
            ConfigurationError: If the policy text does not parse.
        """
        # One parse of one string produces both halves: the annotation index is keyed by
        # Cedar's *positional* generated ids, so deriving it from anything other than the
        # exact text the engine will be built from silently mis-joins every decision.
        provenance = tuple(
            _provenance_of(annotation, source=source, origin=origin, namespace=namespace)
            for annotation in policy_annotations(policies)
        )
        return cls(
            policies=policies,
            schema=schema,
            entities=tuple(entities),
            provenance=provenance,
            bundle_hash=_bundle_hash(policies, schema),
            source=source,
        )


@runtime_checkable
class PolicySource(Protocol):
    """Where Cedar policy logic comes from.

    Read-mostly by construction: policy *logic* is reviewed in version control, so a
    source's job is to fetch an artifact and say which artifact it fetched — never to
    author or mutate policy at runtime.

    Implementations are addressed by DSN and registered under the
    ``sentrykit.policy_sources`` entry-point group.
    """

    @property
    def name(self) -> str:
        """Short name for this source, used to namespace policy ids and tag provenance."""
        ...

    def load(self) -> PolicyBundle:
        """Fetch the current policy artifact.

        Returns:
            The loaded bundle, ready to build a :class:`~sentrykit.cedar.PolicyEngine`.

        Raises:
            ConfigurationError: If the artifact is missing, unparseable, or fails schema
                validation.
        """
        ...

    def current_hash(self) -> str:
        """Return the digest of the artifact that :meth:`load` would return right now.

        Cheap enough to poll: a caller uses it to decide whether a reload is needed without
        paying for a parse. Equal to the loaded bundle's :attr:`PolicyBundle.bundle_hash`.
        """
        ...


# --- grant store -------------------------------------------------------------------------


class GrantSpec(BaseModel):
    """A grant to make: what to confer on whom, and for how long.

    Grants are *data*, never logic. Nothing here changes reviewed policy — a role is a
    parent edge, an expiry is a timestamp the store enforces at materialization, and an
    argument constraint is an attribute of the grant. That separation is what lets an admin
    API exist without an approval workflow around every call.

    Attributes:
        principal: Who receives the grant.
        kind: What is being conferred.
        subject: The role name, parent uid, attribute name, or argument name, depending on
            :attr:`kind`.
        value: The attribute value, for ``kind="attribute"``.
        constraint: The argument constraint, for ``kind="constraint"``.
        action: Which action a ``constraint`` applies to — a full uid, a bare action id, or
            ``"*"`` for every action, matching
            :meth:`~sentrykit.context.Principal.constraints_for`.
        granted_by: The actor making the grant, recorded for the audit trail.
        expires_at: When the grant stops applying. ``None`` means it does not expire.
        reason: Why the grant was made — the justification an auditor asks for.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    principal: EntityRef
    kind: GrantKind
    subject: str
    value: object | None = None
    constraint: ArgumentConstraint | None = None
    action: str = WILDCARD_ACTION
    granted_by: str | None = None
    expires_at: datetime | None = None
    reason: str | None = None


class GrantRecord(BaseModel):
    """A grant as stored: a :class:`GrantSpec` plus its lifecycle.

    Returned by every mutation so the caller — and the audit trail — sees exactly what
    changed, including the id needed to revoke it later.

    Attributes:
        id: Stable identifier for this grant.
        spec: What was granted.
        granted_at: When it was made.
        revoked_at: When it was withdrawn, or ``None`` while it stands.
        revoked_by: The actor who withdrew it.
        revoked_reason: Why it was withdrawn.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    spec: GrantSpec
    granted_at: datetime
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    revoked_reason: str | None = None

    def is_active(self, now: datetime) -> bool:
        """Whether this grant applies at ``now`` — neither revoked nor expired.

        A naive timestamp on either side is read as UTC rather than as local time, for the
        same reason :func:`~sentrykit.cedar.coerce_value` does it: whether a grant has
        expired must not depend on the timezone of the host that happened to ask.
        """
        if self.revoked_at is not None:
            return False
        expires_at = self.spec.expires_at
        return expires_at is None or _as_utc(expires_at) > _as_utc(now)

    def as_record(self) -> dict[str, object]:
        """Render for an audit mutation record.

        Rendered by hand rather than dumped, because two fields need shaping: the principal
        is written as its Cedar uid (a bare ``model_dump`` would emit the underlying
        two-tuple), and a constraint is *described* rather than dumped, so a per-principal
        default value cannot leak into the log through the back door.
        """
        spec = self.spec
        rendered: dict[str, object] = {
            "id": self.id,
            "principal": str(spec.principal),
            "kind": spec.kind,
            "subject": spec.subject,
            "action": spec.action,
            "granted_at": self.granted_at.isoformat(),
            "granted_by": spec.granted_by,
            "reason": spec.reason,
            "expires_at": spec.expires_at.isoformat() if spec.expires_at is not None else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at is not None else None,
            "revoked_by": self.revoked_by,
            "revoked_reason": self.revoked_reason,
        }
        if spec.value is not None:
            rendered["value"] = spec.value
        if spec.constraint is not None:
            rendered["constraint"] = spec.constraint.describe()
        return rendered


@runtime_checkable
class GrantStore(Protocol):
    """Where principals, their edges, and their argument constraints live.

    The mutable store, and the admin surface's only write target. Because
    ``Action::"grant_role"`` is an ordinary Cedar action, an admin surface built on this is
    governed by the same engine it administers and logged into the same sink.

    Implementations are addressed by DSN and registered under the
    ``sentrykit.grant_stores`` entry-point group.
    """

    @property
    def name(self) -> str:
        """Short name for this store, used for namespace routing and audit provenance."""
        ...

    def get_principal(
        self,
        principal: str | EntityRef,
        *,
        now: datetime | None = None,
    ) -> Principal | None:
        """Materialize a principal with its roles, parents, attributes and constraints.

        "Materialized" is the whole contract: the returned
        :class:`~sentrykit.context.Principal` is ready to hand to the engine, with expired
        and revoked grants already excluded, so the decision path never reasons about grant
        lifecycles.

        Args:
            principal: The principal id (assumed type ``User``) or a full reference.
            now: The moment to evaluate expiries against. Defaults to the current UTC time;
                pass one to make a test deterministic.

        Returns:
            The principal, or ``None`` when the store knows nothing about them. ``None`` is
            not an error — the caller fails closed on it.
        """
        ...

    def grants_for(
        self,
        principal: str | EntityRef,
        *,
        include_inactive: bool = False,
    ) -> tuple[GrantRecord, ...]:
        """List the grants held by ``principal``.

        Args:
            principal: The principal id or reference.
            include_inactive: Whether to include revoked and expired grants, which an audit
                report needs and a decision does not.

        Returns:
            The grants, oldest first.
        """
        ...

    def grant(self, spec: GrantSpec, *, now: datetime | None = None) -> GrantRecord:
        """Confer a grant.

        Args:
            spec: What to confer.
            now: The grant timestamp. Defaults to the current UTC time.

        Returns:
            The stored record, carrying the id needed to revoke it.

        Raises:
            ConfigurationError: If the spec is inconsistent — a ``constraint`` grant with no
                constraint, say.
        """
        ...

    def revoke(
        self,
        grant_id: str,
        *,
        revoked_by: str | None = None,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> GrantRecord:
        """Withdraw a grant.

        Revocation marks the record rather than deleting it: "who had what, when" has to
        survive the withdrawal or the audit trail has a hole in it.

        Args:
            grant_id: The id returned by :meth:`grant`.
            revoked_by: The actor withdrawing it.
            reason: Why.
            now: The revocation timestamp. Defaults to the current UTC time.

        Returns:
            The updated record.

        Raises:
            ConfigurationError: If no such grant exists.
        """
        ...

    def entities(self) -> tuple[Entity, ...]:
        """Return the stable entities this store contributes to the Cedar graph.

        Roles, teams and projects that grants point at — the nodes a parent edge needs to
        resolve. Principals are *not* included: they are per-request deltas, so one
        principal's snapshot can never leak into another's decision.
        """
        ...


# --- audit sink --------------------------------------------------------------------------


class AuditWindow(BaseModel):
    """A filter over an audit log — the query half of "the yearly report is a query".

    Every field narrows; an empty window matches everything. Filtering lives on the window
    rather than in each sink so that a third-party backend can push down what it can and lean
    on :meth:`matches` for the rest, without the semantics drifting per backend.

    Attributes:
        start: Inclusive lower bound on ``timestamp``.
        end: Exclusive upper bound on ``timestamp``.
        principal: Match this principal uid exactly.
        action: Match this action, as either a full uid or a bare id.
        resource: Match this resource uid exactly.
        decision: ``allow`` or ``deny``.
        kind: ``decision`` or ``mutation``.
        limit: Stop after this many records.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    start: datetime | None = None
    end: datetime | None = None
    principal: str | None = None
    action: str | None = None
    resource: str | None = None
    decision: Literal["allow", "deny"] | None = None
    kind: Literal["decision", "mutation"] | None = None
    limit: int | None = Field(default=None, ge=1)

    def matches(self, record: AuthzAuditRecord) -> bool:
        """Whether ``record`` falls inside this window, ignoring :attr:`limit`.

        The time bounds are half-open — ``start`` inclusive, ``end`` exclusive — so adjacent
        windows tile a log without double-counting a record on the boundary.
        """
        if self.start is not None and _as_utc(record.timestamp) < _as_utc(self.start):
            return False
        if self.end is not None and _as_utc(record.timestamp) >= _as_utc(self.end):
            return False
        if self.principal is not None and record.principal.uid != self.principal:
            return False
        if self.action is not None and not _names_action(self.action, record.action):
            return False
        if self.resource is not None and record.resource != self.resource:
            return False
        if self.decision is not None and record.decision != self.decision:
            return False
        return not (self.kind is not None and record.kind != self.kind)


@runtime_checkable
class AuditSink(Protocol):
    """Where audit records are written, and read back from.

    Append-only and tamper-evident. A sink never updates or deletes a record, and never
    masks one: by the time a record reaches :meth:`write` its sensitive values are already
    masked, because masking runs upstream of the immutable write and
    :class:`~sentrykit.audit.AuditTrail` is the only thing that calls this method.

    Implementations are addressed by DSN and registered under the ``sentrykit.audit_sinks``
    entry-point group.
    """

    @property
    def name(self) -> str:
        """Short name for this sink, used in fan-out error reporting."""
        ...

    def write(self, record: AuthzAuditRecord) -> None:
        """Append one record.

        Args:
            record: The record, already masked and already chained.

        Raises:
            AuditUnavailable: If the record could not be durably appended. The caller
                decides what that means: under ``fail_mode="closed"`` the governed call is
                refused, because an action that cannot be proven cannot be taken.
        """
        ...

    def query(self, window: AuditWindow) -> Iterator[AuthzAuditRecord]:
        """Read back the records matching ``window``, oldest first.

        Returns:
            An iterator, so a sink over a large log need not materialize it.

        Raises:
            AuditUnavailable: If the log cannot be read.
        """
        ...


@runtime_checkable
class SupportsClose(Protocol):
    """A backend holding a resource that should be released.

    Kept separate from :class:`AuditSink` on purpose: a third-party sink that posts to an
    HTTP endpoint has nothing to close, and requiring a no-op ``close`` from it would be
    contract for contract's sake. Composites and the registry close what supports closing.
    """

    def close(self) -> None:
        """Release the backend's resources. Idempotent."""
        ...


class NullAuditSink:
    """The sink that discards everything — the default when none is configured.

    A governor with no sink does not construct records at all, so this exists for the case
    where a sink is *wanted* structurally (a composite with nothing configured, a test
    asserting the write path runs) but nothing should be persisted.
    """

    name: str = "null"

    def write(self, record: AuthzAuditRecord) -> None:
        """Discard ``record``."""

    def query(self, window: AuditWindow) -> Iterator[AuthzAuditRecord]:
        """Yield nothing."""
        return iter(())


# --- context provider ---------------------------------------------------------------------


@runtime_checkable
class ContextProvider(Protocol):
    """How a framework establishes ambient context and renders sentrykit's refusals.

    Declared here, with the other three contracts, so the plugin machinery is uniform across
    all four entry-point groups. The implementations live under ``sentrykit/integrations/``,
    behind optional extras, and the core must not import them to know the contract.
    Registered under the ``sentrykit.context_providers`` entry-point group.
    """

    @property
    def name(self) -> str:
        """Short name for this provider, e.g. ``fastapi``."""
        ...

    def establish(self, request: object) -> object:
        """Resolve the principal and environment from a framework request and establish them.

        Args:
            request: The framework's request object.

        Returns:
            A :class:`~sentrykit.context.ContextScope` to reset at the end of the boundary.
        """
        ...

    def render_error(self, error: Exception) -> object:
        """Render a sentrykit refusal as the framework's error response.

        Args:
            error: A :class:`~sentrykit.errors.SentrykitError`.

        Returns:
            The framework-native response, carrying the ``_authz`` envelope at whatever the
            effective verbosity allows.
        """
        ...


# --- helpers -----------------------------------------------------------------------------


def _as_utc(moment: datetime) -> datetime:
    """Read a naive timestamp as UTC so two timestamps are always comparable.

    Mixing an aware and a naive ``datetime`` is a ``TypeError`` in Python, and the places
    that compare them here — grant expiry, an audit window — must not be able to raise from
    a caller passing ``datetime.now()`` instead of ``datetime.now(UTC)``.
    """
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def _names_action(wanted: str, actual: str) -> bool:
    """Whether ``wanted`` names ``actual``, as either a full uid or a bare action id.

    Compared textually rather than through :meth:`~sentrykit.cedar.EntityRef.parse`, because
    a mutation record carries an empty action and an unparseable name must read as "does not
    match" rather than as a configuration fault raised from inside a report query.
    """
    if wanted == actual:
        return True
    _, separator, quoted = actual.partition('::"')
    return bool(separator) and quoted.endswith('"') and quoted[:-1] == wanted


def _bundle_hash(policies: str, schema: str | None) -> str:
    """Digest the policy text and schema that a bundle pins.

    Mirrors :func:`sentrykit.cedar.PolicyEngine.policy_set_hash`'s construction — the policy
    bytes, a separator, then the schema bytes — so a bundle's hash and the hash recorded on a
    decision made against it agree. Computed here rather than imported, because a digest
    format the audit trail depends on should not be a private detail of another module.
    """
    digest = hashlib.sha256()
    digest.update(policies.encode("utf-8"))
    digest.update(b"\x00")
    digest.update((schema or "").encode("utf-8"))
    return digest.hexdigest()


def _provenance_of(
    annotation: PolicyAnnotation,
    *,
    source: str,
    origin: str,
    namespace: str | None,
) -> PolicyProvenance:
    """Turn one parsed policy's annotations into a provenance entry.

    Args:
        annotation: One entry from :func:`~sentrykit.cedar.policy_annotations`.
        source: Name of the contributing source.
        origin: Artifact-level provenance for this policy.
        namespace: Prefix for the declared id, per :meth:`PolicyBundle.from_text`.

    Returns:
        The entry, with the ``@obligations`` annotation split on commas and stripped. An
        empty segment is dropped, so a trailing comma is not an obligation named ``""``.
    """
    declared = annotation.declared_id
    declared_obligations = annotation.annotation(OBLIGATIONS_ANNOTATION)
    obligations = (
        tuple(part.strip() for part in declared_obligations.split(",") if part.strip())
        if declared_obligations
        else ()
    )
    return PolicyProvenance(
        cedar_id=annotation.cedar_id,
        policy_id=f"{namespace}/{declared}" if namespace else declared,
        effect=annotation.effect,
        source=source,
        origin=origin,
        annotations=dict(annotation.annotations),
        obligations=obligations,
    )
