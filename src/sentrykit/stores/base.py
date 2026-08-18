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
them structurally without importing anything from sentrykit — the discovery half of ADR-004.
Every reference implementation in this package registers through the same decorator a
third-party package would use, so the core cannot tell them apart.

This module holds only contracts and value objects. It deliberately imports no backend, so
``registry.py`` can talk about a sink it has not yet loaded.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Final, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from sentrykit.cedar import Entity, EntityRef, PolicyEngine
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
"""The Cedar annotation obligations are declared in, per ADR-012.

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
        """Render for the audit record's ``provenance`` list."""
        raise NotImplementedError


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
        bundle_hash: Digest pinning the exact logic a decision was made against, per ADR-006.
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
        raise NotImplementedError

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
        raise NotImplementedError

    def obligations_for(self, determining: Sequence[str], *, allowed: bool) -> tuple[str, ...]:
        """Collect the obligations attached to the policies that decided a request.

        Per ADR-012, only the determining **permit** policies contribute obligations to a
        call that proceeds — an obligation on a ``forbid`` describes what must happen about a
        refusal, and belongs to the denial record instead.

        Args:
            determining: The determining policy names from the decision.
            allowed: Whether the decision permitted the call. Selects ``permit`` policies
                when true and ``forbid`` policies when false.

        Returns:
            The obligations, de-duplicated, first-seen order preserved.
        """
        raise NotImplementedError

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
        raise NotImplementedError


@runtime_checkable
class PolicySource(Protocol):
    """Where Cedar policy logic comes from.

    Read-mostly by construction: policy *logic* is reviewed in version control (ADR-005), so
    a source's job is to fetch an artifact and say which artifact it fetched — never to
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

    Grants are *data* (ADR-005). Nothing here changes reviewed policy logic — a role is a
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
        """Whether this grant applies at ``now`` — neither revoked nor expired."""
        raise NotImplementedError

    def as_record(self) -> dict[str, object]:
        """Render for an audit mutation record."""
        raise NotImplementedError


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
    """A filter over an audit log — the query half of ADR-006's "the report is a query".

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
        """Whether ``record`` falls inside this window, ignoring :attr:`limit`."""
        raise NotImplementedError


@runtime_checkable
class AuditSink(Protocol):
    """Where audit records are written, and read back from.

    Append-only and tamper-evident (ADR-006). A sink never updates or deletes a record, and
    never masks one: by the time a record reaches :meth:`write` its sensitive values are
    already masked, because ADR-007 puts masking upstream of the immutable write and
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


# --- context provider (phase 3) ----------------------------------------------------------


@runtime_checkable
class ContextProvider(Protocol):
    """How a framework establishes ambient context and renders sentrykit's refusals.

    Stubbed here so the plugin machinery is uniform across all four entry-point groups from
    the start (ADR-004): phases 3 and 4 add implementations under
    ``sentrykit/integrations/``, and the registry needs the contract to exist before they do.
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
