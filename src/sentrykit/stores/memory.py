"""In-memory backends: a grant store, an audit sink, and a token vault.

The zero-dependency defaults. They exist for three audiences at once — a test that needs a
grant store without a database, an example app that should run from a clone, and a host that
wants to see the wiring work before choosing a real backend — and they implement the *whole*
contract rather than a convenient subset, so behavior learned here transfers to a durable
backend unchanged.

Two properties are worth stating plainly, because "in-memory" invites the wrong assumptions:

* **Grant lifecycles are enforced here, not downstream.**
  :meth:`InMemoryGrantStore.get_principal` returns a principal with expired and revoked
  grants already excluded, so the decision path never reasons about ``expires_at``. That is
  the contract every :class:`~sentrykit.stores.base.GrantStore` owes, and putting it in the
  reference implementation is what stops it from being reinvented per backend.
* **Revocation marks; it never deletes.** "Who had what, when" has to survive the withdrawal,
  so a revoked grant stays in the store with its revocation stamped on it and simply stops
  being active.

Nothing here is durable. :class:`InMemoryAuditSink` is a fine target for a test asserting
what was written and a bad one for anything that has to survive a restart — that is what
:class:`~sentrykit.stores.jsonl.JsonlAuditSink` and the durable backends are for.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final
from uuid import uuid4

from sentrykit.cedar import Entity, EntityRef
from sentrykit.constraints import ArgumentConstraint, ConstraintSet
from sentrykit.context import Principal
from sentrykit.errors import ConfigurationError
from sentrykit.registry import DSN, register_audit_sink, register_grant_store
from sentrykit.stores.base import AuditWindow, GrantRecord, GrantSpec

if TYPE_CHECKING:  # pragma: no cover - the sink only needs the type for its annotations
    from sentrykit.audit import AuthzAuditRecord

__all__ = ["InMemoryAuditSink", "InMemoryGrantStore", "InMemoryTokenVault"]

DEFAULT_PRINCIPAL_TYPE: Final = "User"
"""Entity type assumed when a principal is named by a bare id, matching
:class:`~sentrykit.context.Principal`'s own default."""

TOKEN_PREFIX: Final = "token:"  # noqa: S105 - a display prefix, not a credential
"""The prefix :class:`~sentrykit.masking.TokenizeStrategy` puts on a vault token."""


@register_grant_store("memory")
class InMemoryGrantStore:
    """Roles, parent edges, attributes and argument constraints, held in a dict.

    Args:
        name: Short name for this store, used for audit provenance and error messages.
        namespace: The namespace this store answers for, when a
            :class:`~sentrykit.stores.composite.CompositeGrantStore` routes by namespace
            rather than merging by precedence. ``None`` means it takes part in merging.

    Example:
        ```python
        store = InMemoryGrantStore()
        store.add_entity(Entity(EntityRef("Team", "payments")))
        store.grant(GrantSpec(principal=EntityRef("User", "alice"), kind="role",
                              subject="support"))
        principal = store.get_principal("alice")
        ```
    """

    __slots__ = ("_by_principal", "_entities", "_grants", "_lock", "_name", "_namespace")

    def __init__(self, *, name: str = "memory", namespace: str | None = None) -> None:
        self._name = name
        self._namespace = namespace
        # Insertion-ordered on purpose: "oldest first" is the contract for ``grants_for``,
        # and a later grant overriding an earlier one for the same attribute falls out of it.
        self._grants: dict[str, GrantRecord] = {}
        self._by_principal: dict[EntityRef, list[str]] = {}
        self._entities: dict[EntityRef, Entity] = {}
        self._lock = threading.RLock()

    @classmethod
    def from_dsn(cls, dsn: DSN) -> InMemoryGrantStore:
        """Build from ``memory://`` or ``memory://<namespace>?namespace=...``.

        The target doubles as the namespace, so ``memory://tenant-a`` and
        ``memory://?namespace=tenant-a`` mean the same thing. Each call builds a *separate*
        store: two ``memory://`` DSNs are two independent sets of grants, which is what makes
        namespace routing testable without a database.

        Args:
            dsn: The parsed address.

        Returns:
            The store.
        """
        namespace = dsn.option("namespace") or dsn.target.strip() or None
        # Named after the namespace where there is one, so a routed composite's members are
        # distinguishable in an error message and in audit provenance rather than all being
        # called "memory".
        return cls(name=dsn.option("name") or namespace or dsn.scheme, namespace=namespace)

    @property
    def name(self) -> str:
        """Short name for this store, used for namespace routing and audit provenance."""
        return self._name

    @property
    def namespace(self) -> str | None:
        """The namespace this store answers for, or ``None`` when it takes part in merging."""
        return self._namespace

    def add_entity(self, entity: Entity) -> None:
        """Seed one node of the stable entity graph.

        The nodes a parent edge points *at* — roles, teams, projects, tools — have to exist
        for Cedar to resolve a multi-hop relationship through them. Seeding replaces any
        entity already held under the same uid.

        Args:
            entity: The node. Principals do not belong here: they are materialized per
                request by :meth:`get_principal`, and a stale copy in the base graph is
                exactly the leak :meth:`entities` exists to prevent.
        """
        with self._lock:
            self._entities[entity.uid] = entity

    def get_principal(
        self,
        principal: str | EntityRef,
        *,
        now: datetime | None = None,
    ) -> Principal | None:
        """Materialize a principal from their active grants.

        Args:
            principal: The principal id (assumed type ``User``) or a full reference.
            now: The moment to evaluate expiries against. Defaults to the current UTC time.

        Returns:
            The principal, or ``None`` when this store holds neither a grant nor a seeded
            entity for them. ``None`` is not an error — the caller fails closed on it.
        """
        reference = EntityRef.parse(principal, default_type=DEFAULT_PRINCIPAL_TYPE)
        moment = _now(now)
        with self._lock:
            held = tuple(
                self._grants[grant_id] for grant_id in self._by_principal.get(reference, ())
            )
            seed = self._entities.get(reference)
        if not held and seed is None:
            return None

        roles: dict[str, None] = {}
        parents: dict[EntityRef, None] = {}
        attributes: dict[str, object] = {}
        constraints: dict[str, dict[str, ArgumentConstraint]] = {}
        if seed is not None:
            attributes.update(seed.attributes)
            for parent in seed.parents:
                parents.setdefault(parent, None)

        for record in held:
            if not record.is_active(moment):
                continue
            spec = record.spec
            if spec.kind == "role":
                roles.setdefault(spec.subject, None)
            elif spec.kind == "parent":
                parents.setdefault(EntityRef.parse(spec.subject), None)
            elif spec.kind == "attribute":
                attributes[spec.subject] = spec.value
            elif spec.constraint is not None:
                constraints.setdefault(spec.action, {})[spec.subject] = spec.constraint

        return Principal(
            id=reference.id,
            type=reference.type,
            roles=tuple(roles),
            parents=tuple(parents),
            attributes=attributes,
            constraints={
                action: ConstraintSet(arguments=arguments)
                for action, arguments in constraints.items()
            },
        )

    def grants_for(
        self,
        principal: str | EntityRef,
        *,
        include_inactive: bool = False,
    ) -> tuple[GrantRecord, ...]:
        """List the grants held by ``principal``, oldest first.

        Args:
            principal: The principal id or reference.
            include_inactive: Whether to include revoked and expired grants, which an audit
                report needs and a decision does not.

        Returns:
            The grants, in the order they were made.
        """
        reference = EntityRef.parse(principal, default_type=DEFAULT_PRINCIPAL_TYPE)
        moment = _now(None)
        with self._lock:
            held = tuple(
                self._grants[grant_id] for grant_id in self._by_principal.get(reference, ())
            )
        if include_inactive:
            return held
        return tuple(record for record in held if record.is_active(moment))

    def grant(self, spec: GrantSpec, *, now: datetime | None = None) -> GrantRecord:
        """Confer a grant.

        Args:
            spec: What to confer.
            now: The grant timestamp. Defaults to the current UTC time.

        Returns:
            The stored record, carrying the id needed to revoke it.

        Raises:
            ConfigurationError: If the spec is inconsistent — a ``constraint`` grant with no
                constraint, or a ``parent`` grant whose subject is not an entity reference.
                Rejected here, at the write, so a malformed grant cannot sit in the store and
                surface as a materialization failure on some unrelated request.
        """
        _check(spec)
        record = GrantRecord(id=uuid4().hex, spec=spec, granted_at=_now(now))
        with self._lock:
            self._grants[record.id] = record
            self._by_principal.setdefault(spec.principal, []).append(record.id)
        return record

    def revoke(
        self,
        grant_id: str,
        *,
        revoked_by: str | None = None,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> GrantRecord:
        """Withdraw a grant, marking the record rather than deleting it.

        Revoking an already-revoked grant returns it unchanged: overwriting the original
        revocation's timestamp and actor would destroy the very fact the record exists to
        preserve.

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
        with self._lock:
            existing = self._grants.get(grant_id)
            if existing is None:
                raise ConfigurationError(
                    f"grant store {self._name!r} holds no grant with id {grant_id!r}"
                )
            if existing.revoked_at is not None:
                return existing
            updated = existing.model_copy(
                update={
                    "revoked_at": _now(now),
                    "revoked_by": revoked_by,
                    "revoked_reason": reason,
                }
            )
            self._grants[grant_id] = updated
            return updated

    def entities(self) -> tuple[Entity, ...]:
        """Return the stable entities this store contributes to the Cedar graph.

        Two sources, in this order: what :meth:`add_entity` seeded, then the nodes the grant
        edges *point at* — ``Role::"support"`` for a role grant, the parsed uid for a parent
        grant. Cedar cannot resolve an edge to an entity it has never heard of, so a store
        that held the edges but not their targets would make every relationship policy fail
        for reasons no one could see.

        Derived nodes are contributed whether or not the grant that named them is still
        active: an expired grant removes the *edge*, and churning the base graph as grants
        expire would mean rebuilding the engine on a timer.

        A principal is *never* included. Principals are per-request deltas materialized by
        :meth:`get_principal`; a snapshot of one in the shared base graph is exactly how one
        principal's roles end up in another principal's decision.
        """
        with self._lock:
            graph: dict[EntityRef, Entity] = dict(self._entities)
            principals = set(self._by_principal)
            for record in self._grants.values():
                target = _edge_target(record.spec)
                if target is not None and target not in principals:
                    graph.setdefault(target, Entity(uid=target))
            return tuple(graph.values())


@register_audit_sink("memory")
class InMemoryAuditSink:
    """Audit records held in a list. For tests and for seeing the write path run.

    Satisfies the whole :class:`~sentrykit.stores.base.AuditSink` contract, including
    :meth:`query`, so a report written against this sink runs unchanged against a durable
    one. It is not durable and does not pretend to be.

    Args:
        name: Short name for this sink, used in fan-out error reporting.
    """

    __slots__ = ("_lock", "_name", "_records")

    def __init__(self, *, name: str = "memory") -> None:
        self._name = name
        self._records: list[AuthzAuditRecord] = []
        self._lock = threading.Lock()

    @classmethod
    def from_dsn(cls, dsn: DSN) -> InMemoryAuditSink:
        """Build from ``memory://<name>``. Each call is a separate, empty sink."""
        return cls(name=dsn.option("name") or dsn.target.strip() or dsn.scheme)

    @property
    def name(self) -> str:
        """Short name for this sink, used in fan-out error reporting."""
        return self._name

    @property
    def records(self) -> tuple[AuthzAuditRecord, ...]:
        """Everything written so far, oldest first.

        A tuple rather than the live list, so a test holding the result cannot append to the
        log it is asserting about.
        """
        with self._lock:
            return tuple(self._records)

    def write(self, record: AuthzAuditRecord) -> None:
        """Append one already-masked, already-chained record."""
        with self._lock:
            self._records.append(record)

    def query(self, window: AuditWindow) -> Iterator[AuthzAuditRecord]:
        """Read back the records matching ``window``, oldest first.

        Matching runs over a snapshot taken under the lock, so a concurrent write cannot make
        the iterator skip or repeat a record.
        """
        with self._lock:
            snapshot = tuple(self._records)
        matched: list[AuthzAuditRecord] = []
        for record in snapshot:
            if not window.matches(record):
                continue
            matched.append(record)
            if window.limit is not None and len(matched) >= window.limit:
                break
        return iter(matched)


class InMemoryTokenVault:
    """The reversible mapping behind ``tokenize`` masking, held in a dict.

    Satisfies :class:`~sentrykit.masking.TokenVault`. Deliberately *not* an audit sink: the
    whole reason the two are separate is that this half must stay mutable, so an erasure
    request can drop a mapping and leave the hash chain intact but no longer resolvable.

    Tokens are minted per ``(field, value)`` pair rather than per value, for the same reason
    :class:`~sentrykit.masking.HmacStrategy` binds its digest to the field name: the same
    string appearing as ``customer_id`` and as ``note`` should not become correlatable just
    because it was tokenized.
    """

    __slots__ = ("_lock", "_tokens", "_values")

    def __init__(self) -> None:
        self._tokens: dict[tuple[str, str], str] = {}
        self._values: dict[str, str] = {}
        self._lock = threading.Lock()

    def tokenize(self, value: str, *, field: str) -> str:
        """Return a stable token for ``value``, minting one if this is the first sighting.

        Args:
            value: The raw value.
            field: The argument name the value appeared under.

        Returns:
            The token, without the ``token:`` prefix — that is the strategy's to add.
        """
        key = (field, value)
        with self._lock:
            token = self._tokens.get(key)
            if token is None:
                token = uuid4().hex
                self._tokens[key] = token
                self._values[token] = value
            return token

    def resolve(self, token: str) -> str | None:
        """Return the raw value behind ``token``, or ``None`` if it is unknown or erased.

        Accepts the token either bare or with the ``token:`` prefix it carries in an audit
        record, so an auditor can paste what they see in the log.
        """
        with self._lock:
            return self._values.get(_bare_token(token))

    def erase(self, token: str) -> bool:
        """Forget one mapping, satisfying an erasure request.

        The audit records keep their tokens and their hashes — the chain stays intact and
        still verifies — but the token no longer resolves to anything.

        Args:
            token: The token, bare or prefixed.

        Returns:
            Whether a mapping was actually removed.
        """
        bare = _bare_token(token)
        with self._lock:
            if self._values.pop(bare, None) is None:
                return False
            for key, held in list(self._tokens.items()):
                if held == bare:
                    del self._tokens[key]
            return True


def _now(now: datetime | None) -> datetime:
    """Resolve a caller-supplied moment, defaulting to the current UTC time."""
    return now if now is not None else datetime.now(UTC)


def _bare_token(token: str) -> str:
    """Strip the ``token:`` prefix a masked record carries, if it is there."""
    return token[len(TOKEN_PREFIX) :] if token.startswith(TOKEN_PREFIX) else token


def _edge_target(spec: GrantSpec) -> EntityRef | None:
    """The entity a grant's parent edge points at, or ``None`` when it is not an edge.

    A ``role`` grant is the shorthand for a ``Role::"<subject>"`` edge, so it names a node
    just as much as an explicit ``parent`` grant does. Attribute and constraint grants name
    nothing.
    """
    if spec.kind == "role":
        return EntityRef("Role", spec.subject)
    if spec.kind == "parent":
        return EntityRef.parse(spec.subject)
    return None


def _check(spec: GrantSpec) -> None:
    """Reject a grant that could not be materialized later.

    Args:
        spec: The grant to check.

    Raises:
        ConfigurationError: If the subject is empty, a ``constraint`` grant carries no
            constraint, or a ``parent`` grant's subject is not a Cedar entity reference.
    """
    if not spec.subject.strip():
        raise ConfigurationError(f"a {spec.kind!r} grant needs a non-empty subject")
    if spec.kind == "constraint" and spec.constraint is None:
        raise ConfigurationError(
            f"a 'constraint' grant for argument {spec.subject!r} carries no constraint"
        )
    if spec.kind == "parent":
        # Raises ConfigurationError on a bare id, which is the point: a parent edge has to
        # name the entity type or Cedar cannot resolve the relationship it stands for.
        EntityRef.parse(spec.subject)
