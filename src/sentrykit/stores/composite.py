"""Many backends behind one Protocol — the second half of the plugin mechanism.

Multiplicity never reaches the core. Configure three audit sinks and the governor still holds
exactly one :class:`~sentrykit.stores.base.AuditSink`; configure two policy directories and it
still holds one :class:`~sentrykit.stores.base.PolicySource`. Each composite *is-a* the
Protocol it composes, so "how many are configured" is a wiring question that
:mod:`sentrykit.registry` answers once and nothing downstream can ask again.

The three compose differently, because the three stores guarantee different things:

* **Policy sources union.** Their bundles are concatenated in a fixed order and reparsed as
  one policy text. There is deliberately **no source precedence, and no "later source wins"
  rule**: in Cedar an override is expressed as a ``forbid``, and forbid always beats permit
  no matter where either policy sits in the text. That property is exactly what makes
  merging sources safe at all. Ordering is fixed only because Cedar numbers policies
  *positionally*, so the provenance index and the engine must be built from one identical
  string.
* **Grant stores merge or route.** Merge-by-precedence when the members are overlapping views
  of the same population (earlier members win per field); route-by-namespace when every member
  declares one and each owns a disjoint population.
* **Audit sinks fan out.** Every sink is attempted on every record, under an explicit error
  policy that says which failures are allowed to refuse production traffic.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final, Literal

from sentrykit.cedar import Entity, EntityRef
from sentrykit.constraints import ConstraintSet
from sentrykit.context import Principal
from sentrykit.errors import AuditUnavailable, ConfigurationError
from sentrykit.stores.base import (
    AuditSink,
    AuditWindow,
    GrantRecord,
    GrantSpec,
    GrantStore,
    PolicyBundle,
    PolicyProvenance,
    PolicySource,
    SupportsClose,
)

if TYPE_CHECKING:  # pragma: no cover - imported for annotations only
    from sentrykit.audit import AuthzAuditRecord

__all__ = [
    "AUDIT_ERROR_POLICIES",
    "AuditErrorPolicy",
    "CompositeAuditSink",
    "CompositeGrantStore",
    "CompositePolicySource",
]

_LOGGER: Final = logging.getLogger("sentrykit.stores.composite")

AuditErrorPolicy = Literal["primary-durable", "all-or-nothing"]
"""How a fan-out reacts when a member sink refuses a record. See :class:`CompositeAuditSink`."""

AUDIT_ERROR_POLICIES: Final[Mapping[str, AuditErrorPolicy]] = {
    "primary-durable": "primary-durable",
    "all-or-nothing": "all-or-nothing",
}
"""The valid ``?on_error=`` values, so the registry can validate a DSN option against them."""


# --- policy sources ----------------------------------------------------------------------


class CompositePolicySource:
    """Several policy sources, unioned into one bundle.

    The union is a **concatenation, not a precedence chain**. Ordering the members cannot
    change a decision: an override is a Cedar ``forbid``, and forbid wins wherever it sits.
    The order is fixed anyway because Cedar's generated policy ids (``policy0``, ``policy1``)
    are positional in the text it parsed — so the combined text is built once, and the
    provenance index is derived from *that* string rather than reassembled from the members'.

    Each member's declared ``@id`` is namespaced as ``<source-name>/<id>`` in the provenance
    index. Cedar does not enforce ``@id`` uniqueness — two sources may both declare
    ``@id("btg-read")`` and it parses without complaint — so the namespacing is sentrykit's
    hygiene, and it is what keeps a decision's determining policies attributable to one
    artifact. It is applied to the index rather than to the policy text, so Cedar keeps
    reporting the raw ``@id``; :meth:`~sentrykit.stores.base.PolicyBundle.provenance_for`
    resolves both spellings, which is what keeps the join working across a union.

    Args:
        sources: The members, in the order their policies are concatenated.
        name: This composite's name, recorded on the combined bundle.

    Raises:
        ConfigurationError: If no sources were given, or if two of them share a name — the
            name *is* the namespace, so duplicates would defeat the disambiguation.
    """

    __slots__ = ("_name", "_sources")

    def __init__(self, sources: Sequence[PolicySource], *, name: str = "composite") -> None:
        if not sources:
            raise ConfigurationError("a composite policy source needs at least one member source")
        seen: dict[str, None] = {}
        for source in sources:
            if source.name in seen:
                raise ConfigurationError(
                    f"two policy sources are both named {source.name!r}; names namespace "
                    "policy ids, so they must be distinct"
                )
            seen[source.name] = None
        self._sources = tuple(sources)
        self._name = name

    @property
    def name(self) -> str:
        """This composite's name."""
        return self._name

    @property
    def sources(self) -> tuple[PolicySource, ...]:
        """The members, in concatenation order."""
        return self._sources

    def load(self) -> PolicyBundle:
        """Load every member and union them into one bundle.

        Returns:
            The combined bundle: every member's policy text concatenated in order, every
            member's entities unioned, and one provenance entry per policy carrying the
            member that contributed it and that member's namespaced policy id.

        Raises:
            ConfigurationError: If a member fails to load, if the combined text does not
                parse, or if two members contribute conflicting definitions of one entity.
        """
        bundles = [source.load() for source in self._sources]
        fragments = [bundle.policies.strip() for bundle in bundles]
        # One concatenation, parsed once. Everything downstream -- the engine, the generated
        # ids, the provenance index -- is derived from this single string, because Cedar
        # numbers policies positionally and an index built from anything else mis-joins.
        combined = PolicyBundle.from_text(
            "\n\n".join(fragment for fragment in fragments if fragment),
            schema=self._combined_schema(bundles),
            entities=self._combined_entities(bundles),
            source=self._name,
        )
        counts = [len(bundle.provenance) for bundle in bundles]
        return replace(combined, provenance=self._attributed(combined.provenance, counts, bundles))

    def current_hash(self) -> str:
        """Return the digest of the bundle :meth:`load` would return right now.

        The union's hash covers the *concatenated* text, so — unlike a single source, which
        can usually stat a file — there is no shortcut: the combined string does not exist
        until every member has been read. Polling a union therefore costs a load, which is
        the price of the contract that a bundle hash pins exactly the logic a decision was
        made against.
        """
        return self.load().bundle_hash

    @staticmethod
    def _combined_schema(bundles: Sequence[PolicyBundle]) -> str | None:
        """Concatenate the members' schema fragments, dropping exact repeats.

        Two sources shipping the same ``.cedarschema`` is the common case and must not become
        a duplicate-declaration error; two sources declaring the *same entity type differently*
        is a genuine conflict, and Cedar reports it when the bundle builds its engine.
        """
        fragments: list[str] = []
        for bundle in bundles:
            if bundle.schema and bundle.schema not in fragments:
                fragments.append(bundle.schema)
        return "\n\n".join(fragments) if fragments else None

    def _combined_entities(self, bundles: Sequence[PolicyBundle]) -> tuple[Entity, ...]:
        """Union the members' entity graphs.

        Raises:
            ConfigurationError: If two members contribute the same uid with different content.
                Identical contributions are fine — two sources may legitimately both declare
                ``Role::"admin"`` — but a divergent one would make the graph ambiguous, and
                which of the two won would decide requests.
        """
        merged: dict[EntityRef, Entity] = {}
        contributors: dict[EntityRef, str] = {}
        for source, bundle in zip(self._sources, bundles, strict=True):
            for entity in bundle.entities:
                existing = merged.get(entity.uid)
                if existing is None:
                    merged[entity.uid] = entity
                    contributors[entity.uid] = source.name
                elif existing != entity:
                    raise ConfigurationError(
                        f"entity {entity.uid} is defined differently by policy sources "
                        f"{contributors[entity.uid]!r} and {source.name!r}; "
                        "the entity graph would be ambiguous"
                    )
        return tuple(merged.values())

    def _attributed(
        self,
        provenance: Sequence[PolicyProvenance],
        counts: Sequence[int],
        bundles: Sequence[PolicyBundle],
    ) -> tuple[PolicyProvenance, ...]:
        """Re-attach each combined provenance entry to the member that contributed it.

        The combined entries carry the ids and annotations Cedar will report, because they
        were read from the combined text. What they cannot know is *which artifact* each
        policy came from — so the member's ``source`` and ``origin`` are stitched back on
        positionally, using how many policies each member contributed.
        """
        attributed: list[PolicyProvenance] = []
        offset = 0
        for source, bundle, count in zip(self._sources, bundles, counts, strict=True):
            for local in range(count):
                if offset + local >= len(provenance):  # pragma: no cover - defensive
                    break
                entry = provenance[offset + local]
                origin = bundle.provenance[local].origin if local < len(bundle.provenance) else ""
                attributed.append(
                    replace(
                        entry,
                        policy_id=_namespaced_id(source.name, entry),
                        source=source.name,
                        origin=origin,
                    )
                )
            offset += count
        attributed.extend(provenance[offset:])
        return tuple(attributed)


def _namespaced_id(source: str, entry: PolicyProvenance) -> str:
    """Namespace one declared policy id, idempotently.

    A policy that declares no ``@id`` keeps Cedar's generated id, which is positional in the
    combined text and therefore already unique across the union. An id that already carries
    this source's prefix — a member that is itself namespaced, or a nested composite — is left
    alone rather than prefixed twice.
    """
    if entry.policy_id == entry.cedar_id:
        return entry.cedar_id
    prefix = f"{source}/"
    return entry.policy_id if entry.policy_id.startswith(prefix) else prefix + entry.policy_id


# --- grant stores ------------------------------------------------------------------------


class CompositeGrantStore:
    """Several grant stores, either merged by precedence or routed by namespace.

    Which one it is is not configured — it is inferred, because the two arrangements are
    distinguishable by what the members declare. If **every** member exposes a non-empty
    ``namespace`` attribute, the members own disjoint populations and lookups **route**: a
    principal whose id or entity type is prefixed ``<namespace>:`` goes to exactly one store.
    Otherwise the members are overlapping views of one population and lookups **merge**, with
    earlier members winning.

    Merging is per field, not per store: a principal known to two stores comes back with their
    roles and parents unioned (order preserving, de-duplicated) and their attributes and
    per-action constraint sets layered with the earlier store on top. That is what lets a
    local override store sit in front of a corporate directory without either having to know
    about the other.

    Args:
        stores: The members, in precedence order.
        name: This composite's name.

    Raises:
        ConfigurationError: If no stores were given, or if two of them claim one namespace.
    """

    __slots__ = ("_name", "_routed", "_routes", "_stores")

    def __init__(self, stores: Sequence[GrantStore], *, name: str = "composite") -> None:
        if not stores:
            raise ConfigurationError("a composite grant store needs at least one member store")
        self._stores = tuple(stores)
        self._name = name
        namespaces = [_namespace_of(store) for store in self._stores]
        self._routed = all(namespace is not None for namespace in namespaces)
        self._routes: dict[str, GrantStore] = {}
        if self._routed:
            for store, namespace in zip(self._stores, namespaces, strict=True):
                if namespace is None:  # pragma: no cover - excluded by ``self._routed``
                    continue
                claimed = self._routes.get(namespace)
                if claimed is not None:
                    raise ConfigurationError(
                        f"grant stores {claimed.name!r} and {store.name!r} both claim "
                        f"namespace {namespace!r}; routing would be ambiguous"
                    )
                self._routes[namespace] = store

    @property
    def name(self) -> str:
        """This composite's name."""
        return self._name

    @property
    def stores(self) -> tuple[GrantStore, ...]:
        """The members, in precedence order."""
        return self._stores

    @property
    def routed(self) -> bool:
        """Whether lookups route by namespace rather than merging by precedence."""
        return self._routed

    def get_principal(
        self,
        principal: str | EntityRef,
        *,
        now: datetime | None = None,
    ) -> Principal | None:
        """Materialize a principal from the routed store, or from every store merged.

        Args:
            principal: The principal id (assumed type ``User``) or a full reference.
            now: The moment expiries are evaluated against.

        Returns:
            The principal, or ``None`` when **no** member knows them — one member returning
            ``None`` is not an answer, it is an absence, and the caller fails closed only when
            every member is silent.
        """
        if self._routed:
            return self._route(principal).get_principal(principal, now=now)
        found = [
            known
            for known in (store.get_principal(principal, now=now) for store in self._stores)
            if known is not None
        ]
        if not found:
            return None
        if len(found) == 1:
            return found[0]
        return _merged_principal(found)

    def grants_for(
        self,
        principal: str | EntityRef,
        *,
        include_inactive: bool = False,
    ) -> tuple[GrantRecord, ...]:
        """List the grants held by ``principal``, oldest first, across every member.

        Args:
            principal: The principal id or reference.
            include_inactive: Whether to include revoked and expired grants.

        Returns:
            The grants. Members are expected to timestamp in UTC, which is what makes one
            ordering across several stores meaningful.
        """
        if self._routed:
            return self._route(principal).grants_for(principal, include_inactive=include_inactive)
        records: list[GrantRecord] = []
        for store in self._stores:
            records.extend(store.grants_for(principal, include_inactive=include_inactive))
        return tuple(sorted(records, key=lambda record: record.granted_at))

    def grant(self, spec: GrantSpec, *, now: datetime | None = None) -> GrantRecord:
        """Confer a grant on the store that owns the principal.

        Args:
            spec: What to confer.
            now: The grant timestamp.

        Returns:
            The stored record.

        Raises:
            ConfigurationError: If routing is in effect and no member owns the principal's
                namespace, or if the owning store rejects the spec.
        """
        if self._routed:
            return self._route(spec.principal).grant(spec, now=now)
        # Merge mode has a precedence order, and the front of it is the store a host put there
        # to hold its own writes -- writing to the corporate directory behind it would be a
        # surprise, and often a read-only one.
        return self._stores[0].grant(spec, now=now)

    def revoke(
        self,
        grant_id: str,
        *,
        revoked_by: str | None = None,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> GrantRecord:
        """Withdraw a grant from whichever member holds it.

        A grant id names no principal, so there is nothing to route on even when routing is in
        effect: the members are probed in order and the first one holding the id performs the
        revocation.

        Args:
            grant_id: The id returned by :meth:`grant`.
            revoked_by: The actor withdrawing it.
            reason: Why.
            now: The revocation timestamp.

        Returns:
            The updated record.

        Raises:
            ConfigurationError: If no member holds that grant.
        """
        for store in self._stores:
            try:
                return store.revoke(grant_id, revoked_by=revoked_by, reason=reason, now=now)
            except ConfigurationError:
                continue
        known = ", ".join(store.name for store in self._stores)
        raise ConfigurationError(f"no grant store holds grant {grant_id!r}; tried: {known}")

    def entities(self) -> tuple[Entity, ...]:
        """Union the stable entities every member contributes, first definition winning."""
        merged: dict[EntityRef, Entity] = {}
        for store in self._stores:
            for entity in store.entities():
                merged.setdefault(entity.uid, entity)
        return tuple(merged.values())

    def _route(self, principal: str | EntityRef | Principal) -> GrantStore:
        """Find the member owning ``principal``.

        Both spellings of a namespace are accepted, because both occur in practice: an id
        prefix (``acme:alice``) and a Cedar type namespace (``Acme::User``, whose ``Acme::``
        starts with ``Acme:``).

        Raises:
            ConfigurationError: If no member claims a matching namespace. Guessing at a
                default would send one tenant's grants to another tenant's store.
        """
        reference = _reference_of(principal)
        for candidate in (reference.id, reference.type):
            prefix, separator, _ = candidate.partition(":")
            if separator and prefix in self._routes:
                return self._routes[prefix]
        known = ", ".join(sorted(self._routes)) or "none"
        raise ConfigurationError(
            f"no grant store handles principal {reference}; known namespaces: {known}"
        )


def _namespace_of(store: GrantStore) -> str | None:
    """Read a store's optional ``namespace``.

    Optional on purpose: the :class:`~sentrykit.stores.base.GrantStore` Protocol does not
    require it, because a store serving the whole population has no namespace to declare, and
    demanding ``namespace = None`` from every third-party backend would be contract for
    contract's sake.
    """
    namespace = getattr(store, "namespace", None)
    return namespace if isinstance(namespace, str) and namespace else None


def _reference_of(principal: str | EntityRef | Principal) -> EntityRef:
    """Normalize the three ways a principal can be named into an entity reference."""
    if isinstance(principal, Principal):
        return principal.uid
    return EntityRef.parse(principal, default_type="User")


def _merged_principal(found: Sequence[Principal]) -> Principal:
    """Layer several views of one principal, earlier winning.

    Roles and parents union — a role granted by any store is held — while attributes and
    constraint sets are layered, so an earlier store's ``region`` or its narrower constraint
    on one argument overrides a later store's.
    """
    roles: dict[str, None] = {}
    parents: dict[EntityRef, None] = {}
    for principal in found:
        for role in principal.roles:
            roles.setdefault(role, None)
        for parent in principal.parents:
            parents.setdefault(parent, None)

    attributes: dict[str, object] = {}
    constraints: dict[str, ConstraintSet] = {}
    # Walk back to front so each earlier store overwrites what the later ones said.
    for principal in reversed(found):
        attributes.update(principal.attributes)
        for action, layer in principal.constraints.items():
            beneath = constraints.get(action)
            constraints[action] = layer if beneath is None else beneath.merged_with(layer)

    return Principal(
        id=found[0].id,
        type=found[0].type,
        roles=tuple(roles),
        parents=tuple(parents),
        attributes=attributes,
        constraints=constraints,
    )


# --- audit sinks -------------------------------------------------------------------------


class CompositeAuditSink:
    """Several audit sinks, written to on every record.

    Every member is attempted before anything is raised, so one dead sink can never hide the
    state of the rest — an operator reading the failure needs to know whether one replica is
    down or all of them are. What happens next is the error policy:

    * ``primary-durable`` — the **first** sink is the record of truth and must succeed; its
      failure raises :class:`~sentrykit.errors.AuditUnavailable`, which under
      ``fail_mode="closed"`` refuses the governed call. A failure in any other member is
      logged at ``ERROR`` and swallowed: a replica or a search index being unreachable is an
      operational problem, not a reason to refuse production traffic.
    * ``all-or-nothing`` — any failure raises, carrying one ``failures`` entry per failed sink.
      This is **not a transaction**: sinks that already accepted the record keep it, and
      append-only storage has nothing to roll back to. The guarantee is "you will be told
      that the copies diverged", not "nothing was written".

    Args:
        sinks: The members. The first is the primary under ``primary-durable``.
        on_error: The error policy.
        name: This composite's name, used when reporting a fan-out failure.

    Raises:
        ConfigurationError: If no sinks were given or ``on_error`` is not a known policy.
    """

    __slots__ = ("_name", "_on_error", "_sinks")

    def __init__(
        self,
        sinks: Sequence[AuditSink],
        *,
        on_error: AuditErrorPolicy = "primary-durable",
        name: str = "composite",
    ) -> None:
        if not sinks:
            raise ConfigurationError("a composite audit sink needs at least one member sink")
        if on_error not in AUDIT_ERROR_POLICIES:
            known = ", ".join(sorted(AUDIT_ERROR_POLICIES))
            raise ConfigurationError(f"on_error is {on_error!r}; expected one of {known}")
        self._sinks = tuple(sinks)
        self._on_error = on_error
        self._name = name

    @property
    def name(self) -> str:
        """This composite's name."""
        return self._name

    @property
    def sinks(self) -> tuple[AuditSink, ...]:
        """The members. The first is the primary."""
        return self._sinks

    @property
    def on_error(self) -> AuditErrorPolicy:
        """How this fan-out reacts to a member failing."""
        return self._on_error

    def write(self, record: AuthzAuditRecord) -> None:
        """Append ``record`` to every member.

        Args:
            record: The record, already masked and already chained.

        Raises:
            AuditUnavailable: Under ``primary-durable`` when the first sink failed, and under
                ``all-or-nothing`` when any sink did. ``failures`` carries one entry per
                failed member either way.
        """
        failures: list[dict[str, Any]] = []
        primary: Exception | None = None
        for position, sink in enumerate(self._sinks):
            try:
                sink.write(record)
            except Exception as exc:
                # A sink is arbitrary backend code -- a socket, a file, a stranger's library.
                # Anything it raises is a write that did not happen, and the policy below is
                # what decides whether that refuses the governed call.
                _LOGGER.error(
                    "Audit sink %r did not accept record %s: %s", sink.name, record.record_id, exc
                )
                failures.append({"sink": sink.name, "error": str(exc), "type": type(exc).__name__})
                if position == 0:
                    primary = exc
        if not failures:
            return
        if self._on_error == "primary-durable":
            if primary is None:
                return
            raise AuditUnavailable(self._sinks[0].name, str(primary), failures) from primary
        raise AuditUnavailable(
            self._name,
            f"{len(failures)} of {len(self._sinks)} sinks did not accept the record",
            failures,
        )

    def query(self, window: AuditWindow) -> Iterator[AuthzAuditRecord]:
        """Read back matching records **from the first sink only**.

        A fan-out writes the same record to every member, so reading from all of them would
        return each record once per sink. De-duplicating by ``record_hash`` would look tidier
        and would be worse: it would silently paper over a divergence between two copies of an
        allegedly tamper-evident log, which is precisely the thing an auditor came to find.
        Reading one sink at a time keeps a comparison possible.

        Args:
            window: The filter.

        Returns:
            The primary sink's matching records, oldest first.
        """
        return self._sinks[0].query(window)

    def close(self) -> None:
        """Close every member that holds a resource.

        Failures are logged rather than raised: close is cleanup, and one member's failure to
        release a handle must not stop the others from releasing theirs.
        """
        for sink in self._sinks:
            if not isinstance(sink, SupportsClose):
                continue
            try:
                sink.close()
            except Exception as exc:
                _LOGGER.error("Audit sink %r failed to close: %s", sink.name, exc)
