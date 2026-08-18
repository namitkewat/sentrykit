"""Thin wrapper over ``cedarpy`` — the only module in sentrykit that imports Cedar.

Everything else in the core talks to :class:`CedarDecision`, a normalized value object, so
the decision path stays unit-testable without a policy set and so a future engine binding
(see ADR-002 on partial evaluation) can be swapped in behind this seam.

Three things this module owns that callers should not re-implement:

1. **Pre-parsed handles.** ``cedarpy`` exposes reusable ``PolicySet`` / ``Entities`` /
   ``Schema`` handles. :class:`PolicyEngine` parses once at construction — so a bad policy
   raises :class:`~sentrykit.errors.ConfigurationError` at wiring time rather than silently
   denying every request at runtime — and reuses the handles per call.
2. **Determining-policy naming.** Cedar reports parser-generated ids (``policy0``) in its
   diagnostics; the human-meaningful name is the policy's ``@id("...")`` annotation.
   :attr:`CedarDecision.determining_policies` carries the annotation when one exists and the
   generated id otherwise, so denial messages and audit records stay readable.
3. **Value coercion.** Cedar's type system has no floating-point and no null. A stray
   ``None`` in the request context turns the whole decision into ``NoDecision``, and a
   ``None`` in an entity attribute makes the entity set fail to parse outright. Every value
   handed to Cedar passes through :func:`coerce_value` first.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Final, Literal, NamedTuple

import cedarpy

from sentrykit.errors import ConfigurationError

__all__ = [
    "CedarDecision",
    "CedarRequest",
    "Entity",
    "EntityRef",
    "PolicyAnnotation",
    "PolicyEngine",
    "coerce_value",
    "policy_annotations",
]

_LOGGER: Final = logging.getLogger("sentrykit.cedar")

_UID_RE: Final = re.compile(
    r'^(?P<type>[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)::"(?P<id>.*)"$'
)

DecisionLiteral = Literal["allow", "deny", "no-decision"]
"""Normalized spelling of Cedar's ``Allow`` / ``Deny`` / ``NoDecision``."""

_DECISIONS: Final[dict[cedarpy.Decision, DecisionLiteral]] = {
    cedarpy.Decision.Allow: "allow",
    cedarpy.Decision.Deny: "deny",
    cedarpy.Decision.NoDecision: "no-decision",
}


class EntityRef(NamedTuple):
    """A Cedar entity reference — an entity type plus an id.

    Rendered as ``Type::"id"`` and sent to Cedar in its structured ``{"type", "id"}`` form,
    which sidesteps the surface-syntax normalization rules that would otherwise reject ids
    containing awkward characters. That matters because resource ids reach us from callers
    and from language models.
    """

    type: str
    id: str

    @classmethod
    def parse(cls, value: str | EntityRef, *, default_type: str | None = None) -> EntityRef:
        """Parse ``Type::"id"``, or a bare id when ``default_type`` is supplied.

        Args:
            value: A Cedar uid string, a bare id, or an already-parsed reference.
            default_type: Entity type to assume when ``value`` carries no ``Type::`` prefix.

        Returns:
            The parsed reference.

        Raises:
            ConfigurationError: If ``value`` has no type prefix and no ``default_type`` was
                given, or if it is malformed.
        """
        if isinstance(value, EntityRef):
            return value
        match = _UID_RE.match(value)
        if match is not None:
            return cls(match.group("type"), match.group("id"))
        if default_type is not None and "::" not in value:
            return cls(default_type, value)
        raise ConfigurationError(
            f'cannot parse entity reference {value!r}; expected Type::"id"'
            + ("" if default_type is not None else " (no default entity type was supplied)")
        )

    def __str__(self) -> str:
        """Render the Cedar surface form, ``Type::"id"``."""
        return f'{self.type}::"{self.id}"'

    def as_json(self) -> dict[str, str]:
        """Return the structured ``{"type": ..., "id": ...}`` form ``cedarpy`` accepts."""
        return {"type": self.type, "id": self.id}


@dataclass(frozen=True, slots=True)
class Entity:
    """One node of the Cedar entity graph.

    Args:
        uid: This entity's reference.
        attributes: Cedar attributes. Values are coerced by :func:`coerce_value`, so
            ``None`` entries are dropped rather than making the entity set unparseable.
        parents: Direct parent edges. Cedar computes the transitive closure, so a role, a
            team and a delegation edge are all just parents — this is the mechanism that
            lets multi-hop relationships be resolved by policy instead of by application
            code.
    """

    uid: EntityRef
    attributes: Mapping[str, object] = field(default_factory=dict)
    parents: tuple[EntityRef, ...] = ()

    def as_json(self) -> dict[str, object]:
        """Return the Cedar entity-JSON form: ``{"uid", "attrs", "parents"}``."""
        return {
            "uid": self.uid.as_json(),
            "attrs": _coerce_mapping(self.attributes),
            "parents": [parent.as_json() for parent in self.parents],
        }


@dataclass(frozen=True, slots=True)
class CedarRequest:
    """One authorization question, in sentrykit's own terms.

    Args:
        principal: Who is acting.
        action: What they propose to do.
        resource: What they propose to do it to.
        context: Cedar request context — ``now``, ``channel``, the proposed arguments, and
            whatever else the provider established. Coerced before evaluation.
        entities: Per-request entities merged on top of the engine's base graph, typically
            the principal snapshot. A delta entity whose uid duplicates a *different* base
            entity is an error, so the base graph should hold only stable, shared nodes.
        correlation_id: Invocation id, echoed back on the decision so operational logs, the
            Cedar result and the audit record share one key.
    """

    principal: EntityRef
    action: EntityRef
    resource: EntityRef
    context: Mapping[str, object] = field(default_factory=dict)
    entities: tuple[Entity, ...] = ()
    correlation_id: str | None = None


@dataclass(frozen=True, slots=True)
class CedarDecision:
    """A Cedar authorization result, normalized.

    Attributes:
        allowed: Whether Cedar returned ``Allow``. ``Deny`` and ``NoDecision`` are both
            ``False``; read :attr:`decision` to tell them apart.
        decision: The raw verdict, lower-cased.
        determining_policies: The policies that decided it, named by their ``@id``
            annotation where they declare one. Empty on a default deny — which is itself
            diagnostic: it means no policy matched at all.
        errors: Cedar parse or evaluation errors. Cedar folds these into the result instead
            of raising; a non-empty list is an *engine failure*, distinct from a policy
            denial, and is what ``fail_mode`` arbitrates.
        correlation_id: Echoed from the request.
        policy_set_hash: Digest of the policy text the decision was evaluated against, so a
            decision can be replayed later against the same logic.
    """

    allowed: bool
    decision: DecisionLiteral
    determining_policies: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    correlation_id: str | None = None
    policy_set_hash: str = ""

    @property
    def failed(self) -> bool:
        """Whether the engine failed, as opposed to reaching a clean allow or deny."""
        return bool(self.errors) or self.decision == "no-decision"

    def as_trace(self) -> dict[str, object]:
        """Render the decision for the envelope's debug trace and the audit record."""
        return {
            "allowed": self.allowed,
            "decision": self.decision,
            "determining_policies": list(self.determining_policies),
            "errors": list(self.errors),
            "correlation_id": self.correlation_id,
            "policy_set_hash": self.policy_set_hash,
        }


class PolicyEngine:
    """A parsed, reusable Cedar policy set plus a base entity graph.

    Phase 1's in-memory policy source: hand it policy text and the stable entities, and it
    answers questions. Phase 2 replaces *where the text comes from* (``PolicySource``,
    ``GrantStore``) without changing this class.

    Args:
        policies: Cedar policy text. Parsed eagerly.
        entities: The stable part of the entity graph — roles, teams, resources. Per-request
            entities such as the principal snapshot go on :class:`CedarRequest` instead.
        schema: Optional Cedar schema text, used to validate entities and requests.

    Raises:
        ConfigurationError: If the policies, entities or schema fail to parse.
    """

    __slots__ = ("_entity_handle", "_hash", "_policies", "_policy_set", "_schema", "_schema_text")

    _policies: str
    _schema_text: str | None
    _policy_set: cedarpy.PolicySet
    _entity_handle: cedarpy.Entities
    _schema: cedarpy.Schema | None
    _hash: str

    def __init__(
        self,
        policies: str,
        entities: Sequence[Entity] = (),
        *,
        schema: str | None = None,
    ) -> None:
        try:
            policy_set = cedarpy.PolicySet.from_str(policies)
        except ValueError as exc:
            raise ConfigurationError(f"cedar policy set failed to parse: {exc}") from exc

        try:
            entity_handle = cedarpy.Entities.from_json_str(_entities_json(entities))
        except ValueError as exc:
            raise ConfigurationError(f"cedar entities failed to parse: {exc}") from exc

        parsed_schema: cedarpy.Schema | None = None
        if schema is not None:
            try:
                parsed_schema = cedarpy.Schema.from_str(schema)
            except ValueError as exc:
                raise ConfigurationError(f"cedar schema failed to parse: {exc}") from exc

        self._policies = policies
        self._schema_text = schema
        self._policy_set = policy_set
        self._entity_handle = entity_handle
        self._schema = parsed_schema
        self._hash = _policy_set_hash(policies, schema)

    @classmethod
    def _rebound(cls, source: PolicyEngine, entity_handle: cedarpy.Entities) -> PolicyEngine:
        """Build an engine sharing ``source``'s parsed policy set and schema.

        Bypasses ``__init__`` deliberately: re-running it would re-parse policy text that is
        already known good, which is the cost :meth:`with_entities` exists to avoid.
        """
        engine = cls.__new__(cls)
        engine._policies = source._policies
        engine._schema_text = source._schema_text
        engine._policy_set = source._policy_set
        engine._entity_handle = entity_handle
        engine._schema = source._schema
        engine._hash = source._hash
        return engine

    @property
    def policy_set_hash(self) -> str:
        """Stable digest of the policy text and schema this engine evaluates against."""
        return self._hash

    @property
    def policies(self) -> str:
        """The Cedar policy text this engine was built from."""
        return self._policies

    def with_entities(self, entities: Iterable[Entity]) -> PolicyEngine:
        """Return a new engine with ``entities`` added to the base graph.

        The receiver is unchanged and its parsed handles are reused, so this is cheap enough
        to call when a tenant's entities are loaded alongside the shared ones.
        """
        added = tuple(entities)
        if not added:
            return self
        try:
            entity_handle = self._entity_handle.with_added_json_str(_entities_json(added))
        except ValueError as exc:
            raise ConfigurationError(f"cedar entities failed to merge: {exc}") from exc
        return self._rebound(self, entity_handle)

    def evaluate(self, request: CedarRequest) -> CedarDecision:
        """Ask Cedar whether ``request`` is authorized.

        Never raises on a denial or on a Cedar evaluation error: both come back on the
        returned decision, because deciding what an engine failure *means* is the
        :class:`~sentrykit.engine.Governor`'s job, governed by ``fail_mode``.

        Args:
            request: The question to answer.

        Returns:
            The normalized decision.

        Raises:
            ConfigurationError: If the request's per-request entities cannot be merged onto
                the base graph — for example a delta uid that duplicates a different base
                entity. That is a wiring fault, not a decision.
        """
        entity_handle = self._entity_handle
        if request.entities:
            try:
                entity_handle = entity_handle.with_added_json_str(_entities_json(request.entities))
            except ValueError as exc:
                raise ConfigurationError(
                    f"per-request cedar entities failed to merge: {exc}"
                ) from exc

        payload: dict[str, object] = {
            "principal": request.principal.as_json(),
            "action": request.action.as_json(),
            "resource": request.resource.as_json(),
            "context": _coerce_mapping(request.context),
        }
        if request.correlation_id is not None:
            payload["correlation_id"] = request.correlation_id

        result = cedarpy.is_authorized(payload, self._policy_set, entity_handle, self._schema)

        decision = _DECISIONS.get(result.decision, "no-decision")
        errors = tuple(result.diagnostics.errors)
        determining = _determining_policies(result.diagnostics)

        if errors:
            # An engine failure, not a policy denial: the operator has a broken policy set or
            # an entity missing an attribute a policy reads. Argument values never appear
            # here -- only ids, the action, and Cedar's own messages.
            _LOGGER.error(
                "cedar evaluation reported errors",
                extra={
                    "correlation_id": request.correlation_id,
                    "action": str(request.action),
                    "decision": decision,
                    "cedar_errors": list(errors),
                    "policy_set_hash": self._hash,
                },
            )
        else:
            _LOGGER.debug(
                "cedar decision",
                extra={
                    "correlation_id": request.correlation_id,
                    "action": str(request.action),
                    "decision": decision,
                    "determining_policies": list(determining),
                    "policy_set_hash": self._hash,
                },
            )

        return CedarDecision(
            allowed=result.allowed,
            decision=decision,
            determining_policies=determining,
            errors=errors,
            correlation_id=request.correlation_id,
            policy_set_hash=self._hash,
        )


def coerce_value(value: object) -> object | None:
    """Coerce a Python value into something Cedar's type system accepts.

    Cedar has integers, booleans, strings, sets, records and entity references — and no
    floating-point type and no null. Feeding it either produces a ``NoDecision`` with the
    unhelpful message ``failed to parse schema from request``, or, in an entity attribute,
    makes the whole entity set fail to parse. Coercing at this boundary is what keeps a
    caller-supplied ``None`` from quietly denying every request.

    The mapping: ``None`` becomes ``None`` and is dropped by the caller; ``bool``, ``int``
    and ``str`` pass through; ``datetime`` and ``date`` become epoch seconds so policies can
    compare them against ``context.now``; ``float`` and ``Decimal`` are rendered as strings,
    since silently truncating them to integers would change what a policy decides;
    ``EntityRef`` becomes Cedar's ``{"__entity": ...}`` form; mappings and sequences recurse,
    dropping any element or entry that coerces to ``None``. Anything else is stringified.

    Naive ``datetime`` values are read as UTC rather than as local time, so a decision does
    not depend on the timezone of the host that happened to evaluate it.

    Args:
        value: The value to coerce.

    Returns:
        A Cedar-safe value, or ``None`` when the value has no Cedar representation and
        should be omitted.
    """
    if value is None:
        return None
    # bool before int: bool is a subclass of int, and Cedar distinguishes the two.
    if isinstance(value, bool | int | str):
        return value
    if isinstance(value, EntityRef):
        return {"__entity": value.as_json()}
    if isinstance(value, Enum):
        return coerce_value(value.value)
    # datetime before date: datetime is a subclass of date.
    if isinstance(value, dt.datetime):
        moment = value if value.tzinfo is not None else value.replace(tzinfo=dt.UTC)
        return int(moment.timestamp())
    if isinstance(value, dt.date):
        return int(dt.datetime.combine(value, dt.time.min, tzinfo=dt.UTC).timestamp())
    # Cedar has no floating-point type. Truncating to int would silently change what a
    # policy decides (a 1.5 threshold becoming 1), so render the exact value as a string.
    if isinstance(value, float | Decimal):
        return str(value)
    if isinstance(value, Mapping):
        return _coerce_mapping({str(key): item for key, item in value.items()})
    if isinstance(value, set | frozenset):
        return _coerce_sequence(sorted(value, key=repr))
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return _coerce_sequence(value)
    return str(value)


def _coerce_mapping(mapping: Mapping[str, object]) -> dict[str, object]:
    """Coerce every value of ``mapping``, dropping the keys with no Cedar representation.

    Dropping rather than substituting is deliberate: Cedar has no null, so a record with a
    ``None`` member is unrepresentable, while a record with the member *absent* is exactly
    what ``has`` tests for in a policy.
    """
    coerced: dict[str, object] = {}
    for key, value in mapping.items():
        item = coerce_value(value)
        if item is not None:
            coerced[str(key)] = item
    return coerced


def _coerce_sequence(values: Iterable[object]) -> list[object]:
    """Coerce every element of ``values``, dropping the ones with no Cedar representation."""
    return [item for item in (coerce_value(value) for value in values) if item is not None]


def _entities_json(entities: Iterable[Entity]) -> str:
    """Render entities as the Cedar entity-JSON document ``cedarpy`` parses."""
    return json.dumps([entity.as_json() for entity in entities])


def _policy_set_hash(policies: str, schema: str | None) -> str:
    """Digest the policy text and schema so a decision can be replayed against the same logic."""
    digest = hashlib.sha256()
    digest.update(policies.encode("utf-8"))
    digest.update(b"\x00")
    digest.update((schema or "").encode("utf-8"))
    return digest.hexdigest()


def _determining_policies(diagnostics: cedarpy.Diagnostics) -> tuple[str, ...]:
    """Name the policies that decided a request, preferring their ``@id`` annotation.

    Cedar's own reasons are parser-generated positional ids (``policy0``), which change when
    an unrelated policy is inserted above. The ``@id("...")`` annotation is the stable,
    human-meaningful name, so it wins wherever a policy declares a non-empty one.
    """
    annotations = diagnostics.id_annotations_by_reason
    named: list[str] = []
    for policy_id in diagnostics.reasons:
        annotation = annotations.get(policy_id)
        named.append(annotation if isinstance(annotation, str) and annotation else policy_id)
    return tuple(named)


@dataclass(frozen=True, slots=True)
class PolicyAnnotation:
    """One policy's identity and annotations, read out of the policy text.

    Cedar's ``PolicySet`` handle is opaque — it cannot be walked — but
    ``cedarpy.policies_to_json_str`` renders the parsed set as JSON carrying *every*
    annotation, not just ``@id``. That is the only way to see an ``@obligations(...)``
    declaration, which is why :func:`policy_annotations` exists and why ADR-012 puts
    obligations in annotations at all.

    Attributes:
        cedar_id: Cedar's generated id (``policy0``). Positional in the policy text, and the
            key that ``diagnostics.reasons`` reports.
        effect: ``permit`` or ``forbid``.
        annotations: Every annotation on the policy. A valueless annotation
            (``@obligations`` with no parentheses) maps to ``None``.
    """

    cedar_id: str
    effect: Literal["permit", "forbid"]
    annotations: Mapping[str, str | None] = field(default_factory=dict)

    @property
    def declared_id(self) -> str:
        """The ``@id`` annotation when the policy declares a non-empty one, else :attr:`cedar_id`.

        Matches how :attr:`CedarDecision.determining_policies` names a policy, so the two can
        be joined.
        """
        declared = self.annotations.get("id")
        return declared if isinstance(declared, str) and declared else self.cedar_id

    def annotation(self, key: str) -> str | None:
        """Return one annotation's value, or ``None`` when it is absent or valueless."""
        value = self.annotations.get(key)
        return value if isinstance(value, str) and value else None


def policy_annotations(policies: str) -> tuple[PolicyAnnotation, ...]:
    """Read the effect and annotations of every static policy in ``policies``.

    The generated ids this returns are positional in ``policies``, so the result is only
    joinable with a decision if it was produced from **exactly** the text the
    :class:`PolicyEngine` was built from. Callers that concatenate policy fragments must
    concatenate once, deterministically, and derive both the engine and this index from that
    one string.

    Templates and template links are ignored: only static policies can be determining.

    Args:
        policies: Cedar policy text.

    Returns:
        One entry per static policy, in the order Cedar numbered them.

    Raises:
        ConfigurationError: If the text does not parse.
    """
    if not policies.strip():
        return ()
    try:
        rendered = json.loads(cedarpy.policies_to_json_str(policies))
    except ValueError as exc:
        raise ConfigurationError(f"cedar policy set failed to parse: {exc}") from exc

    read: list[PolicyAnnotation] = []
    for cedar_id, policy in rendered.get("staticPolicies", {}).items():
        # A policy with no annotations renders ``"annotations": null`` rather than ``{}``,
        # and an annotation written without parentheses renders a null value — both mean
        # "absent" and neither can be assumed to be a dict or a str.
        annotations = policy.get("annotations") or {}
        effect = policy.get("effect")
        read.append(
            PolicyAnnotation(
                cedar_id=str(cedar_id),
                effect="forbid" if effect == "forbid" else "permit",
                annotations={str(key): value for key, value in annotations.items()},
            )
        )
    return tuple(read)
