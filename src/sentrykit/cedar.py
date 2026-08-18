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

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Literal, NamedTuple

__all__ = [
    "CedarDecision",
    "CedarRequest",
    "Entity",
    "EntityRef",
    "PolicyEngine",
    "coerce_value",
]

_UID_RE: Final = re.compile(
    r'^(?P<type>[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)::"(?P<id>.*)"$'
)

DecisionLiteral = Literal["allow", "deny", "no-decision"]
"""Normalized spelling of Cedar's ``Allow`` / ``Deny`` / ``NoDecision``."""


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
        raise NotImplementedError

    def __str__(self) -> str:
        """Render the Cedar surface form, ``Type::"id"``."""
        raise NotImplementedError

    def as_json(self) -> dict[str, str]:
        """Return the structured ``{"type": ..., "id": ...}`` form ``cedarpy`` accepts."""
        raise NotImplementedError


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
        raise NotImplementedError


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
        raise NotImplementedError

    def as_trace(self) -> dict[str, object]:
        """Render the decision for the envelope's debug trace and the audit record."""
        raise NotImplementedError


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

    def __init__(
        self,
        policies: str,
        entities: Sequence[Entity] = (),
        *,
        schema: str | None = None,
    ) -> None:
        raise NotImplementedError

    @property
    def policy_set_hash(self) -> str:
        """Stable digest of the policy text and schema this engine evaluates against."""
        raise NotImplementedError

    @property
    def policies(self) -> str:
        """The Cedar policy text this engine was built from."""
        raise NotImplementedError

    def with_entities(self, entities: Iterable[Entity]) -> PolicyEngine:
        """Return a new engine with ``entities`` added to the base graph.

        The receiver is unchanged and its parsed handles are reused, so this is cheap enough
        to call when a tenant's entities are loaded alongside the shared ones.
        """
        raise NotImplementedError

    def evaluate(self, request: CedarRequest) -> CedarDecision:
        """Ask Cedar whether ``request`` is authorized.

        Never raises on a denial or on a Cedar evaluation error: both come back on the
        returned decision, because deciding what an engine failure *means* is the
        :class:`~sentrykit.engine.Governor`'s job, governed by ``fail_mode``.

        Args:
            request: The question to answer.

        Returns:
            The normalized decision.
        """
        raise NotImplementedError


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
    ``EntityRef`` becomes Cedar's ``{"__entity": ...}`` form; mappings and sequences recurse.
    Anything else is stringified.

    Args:
        value: The value to coerce.

    Returns:
        A Cedar-safe value, or ``None`` when the value has no Cedar representation and
        should be omitted.
    """
    raise NotImplementedError
