"""Masking — the step that runs immediately before every audit write.

The reasoning in one line: anything written to an append-only store is permanent, so a raw
sensitive value written there cannot be withdrawn, and masking at read or report time is too
late by definition. The consequence: masking on the audit path is *not* configurable. The
``redaction`` setting governs the caller-facing envelope and the operational logs; it cannot
switch off the mask before an immutable write.

Four strategies, trading recoverability against exposure:

``redact``
    Replace the value outright. Nothing survives — use it for values that have no analytical
    use at all.
``partial``
    Keep a short suffix (``****4321``). Enough for a human to recognize a record, not enough
    to reconstruct the value.
``hmac``
    Keyed digest. **The default**, because it is the only one that lets an auditor correlate
    records — "the same account appears in these fourteen decisions" — without the store ever
    holding the account number. Unkeyed hashing would not do: a low-entropy value like a
    customer id is trivially recovered from a plain digest by enumeration.
``tokenize``
    Reversible, via a mapping held in a separate vault. The audit store holds only the token;
    the vault is mutable and can honor an erasure request, which is exactly why the two must
    not be the same store.

A field selects its strategy three ways, most specific first:

1. **A policy obligation** — ``@obligations("mask:customer_id, redact:ssn")`` on a
   determining policy. Policy wins, because an obligation is reviewed logic.
2. **A signature annotation** — ``Annotated[str, Sensitive("hmac")]`` on the protected
   callable's parameter. The developer's declared default.
3. **The configured default strategy**, for anything an obligation named without a verb.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal, Protocol, runtime_checkable

from pydantic import BaseModel

from sentrykit.config import Settings
from sentrykit.constraints import RejectedArgument
from sentrykit.errors import ConfigurationError

__all__ = [
    "MASK_VERBS",
    "HmacStrategy",
    "MaskStrategy",
    "MaskStrategyName",
    "Masker",
    "PartialStrategy",
    "RedactStrategy",
    "Sensitive",
    "TokenVault",
    "TokenizeStrategy",
    "sensitive_fields",
]

MaskStrategyName = Literal["redact", "partial", "hmac", "tokenize"]
"""The four masking strategies a value can be written through."""

MASK_VERBS: Final[frozenset[str]] = frozenset({"mask", "redact", "partial", "hmac", "tokenize"})
"""Obligation verbs that select a masking strategy.

``mask`` means "use the configured default"; the other four name a strategy outright. An
obligation whose verb is not in this set — ``notify:secops``, ``justify`` — is not a masking
instruction and passes through untouched, to be discharged by the host.
"""

REDACTED: Final = "[redacted]"
"""What :class:`RedactStrategy` substitutes. A fixed marker, so it is greppable in a log."""

_STRATEGY_BY_VERB: Final[dict[str, MaskStrategyName]] = {
    "redact": "redact",
    "partial": "partial",
    "hmac": "hmac",
    "tokenize": "tokenize",
}
"""The obligation verbs that name a strategy outright.

``mask`` is deliberately absent: it means "whatever the configuration says", so it resolves
against :attr:`Masker._default` rather than against a fixed name.
"""

_UNAVAILABLE_HINT: Final[dict[MaskStrategyName, str]] = {
    "hmac": "set SENTRYKIT_HMAC_KEY, or pass key= when building the masker",
    "tokenize": "pass vault= when building the masker",
}
"""What to tell an operator when a strategy was asked for but could not be built."""


def _render(value: object) -> str:
    """Render a value for a strategy that works on text.

    One place, so ``partial``, ``hmac`` and ``tokenize`` agree on what "the value" is — a
    digest that depended on which strategy rendered it would not correlate with itself.
    """
    return value if isinstance(value, str) else str(value)


@dataclass(frozen=True, slots=True)
class Sensitive:
    """Marks a parameter as sensitive, in the signature of the protected callable.

    Written as annotation metadata, so it travels with the type rather than living in a
    registry someone has to keep in sync:

    ```python
    @protect(action='Action::"tool.lookup"')
    def lookup(account: Annotated[str, Sensitive("hmac")], note: str = "") -> dict[str, str]:
        ...
    ```

    Attributes:
        strategy: Which strategy to apply. ``None`` means "sensitive, use the configured
            default", which is the right spelling when a codebase wants to declare *what* is
            sensitive without deciding *how* it is masked.
    """

    strategy: MaskStrategyName | None = None


@runtime_checkable
class MaskStrategy(Protocol):
    """One way of turning a sensitive value into something safe to persist forever."""

    @property
    def name(self) -> MaskStrategyName:
        """The strategy's name, recorded on the audit record so a reader knows what was done."""
        ...

    def mask(self, value: object, *, field: str) -> object:
        """Mask one value.

        Args:
            value: The raw value. May be of any type the callable accepted.
            field: The argument name, used by keyed strategies so that the same raw value
                under two different field names does not produce the same digest.

        Returns:
            The masked value. Always JSON-renderable, because it is bound for a sink.
        """
        ...


class RedactStrategy:
    """Replace the value with a fixed marker. Nothing survives."""

    name: MaskStrategyName = "redact"

    def mask(self, value: object, *, field: str) -> object:
        """Return :data:`REDACTED`.

        The marker is fixed rather than shaped like the input — no length hint, no type hint
        — because anything derived from the value is something an attacker can work with.
        """
        return REDACTED


class PartialStrategy:
    """Keep a short suffix of the rendered value, mask the rest.

    Args:
        keep: How many trailing characters to preserve.
        placeholder: The character standing in for each masked position.
    """

    name: MaskStrategyName = "partial"

    def __init__(self, keep: int = 4, placeholder: str = "*") -> None:
        # A negative ``keep`` would slice from the wrong end and reveal a prefix, so it is
        # clamped rather than trusted.
        self._keep = max(keep, 0)
        self._placeholder = placeholder

    def mask(self, value: object, *, field: str) -> object:
        """Return the value with everything but its last ``keep`` characters replaced.

        A value at or below ``keep`` characters is fully masked rather than partially
        revealed: the short-value case is exactly where a partial mask would leak the whole
        thing.
        """
        rendered = _render(value)
        if len(rendered) <= self._keep:
            return self._placeholder * len(rendered)
        return self._placeholder * (len(rendered) - self._keep) + rendered[-self._keep :]


class HmacStrategy:
    """Keyed SHA-256 digest — correlatable, not recoverable. The default.

    Args:
        key: The HMAC key, from ``SENTRYKIT_HMAC_KEY``.
        digest_size: How many hex characters of the digest to keep. 32 is ample for
            correlation and keeps a record readable.

    Raises:
        ConfigurationError: If ``key`` is empty. An unkeyed digest of a low-entropy value —
            a customer id, an account number — is recoverable by enumeration, so a missing
            key is a configuration fault rather than something to silently degrade over.
    """

    name: MaskStrategyName = "hmac"

    def __init__(self, key: bytes, *, digest_size: int = 32) -> None:
        if not key:
            raise ConfigurationError(
                "The hmac masking strategy needs a key: an unkeyed digest of a low-entropy "
                "value is recoverable by enumeration. Set SENTRYKIT_HMAC_KEY."
            )
        self._key = key
        self._digest_size = max(digest_size, 1)

    def mask(self, value: object, *, field: str) -> object:
        """Return ``hmac:<hex>``, keyed by the configured key and bound to ``field``.

        The field name is hashed alongside the value with a separator that cannot occur in
        an identifier, so ``customer_id="c-1"`` and ``account="c-1"`` do not collide and a
        correlation across records is a correlation of the *same* field.
        """
        message = f"{field}\x00{_render(value)}".encode()
        digest = hmac.new(self._key, message, hashlib.sha256).hexdigest()
        return f"hmac:{digest[: self._digest_size]}"


class TokenVault(Protocol):
    """The reversible mapping behind :class:`TokenizeStrategy`.

    Deliberately *not* an audit store: it is mutable, so a subject-erasure request can drop
    the mapping and leave the audit chain intact but no longer resolvable. Putting it in the
    append-only store would make the erasure impossible, which is the whole point of masking
    upstream of the write.
    """

    def tokenize(self, value: str, *, field: str) -> str:
        """Return a stable token for ``value``, minting one if this is the first sighting."""
        ...

    def resolve(self, token: str) -> str | None:
        """Return the raw value behind ``token``, or ``None`` if it is unknown or erased."""
        ...


class TokenizeStrategy:
    """Replace the value with a stable token, keeping the mapping in a separate vault.

    Args:
        vault: Where the reversible mapping lives.
    """

    name: MaskStrategyName = "tokenize"

    def __init__(self, vault: TokenVault) -> None:
        self._vault = vault

    def mask(self, value: object, *, field: str) -> object:
        """Return ``token:<id>``, recording the mapping in the vault."""
        return f"token:{self._vault.tokenize(_render(value), field=field)}"


def sensitive_fields(model: type[BaseModel]) -> dict[str, MaskStrategyName | None]:
    """Read the :class:`Sensitive` markers off a protected callable's argument model.

    :class:`~sentrykit.engine.ArgumentSpec` builds that model with
    ``get_type_hints(include_extras=True)``, so ``Annotated`` metadata survives onto
    ``model_fields[...].metadata`` and can be read back here without the engine knowing
    anything about masking.

    Args:
        model: The generated argument model.

    Returns:
        Field name to its declared strategy, ``None`` where the marker named no strategy.
        Fields with no marker are absent.
    """
    declared: dict[str, MaskStrategyName | None] = {}
    for name, info in model.model_fields.items():
        for marker in info.metadata:
            # Last marker wins, so ``Annotated[str, Sensitive(), Sensitive("redact")]`` reads
            # left to right like every other refinement in an annotation.
            if isinstance(marker, Sensitive):
                declared[name] = marker.strategy
    return declared


class Masker:
    """Applies the masking policy for one decision.

    Args:
        strategies: Strategy instances by name. Defaults to the built-in four, with
            ``tokenize`` present only when a vault was supplied.
        default: Which strategy an unqualified ``mask:`` obligation or a bare
            ``Sensitive()`` marker resolves to.
        key: HMAC key, used to build the default :class:`HmacStrategy`.
        vault: Token vault, used to build :class:`TokenizeStrategy`.

    Raises:
        ConfigurationError: If a strategy the configuration needs cannot be built — an
            ``hmac`` default with no key, a ``tokenize`` default with no vault. That check is
            deferred to the moment a field actually resolves to the strategy, not made at
            construction: a masker with no key still masks correctly with ``redact`` and
            ``partial``, and a process that declares nothing sensitive must not be stopped
            from auditing because it never set a key it does not use.
    """

    __slots__ = ("_default", "_strategies")

    def __init__(
        self,
        strategies: Mapping[MaskStrategyName, MaskStrategy] | None = None,
        *,
        default: MaskStrategyName = "hmac",
        key: bytes | None = None,
        vault: TokenVault | None = None,
    ) -> None:
        if default not in _STRATEGY_BY_VERB:
            raise ConfigurationError(
                f"Unknown default masking strategy {default!r}; "
                f"expected one of {sorted(_STRATEGY_BY_VERB)}"
            )
        # ``redact`` and ``partial`` need nothing from the environment, so they are always
        # present; the other two are built only when their dependency was supplied.
        built: dict[MaskStrategyName, MaskStrategy] = {
            "redact": RedactStrategy(),
            "partial": PartialStrategy(),
        }
        if key:
            built["hmac"] = HmacStrategy(key)
        if vault is not None:
            built["tokenize"] = TokenizeStrategy(vault)
        if strategies:
            built.update(strategies)
        self._strategies: dict[MaskStrategyName, MaskStrategy] = built
        self._default: MaskStrategyName = default

    @classmethod
    def from_settings(cls, settings: Settings, *, vault: TokenVault | None = None) -> Masker:
        """Build a masker from :class:`~sentrykit.config.Settings`.

        Args:
            settings: The effective settings, read for ``hmac_key`` and ``mask_default``.
            vault: Token vault, when tokenization is wanted.

        Returns:
            The configured masker.

        Raises:
            ConfigurationError: If the settings ask for a strategy that cannot be built.
        """
        secret = settings.hmac_key
        key = secret.get_secret_value().encode("utf-8") if secret is not None else None
        return cls(default=settings.mask_default, key=key, vault=vault)

    def plan(
        self,
        *,
        declared: Mapping[str, MaskStrategyName | None] | None = None,
        obligations: Sequence[str] = (),
    ) -> dict[str, MaskStrategyName]:
        """Decide which strategy applies to which field, for one decision.

        Args:
            declared: :func:`sensitive_fields` output for the protected callable.
            obligations: The obligations the determining policies attached. Masking verbs are
                consumed; anything else is ignored here and left for the host.

        Returns:
            Field name to the strategy that will mask it. An obligation beats a declaration.
        """
        resolved: dict[str, MaskStrategyName] = {}
        for name, declared_strategy in (declared or {}).items():
            resolved[name] = declared_strategy or self._default

        # Applied second, and unconditionally, so policy overrides code: an obligation is
        # reviewed logic, a ``Sensitive`` marker is one developer's default.
        for obligation in obligations:
            verb, separator, target = obligation.partition(":")
            verb = verb.strip().lower()
            target = target.strip()
            if not separator or verb not in MASK_VERBS or not target:
                # Not a masking instruction — ``notify:secops``, ``justify`` — or a masking
                # verb naming nothing. Either way it is the host's to discharge, not ours.
                continue
            named = _STRATEGY_BY_VERB.get(verb)
            resolved[target] = named if named is not None else self._default
        return resolved

    def mask_value(self, field: str, value: object, strategy: MaskStrategyName) -> object:
        """Mask one value with a named strategy.

        Raises:
            ConfigurationError: If the strategy is not available on this masker. Refusing is
                the only safe answer: the alternative is to fall back to a weaker strategy
                and write the value into a store that cannot be corrected.
        """
        implementation = self._strategies.get(strategy)
        if implementation is None:
            hint = _UNAVAILABLE_HINT.get(strategy, "configure it on the masker")
            raise ConfigurationError(
                f"Masking strategy {strategy!r} was asked for but is not configured; {hint}"
            )
        return implementation.mask(value, field=field)

    def mask_mapping(
        self,
        values: Mapping[str, object],
        plan: Mapping[str, MaskStrategyName],
    ) -> dict[str, object]:
        """Mask every field in ``values`` that ``plan`` names, leaving the rest as they are.

        Args:
            values: Raw argument values.
            plan: The output of :meth:`plan`.

        Returns:
            A new mapping. The input is never mutated — the caller still has to hand the raw
            values to the protected callable.
        """
        if not plan:
            return dict(values)
        return {
            name: (self.mask_value(name, value, plan[name]) if name in plan else value)
            for name, value in values.items()
        }

    def mask_rejections(
        self,
        rejected: Iterable[RejectedArgument],
        plan: Mapping[str, MaskStrategyName],
    ) -> tuple[RejectedArgument, ...]:
        """Mask the ``value`` carried on each
        :class:`~sentrykit.constraints.RejectedArgument`.

        A rejection is exactly where raw sensitive data hides: the argument was refused, but
        the value the caller proposed is still attached to explain why.

        Args:
            rejected: The rejections from the decision.
            plan: The output of :meth:`plan`.

        Returns:
            New rejections with masked values, in the original order.
        """
        masked: list[RejectedArgument] = []
        for rejection in rejected:
            strategy = plan.get(rejection.name)
            if strategy is None or rejection.value is None:
                # Nothing to mask: either the field is not sensitive, or the rejection
                # carries no value in the first place (``None`` leaks nothing).
                masked.append(rejection)
                continue
            replacement = self.mask_value(rejection.name, rejection.value, strategy)
            masked.append(rejection.model_copy(update={"value": replacement}))
        return tuple(masked)
