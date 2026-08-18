"""Masking — the step that runs immediately before every audit write.

ADR-007's reasoning in one line: anything written to an append-only store is permanent, so a
raw sensitive value written there cannot be withdrawn, and masking at read or report time is
too late by definition. ADR-014 adds the consequence: masking on the audit path is *not*
configurable. The ``redaction`` setting governs the caller-facing envelope and the
operational logs; it cannot switch off the mask before an immutable write.

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

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal, Protocol, runtime_checkable

from pydantic import BaseModel

from sentrykit.config import Settings
from sentrykit.constraints import RejectedArgument

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
"""The four masking strategies, per ADR-007."""

MASK_VERBS: Final[frozenset[str]] = frozenset({"mask", "redact", "partial", "hmac", "tokenize"})
"""Obligation verbs that select a masking strategy.

``mask`` means "use the configured default"; the other four name a strategy outright. An
obligation whose verb is not in this set — ``notify:secops``, ``justify`` — is not a masking
instruction and passes through untouched, to be discharged by the host.
"""

REDACTED: Final = "[redacted]"
"""What :class:`RedactStrategy` substitutes. A fixed marker, so it is greppable in a log."""


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
        """Return :data:`REDACTED`."""
        raise NotImplementedError


class PartialStrategy:
    """Keep a short suffix of the rendered value, mask the rest.

    Args:
        keep: How many trailing characters to preserve.
        placeholder: The character standing in for each masked position.
    """

    name: MaskStrategyName = "partial"

    def __init__(self, keep: int = 4, placeholder: str = "*") -> None:
        raise NotImplementedError

    def mask(self, value: object, *, field: str) -> object:
        """Return the value with everything but its last ``keep`` characters replaced.

        A value shorter than ``keep`` is fully masked rather than partially revealed: the
        short-value case is exactly where a partial mask would leak the whole thing.
        """
        raise NotImplementedError


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
        raise NotImplementedError

    def mask(self, value: object, *, field: str) -> object:
        """Return ``hmac:<hex>``, keyed by the configured key and bound to ``field``."""
        raise NotImplementedError


class TokenVault(Protocol):
    """The reversible mapping behind :class:`TokenizeStrategy`.

    Deliberately *not* an audit store: it is mutable, so a subject-erasure request can drop
    the mapping and leave the audit chain intact but no longer resolvable. Putting it in the
    append-only store would make the erasure impossible, which is the whole point of ADR-007.
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
        raise NotImplementedError

    def mask(self, value: object, *, field: str) -> object:
        """Return ``token:<id>``, recording the mapping in the vault."""
        raise NotImplementedError


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
    raise NotImplementedError


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
            ``hmac`` default with no key, a ``tokenize`` default with no vault.
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
        raise NotImplementedError

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
        raise NotImplementedError

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
            Field name to the strategy that will mask it. An obligation beats a declaration,
            per ADR-014.
        """
        raise NotImplementedError

    def mask_value(self, field: str, value: object, strategy: MaskStrategyName) -> object:
        """Mask one value with a named strategy.

        Raises:
            ConfigurationError: If the strategy is not available on this masker.
        """
        raise NotImplementedError

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
        raise NotImplementedError

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
        raise NotImplementedError
