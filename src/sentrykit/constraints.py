"""Per-(principal, action) argument constraints: the layer that filters what a caller may pass.

Cedar's gate is boolean — it answers "may this principal perform this action on this
resource", not "with which arguments". ADR-002 keeps argument-level enforcement in Python,
driven by attribute data resolved from the grant store, with a Cedar ``forbid`` backstop as
defense in depth. This module is that enforcement, and nothing in it knows about Cedar, the
engine, or the decorator: it is a pure function from constraints plus proposed arguments to
kept, rejected and defaulted arguments.

That purity is the point. The caller — a web client or a language model — *proposes*
arguments; the constraint set *decides* which of them survive. A rejection is data, not an
exception, so the engine can drop it (``arg_handling="lenient"``) or raise on it
(``"strict"``) without this module knowing which mode is in force.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ArgumentConstraint",
    "ConstraintSet",
    "DefaultsResult",
    "FilterResult",
    "RejectedArgument",
    "Rule",
]

Rule = Literal["allow-set", "deny-set", "pattern", "minimum", "maximum", "not-comparable"]
"""Which kind of constraint a value violated."""


class RejectedArgument(BaseModel):
    """One argument the policy would not accept, and why.

    Carried on the ``_authz`` envelope, on
    :class:`~sentrykit.errors.NoValidArguments`, and into the audit record, so the reason a
    value was dropped is reportable rather than guessable.

    Attributes:
        name: The argument's parameter name.
        rule: Which constraint it violated.
        reason: A sentence-case explanation suitable for showing to the caller.
        policy: Id of the policy or grant that carried the constraint, when known.
        value: The offending value. Emitted only at ``verbose`` verbosity or above, and
            masked before any audit write once Phase 2's masking lands — never assume this
            is safe to log.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    rule: Rule
    reason: str
    policy: str | None = None
    value: object | None = None

    def as_detail(self) -> dict[str, object]:
        """Render without the value, for ``summary`` verbosity and for error payloads."""
        raise NotImplementedError


class FilterResult(NamedTuple):
    """What :meth:`ConstraintSet.filter` decided.

    Attributes:
        kept: The proposed arguments that satisfy their constraints.
        rejected: One entry per argument that does not.
    """

    kept: dict[str, object]
    rejected: tuple[RejectedArgument, ...]


class DefaultsResult(NamedTuple):
    """What :meth:`ConstraintSet.inject_defaults` produced.

    Attributes:
        arguments: The kept arguments plus every injected default.
        applied: Only the defaults that were injected, for the envelope's
            ``defaults_applied``.
    """

    arguments: dict[str, object]
    applied: dict[str, object]


class ArgumentConstraint(BaseModel):
    """The rules that govern one argument for one principal and action.

    Every rule is optional and they compose: a value must satisfy all of the ones that are
    present. An unconstrained argument is one with no entry in the
    :class:`ConstraintSet` at all — an empty constraint here permits everything, which is
    deliberately different from *forbidding* everything, since the coarse Cedar gate has
    already decided the call itself is permitted.

    Attributes:
        allow: If set, the value must be one of these.
        deny: If set, the value must not be one of these.
        pattern: If set, a regular expression the value must match in full. Non-string
            values are rejected as not comparable rather than coerced.
        minimum: If set, the lower bound (inclusive) for a numeric value.
        maximum: If set, the upper bound (inclusive) for a numeric value.
        default: Value to inject when the caller supplies none, or when theirs was dropped.
            Distinguished from "no default configured" by :attr:`has_default`, so a default
            of ``None`` is expressible.
        required: Whether the call cannot proceed without this argument. A required argument
            with no supplied value and no default raises
            :class:`~sentrykit.errors.DefaultUnavailable`.
        policy: Id of the policy or grant this constraint came from, recorded on rejections
            for provenance.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    allow: tuple[object, ...] | None = None
    deny: tuple[object, ...] | None = None
    pattern: str | None = None
    minimum: int | float | None = None
    maximum: int | float | None = None
    default: object | None = None
    required: bool = False
    policy: str | None = None

    @property
    def has_default(self) -> bool:
        """Whether a default was configured, including an explicit default of ``None``."""
        raise NotImplementedError

    def check(self, name: str, value: object) -> RejectedArgument | None:
        """Test one value against every rule in this constraint.

        Args:
            name: The parameter name, used to label a rejection.
            value: The proposed value.

        Returns:
            ``None`` if the value is acceptable, otherwise the rejection describing the first
            rule it violated.
        """
        raise NotImplementedError

    def describe(self) -> dict[str, object]:
        """Summarize the rules, for the "here is what you *may* pass" half of an error."""
        raise NotImplementedError


class ConstraintSet(BaseModel):
    """Every argument constraint that applies to one principal for one action.

    Attributes:
        arguments: Parameter name to its constraint. Parameters absent from this mapping are
            unconstrained.
    """

    model_config = ConfigDict(frozen=True)

    arguments: dict[str, ArgumentConstraint] = Field(default_factory=dict)

    def __bool__(self) -> bool:
        """Whether this set constrains anything at all."""
        raise NotImplementedError

    def merged_with(self, other: ConstraintSet) -> ConstraintSet:
        """Return this set with ``other`` layered on top, per argument.

        Used to let a wildcard (``"*"``) constraint set supply the baseline that an
        action-specific set refines. Overriding is whole-constraint, not field-by-field: an
        action-specific entry for an argument replaces the wildcard entry for it outright,
        which keeps "what applies here" answerable by reading one object.
        """
        raise NotImplementedError

    def filter(self, proposed: Mapping[str, object]) -> FilterResult:
        """Split proposed arguments into those the policy accepts and those it does not.

        Args:
            proposed: What the caller asked for.

        Returns:
            The kept arguments and the rejections. Never raises — turning a rejection into an
            error is ``arg_handling``'s decision, made by the engine.
        """
        raise NotImplementedError

    def inject_defaults(
        self,
        kept: Mapping[str, object],
        parameters: Collection[str],
    ) -> DefaultsResult:
        """Fill in per-principal defaults for arguments the caller did not supply.

        A default never overrides a value that survived filtering — the caller's own valid
        input wins. Defaults are injected for dropped arguments too, which is what makes
        ``lenient`` handling useful: an over-broad request is narrowed to what the principal
        is entitled to rather than refused.

        Args:
            kept: Arguments that survived :meth:`filter`.
            parameters: Parameter names the target callable actually accepts. Defaults for
                anything else are skipped, so a stale grant cannot make a call fail with an
                unexpected keyword argument.

        Returns:
            The completed argument mapping and the subset that was injected.
        """
        raise NotImplementedError

    def missing_required(self, present: Collection[str]) -> tuple[str, ...]:
        """Name the required arguments that are still absent after defaults were injected.

        Args:
            present: Argument names that now have a value.

        Returns:
            The names of required arguments with neither a supplied value nor a default —
            each one a :class:`~sentrykit.errors.DefaultUnavailable`.
        """
        raise NotImplementedError

    def describe(self) -> dict[str, object]:
        """Summarize every constraint, for the allowed-set half of an error payload."""
        raise NotImplementedError
