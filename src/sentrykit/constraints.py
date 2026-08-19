"""Per-(principal, action) argument constraints: the layer that filters what a caller may pass.

Cedar's gate is boolean — it answers "may this principal perform this action on this
resource", not "with which arguments". So argument-level enforcement stays in Python, driven
by attribute data resolved from the grant store, with a Cedar ``forbid`` backstop as defense
in depth. This module is that enforcement, and nothing in it knows about Cedar, the
engine, or the decorator: it is a pure function from constraints plus proposed arguments to
kept, rejected and defaulted arguments.

That purity is the point. The caller — a web client or a language model — *proposes*
arguments; the constraint set *decides* which of them survive. A rejection is data, not an
exception, so the engine can drop it (``arg_handling="lenient"``) or raise on it
(``"strict"``) without this module knowing which mode is in force.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Collection, Mapping
from typing import Final, Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ArgumentConstraint",
    "ConstraintSet",
    "DefaultsResult",
    "FilterResult",
    "RejectedArgument",
    "Rule",
]

_LOGGER: Final = logging.getLogger("sentrykit.constraints")

_PATTERN_CACHE: Final[dict[str, re.Pattern[str] | None]] = {}


def _compiled(pattern: str) -> re.Pattern[str] | None:
    """Compile and memoize ``pattern``, returning ``None`` if it is not a valid regex.

    Constraint checking runs on every protected call, so the compile is cached by pattern
    text. An uncompilable pattern is cached too, and reported as ``None`` rather than raised:
    :meth:`ConstraintSet.filter` promises not to raise, so a malformed grant fails *closed*
    (the value is rejected) instead of taking the call path down with it.
    """
    if pattern in _PATTERN_CACHE:
        return _PATTERN_CACHE[pattern]
    try:
        compiled: re.Pattern[str] | None = re.compile(pattern)
    except re.error as exc:
        _LOGGER.error(
            "Argument constraint pattern is not a valid regular expression",
            extra={"pattern": pattern, "error": str(exc)},
        )
        compiled = None
    _PATTERN_CACHE[pattern] = compiled
    return compiled


def _same_value(candidate: object, member: object) -> bool:
    """Compare a proposed value with a set member without letting ``True`` equal ``1``.

    Python's ``bool`` is an ``int``, so a plain ``==`` would let a caller slip ``True`` past
    an allow-set of ``(1,)``. Membership decides authorization here, so the types must match
    as well as the values.
    """
    if isinstance(candidate, bool) is not isinstance(member, bool):
        return False
    return bool(candidate == member)


def _as_number(value: object) -> int | float | None:
    """Return ``value`` as a number for range comparison, or ``None`` if it is not one.

    ``bool`` is deliberately not a number: comparing ``True >= 1`` would make a boolean
    satisfy a numeric bound by accident.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return value
    return None


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
            masked before any audit write — never assume this is safe to log.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    rule: Rule
    reason: str
    policy: str | None = None
    value: object | None = None

    def as_detail(self) -> dict[str, object]:
        """Render without the value, for ``summary`` verbosity and for error payloads."""
        return self.model_dump(exclude={"value"}, exclude_none=True)


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
        return "default" in self.model_fields_set

    def _reject(self, name: str, rule: Rule, reason: str, value: object) -> RejectedArgument:
        """Build a rejection carrying this constraint's provenance."""
        return RejectedArgument(
            name=name, rule=rule, reason=reason, policy=self.policy, value=value
        )

    def check(self, name: str, value: object) -> RejectedArgument | None:
        """Test one value against every rule in this constraint.

        Rules are evaluated allow-set, deny-set, pattern, minimum, maximum, and the first
        violation is returned: reporting one concrete reason is more actionable than a list,
        and the order runs from the coarsest rule to the finest.

        Args:
            name: The parameter name, used to label a rejection.
            value: The proposed value.

        Returns:
            ``None`` if the value is acceptable, otherwise the rejection describing the first
            rule it violated.
        """
        if self.allow is not None and not any(_same_value(value, m) for m in self.allow):
            return self._reject(
                name, "allow-set", "Value is not one of the permitted values", value
            )

        if self.deny is not None and any(_same_value(value, m) for m in self.deny):
            return self._reject(name, "deny-set", "Value is explicitly denied", value)

        if self.pattern is not None:
            if not isinstance(value, str):
                return self._reject(
                    name,
                    "not-comparable",
                    "Value is not a string and cannot be matched against a pattern",
                    value,
                )
            compiled = _compiled(self.pattern)
            if compiled is None:
                # Fail closed: the grant is malformed, so nothing can be shown to satisfy it.
                return self._reject(
                    name,
                    "pattern",
                    "Value cannot be checked because the configured pattern is invalid",
                    value,
                )
            if compiled.fullmatch(value) is None:
                return self._reject(
                    name,
                    "pattern",
                    f"Value does not match the required pattern {self.pattern!r}",
                    value,
                )

        if self.minimum is not None:
            number = _as_number(value)
            if number is None:
                return self._reject(
                    name,
                    "not-comparable",
                    "Value is not a number and cannot be compared against a minimum",
                    value,
                )
            if number < self.minimum:
                return self._reject(
                    name, "minimum", f"Value is below the minimum of {self.minimum}", value
                )

        if self.maximum is not None:
            number = _as_number(value)
            if number is None:
                return self._reject(
                    name,
                    "not-comparable",
                    "Value is not a number and cannot be compared against a maximum",
                    value,
                )
            if number > self.maximum:
                return self._reject(
                    name, "maximum", f"Value is above the maximum of {self.maximum}", value
                )

        return None

    def describe(self) -> dict[str, object]:
        """Summarize the rules, for the "here is what you *may* pass" half of an error.

        Only the rules that were actually configured appear. The default *value* never does —
        a caller is told that one exists, not what it is, since a per-principal default can
        itself be sensitive (someone else's tenant id, say).
        """
        described: dict[str, object] = {}
        if self.allow is not None:
            described["allow"] = list(self.allow)
        if self.deny is not None:
            described["deny"] = list(self.deny)
        if self.pattern is not None:
            described["pattern"] = self.pattern
        if self.minimum is not None:
            described["minimum"] = self.minimum
        if self.maximum is not None:
            described["maximum"] = self.maximum
        if self.policy is not None:
            described["policy"] = self.policy
        described["required"] = self.required
        described["has_default"] = self.has_default
        return described


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
        return bool(self.arguments)

    def merged_with(self, other: ConstraintSet) -> ConstraintSet:
        """Return this set with ``other`` layered on top, per argument.

        Used to let a wildcard (``"*"``) constraint set supply the baseline that an
        action-specific set refines. Overriding is whole-constraint, not field-by-field: an
        action-specific entry for an argument replaces the wildcard entry for it outright,
        which keeps "what applies here" answerable by reading one object.
        """
        return ConstraintSet(arguments={**self.arguments, **other.arguments})

    def filter(self, proposed: Mapping[str, object]) -> FilterResult:
        """Split proposed arguments into those the policy accepts and those it does not.

        Args:
            proposed: What the caller asked for.

        Returns:
            The kept arguments and the rejections. Never raises — turning a rejection into an
            error is ``arg_handling``'s decision, made by the engine.
        """
        kept: dict[str, object] = {}
        rejected: list[RejectedArgument] = []
        for name, value in proposed.items():
            constraint = self.arguments.get(name)
            if constraint is None:
                # Unconstrained: the coarse Cedar gate already permitted this call, and an
                # empty constraint set must not mean "forbid everything".
                kept[name] = value
                continue
            rejection = constraint.check(name, value)
            if rejection is None:
                kept[name] = value
            else:
                rejected.append(rejection)
        return FilterResult(kept=kept, rejected=tuple(rejected))

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
        arguments: dict[str, object] = dict(kept)
        applied: dict[str, object] = {}
        for name, constraint in self.arguments.items():
            if name in arguments or name not in parameters or not constraint.has_default:
                continue
            arguments[name] = constraint.default
            applied[name] = constraint.default
        return DefaultsResult(arguments=arguments, applied=applied)

    def missing_required(self, present: Collection[str]) -> tuple[str, ...]:
        """Name the required arguments that are still absent after defaults were injected.

        Args:
            present: Argument names that now have a value.

        Returns:
            The names of required arguments with neither a supplied value nor a default —
            each one a :class:`~sentrykit.errors.DefaultUnavailable`.
        """
        return tuple(
            name
            for name, constraint in self.arguments.items()
            if constraint.required and name not in present
        )

    def describe(self) -> dict[str, object]:
        """Summarize every constraint, for the allowed-set half of an error payload."""
        return {name: constraint.describe() for name, constraint in self.arguments.items()}
