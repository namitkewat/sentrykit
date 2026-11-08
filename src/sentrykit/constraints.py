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

A constraint is *data*, which means one can be written that no value satisfies, or whose own
default it would reject. Both are faults of the moment a constraint is **written**, not of
the call that happens to run into them, so :meth:`ArgumentConstraint.inconsistencies` states
them as sentences an operator can act on and a grant store runs it at the write. The decision
path stays fail-closed regardless: :meth:`ConstraintSet.inject_defaults` re-checks every
default against its own constraint and withholds one that fails, because an argument nobody
proposed must not be a way around the rule that governs it.
"""

from __future__ import annotations

import json
import logging
import numbers
import re
from collections.abc import Callable, Collection, Iterator, Mapping
from decimal import Decimal
from itertools import chain
from typing import Final, Literal, NamedTuple, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentrykit.errors import ConfigurationError

__all__ = [
    "CEILING_RULES",
    "ArgumentConstraint",
    "ConstraintSet",
    "DefaultsResult",
    "FilterResult",
    "RejectedArgument",
    "Rule",
    "parse_ceiling",
]

_LOGGER: Final = logging.getLogger("sentrykit.constraints")

_PATTERN_CACHE: Final[dict[str, re.Pattern[str] | None]] = {}

_PROBE: Final = "value"
"""Stand-in argument name for a self-consistency probe.

:meth:`ArgumentConstraint.inconsistencies` reads only a rejection's ``reason``, which
never spells the argument name -- and a constraint does not know what it is attached to.
"""


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


_Number: TypeAlias = int | float | Decimal | numbers.Real
"""A value a numeric bound can be tested against.

Wider than the ``int | float`` a bound is *written* as, because ``Decimal`` is the type money
is held in and a bound on a refund amount is this library's own canonical example. ``Decimal``
compares exactly against both ``int`` and ``float``, so the bound stays ``int | float`` and
only the value side widens -- a ``Decimal`` bound would reach
:meth:`ArgumentConstraint.describe` and from there a JSON error body, which ``Decimal`` cannot
be serialized into.
"""


def _is_nan(value: _Number) -> bool:
    """Whether ``value`` is a NaN, whichever numeric type spells it.

    It matters that a NaN never reaches the bound, and the two spellings of one have to be
    stopped for opposite reasons. A ``Decimal`` NaN *raises* ``InvalidOperation`` from an
    ordering comparison -- and a *signalling* one raises from ``!=`` as well, which is why this
    asks it rather than comparing it -- while :meth:`ConstraintSet.filter` promises not to
    raise. A ``float`` NaN answers ``False`` to every ordering comparison instead, which would
    quietly satisfy a lone ``maximum``. Neither is a value a bound has anything to say about,
    so both are refused as not comparable.

    Everything else is tested by self-inequality, the one property a NaN has whatever type
    holds it, and the only one that needs no conversion -- ``math.isnan`` would overflow on a
    large ``int``.
    """
    if isinstance(value, Decimal):
        return value.is_nan()
    return bool(value != value)


def _as_number(value: object) -> _Number | None:
    """Return ``value`` as a number for range comparison, or ``None`` if it is not one.

    ``bool`` is deliberately not a number: comparing ``True >= 1`` would make a boolean
    satisfy a numeric bound by accident. The value is returned as it arrived rather than
    coerced to ``float``, so an exact type keeps its precision in the comparison that follows.
    """
    if isinstance(value, bool):
        return None
    if not isinstance(value, int | float | Decimal | numbers.Real):
        # ``complex`` lands here: it is a number and it is not ordered, so a bound cannot be
        # tested against it -- and asking would raise rather than answer.
        return None
    return None if _is_nan(value) else value


def _exceeds(number: _Number, maximum: int | float) -> bool:
    """Whether ``number`` is above ``maximum``.

    Written as a negated ``<=`` rather than a ``>`` because the value side of a bound is wider
    than the bound itself, and ``numbers.Real`` guarantees its ordering in the ``<`` direction
    only. The two spellings agree for everything that reaches here: a NaN is the one value
    they would differ over, and :func:`_as_number` has already refused it.
    """
    return not number <= maximum


_DENY_DEPTH_LIMIT: Final = 16
"""How far into a proposed container a deny-set is read.

A proposal is untrusted input -- a request body, or a model's tool call -- so it can be
self-referential or nested past any plausible depth. The walk stops here and the value is
rejected *unsearched*, which is the fail-closed direction and the reason this is a limit
rather than a recursion error: :meth:`ConstraintSet.filter` promises not to raise.
"""

_DenyHit = Literal["value", "element", "depth"]
"""Where a deny-set matched, or why the walk could not finish looking."""


def _elements(value: object) -> Iterator[object] | None:
    """Return the sub-values a deny-set should be read against, or ``None`` for a leaf.

    A mapping contributes its keys as well as its values, because a denied name used as a key
    is as much a reference to it as one used as a value. ``str`` and ``bytes`` are leaves:
    reading a string element-wise would turn a deny-set of whole values into a substring rule.
    So is anything that is not a sized, iterable container -- a generator among them, which
    also keeps the walk from consuming an iterator the callable is about to receive.

    Lazily, because the container is the caller's: copying it to walk it would double the cost
    of a large proposal before deciding anything about it.
    """
    if isinstance(value, str | bytes):
        return None
    if isinstance(value, Mapping):
        return chain(value.values(), value.keys())
    if isinstance(value, Collection):
        return iter(value)
    return None


def _deny_hit(value: object, deny: Collection[object], *, depth: int = 0) -> _DenyHit | None:
    """Find a denied value in ``value`` itself or anywhere inside it.

    Denial is the one rule read element-wise, because it is the fail-closed direction. A
    scalar never equals a container, so a deny-set that compared whole values only would be
    defeated by wrapping the forbidden value in a one-element list -- which is the shape a
    language model proposing ``targets=["dev", "prod"]`` sends. Permission is deliberately not
    read this way; :meth:`ArgumentConstraint.check` says why.

    Args:
        value: The proposed value, or a sub-value of one.
        deny: The members no value may be.
        depth: How far inside the original proposal ``value`` sits.

    Returns:
        Where the match was, ``"depth"`` if a container was left unsearched at
        :data:`_DENY_DEPTH_LIMIT`, or ``None`` if nothing in ``value`` is denied.
    """
    if any(_same_value(value, member) for member in deny):
        return "value" if depth == 0 else "element"
    elements = _elements(value)
    if elements is None:
        return None
    if depth >= _DENY_DEPTH_LIMIT:
        return "depth"
    for element in elements:
        hit = _deny_hit(element, deny, depth=depth + 1)
        if hit is not None:
            return hit
    return None


def _union(
    first: tuple[object, ...] | None, second: tuple[object, ...] | None
) -> tuple[object, ...] | None:
    """Combine two deny-sets, preserving first-seen order and dropping repeats."""
    if first is None or second is None:
        return first if first is not None else second
    combined = list(first)
    combined += [
        member for member in second if not any(_same_value(member, seen) for seen in combined)
    ]
    return tuple(combined)


def _tighter(
    first: int | float | None,
    second: int | float | None,
    *,
    loosen: Callable[[int | float, int | float], int | float],
) -> int | float | None:
    """Return whichever bound is tighter, or the only one that is set.

    ``loosen`` is the function that would *widen* the bound -- ``min`` for a lower bound and
    ``max`` for an upper one -- so whichever value it does not pick is the tighter one.
    """
    if first is None or second is None:
        return first if first is not None else second
    return second if loosen(first, second) == first else first


def _both_patterns(first: str | None, second: str | None) -> str | None:
    """Return a pattern matching exactly the strings that both of these match in full.

    Each side is asserted as a zero-width lookahead anchored at the end of the string, which
    is what :meth:`ArgumentConstraint.check`'s ``fullmatch`` means, and a permissive
    consuming tail satisfies the match itself. Composing this way rather than concatenating
    keeps each pattern's own anchors and alternation inside its own group.

    A capturing group in either pattern is renumbered by the composition, so a backreference
    would resolve to the wrong group. :func:`parse_ceiling` refuses a declared pattern
    carrying one, which is the layer that can: a pattern in a grant is the operator's own.
    """
    if first is None or second is None:
        return first if first is not None else second
    if first == second:
        return first
    return f"(?=(?:{first})\\Z)(?=(?:{second})\\Z)(?s:.*)"


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
        withheld: One entry per default that was *not* injected because it does not satisfy
            its own constraint. A grant store refuses such a constraint at the write, so
            reaching this is an operator fault in a constraint set built some other way --
            and the fault is reported rather than resolved in the caller's favour.
    """

    arguments: dict[str, object]
    applied: dict[str, object]
    withheld: tuple[RejectedArgument, ...] = ()


class ArgumentConstraint(BaseModel):
    """The rules that govern one argument for one principal and action.

    Every rule is optional and they compose: a value must satisfy all of the ones that are
    present. An unconstrained argument is one with no entry in the
    :class:`ConstraintSet` at all — an empty constraint here permits everything, which is
    deliberately different from *forbidding* everything, since the coarse Cedar gate has
    already decided the call itself is permitted.

    Attributes:
        allow: If set, the value must be one of these. The value is compared as a whole, so a
            container is rejected outright rather than read element-wise: admitting a list
            because each of its elements is permitted would *widen* a rule written about one
            value.
        deny: If set, neither the value nor anything inside it may be one of these. This is
            the one rule read element-wise, because denial is the fail-closed direction — a
            scalar never equals a container, so comparing whole values only would let a caller
            defeat the rule by wrapping the forbidden value in a one-element list.
        pattern: If set, a regular expression the value must match in full. Non-string
            values are rejected as not comparable rather than coerced.
        minimum: If set, the lower bound (inclusive) for a numeric value. Written as an
            ``int`` or a ``float``; a ``Decimal`` or any other real number is compared against
            it at its own precision.
        maximum: If set, the upper bound (inclusive) for a numeric value, on the same terms as
            :attr:`minimum`.
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

        The vocabulary is scalar-only but for one asymmetry: ``deny`` is read element-wise and
        nothing else is. It walks a proposed container — a mapping's values and its keys, any
        other collection that is not a ``str`` or ``bytes``, and on through nesting as far as
        :data:`_DENY_DEPTH_LIMIT` — and rejects the value if anything inside it is denied, or
        if the container was too deep to finish reading. Every other rule compares the value
        as a whole and so rejects a container outright, ``allow`` as ``allow-set`` and the
        pattern and the bounds as ``not-comparable``. That is deliberate and not an oversight
        to tidy up: reading denial element-wise only ever *narrows* what a principal may pass,
        while reading permission the same way would widen it.

        Args:
            name: The parameter name, used to label a rejection.
            value: The proposed value.

        Returns:
            ``None`` if the value is acceptable, otherwise the rejection describing the first
            rule it violated. Never raises, whatever the proposal holds.
        """
        if self.allow is not None and not any(_same_value(value, m) for m in self.allow):
            return self._reject(
                name, "allow-set", "Value is not one of the permitted values", value
            )

        if self.deny is not None:
            match _deny_hit(value, self.deny):
                case "value":
                    return self._reject(name, "deny-set", "Value is explicitly denied", value)
                case "element":
                    return self._reject(
                        name, "deny-set", "Value contains an explicitly denied value", value
                    )
                case "depth":
                    # Fail closed: part of the proposal was never read, so nothing in it can
                    # be shown to be permitted.
                    return self._reject(
                        name,
                        "deny-set",
                        "Value is nested too deeply to be read against the denied values",
                        value,
                    )

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
            if _exceeds(number, self.maximum):
                return self._reject(
                    name, "maximum", f"Value is above the maximum of {self.maximum}", value
                )

        return None

    def intersected_with(self, other: ArgumentConstraint) -> ArgumentConstraint:
        """Return the constraint satisfying both this one and ``other``.

        The counterpart to :meth:`ConstraintSet.merged_with`, which *overrides*. Layering a
        ceiling declared in reviewed policy text over a principal's grant must never widen
        what they may pass, so every rule composes in the tightening direction: allow-sets
        intersect, deny-sets union, bounds move inward, ``required`` is sticky, and two
        patterns must both match in full.

        ``default`` and ``policy`` come from the receiver where it has them. A ceiling
        declares no default -- a per-principal default is grant data, not reviewed logic --
        and the receiver's ``policy`` names the specific, per-principal layer, while the
        layer being intersected in is already named by the decision's determining policies,
        which the envelope and the audit record carry.

        Args:
            other: The constraint to narrow by.

        Returns:
            A constraint no value satisfies unless it satisfies both. It may well be
            unsatisfiable -- two disjoint allow-sets intersect to none, and nothing then
            passes, which is the fail-closed direction.
        """
        fields: dict[str, object] = {
            "deny": _union(self.deny, other.deny),
            "pattern": _both_patterns(self.pattern, other.pattern),
            "minimum": _tighter(self.minimum, other.minimum, loosen=min),
            "maximum": _tighter(self.maximum, other.maximum, loosen=max),
            "required": self.required or other.required,
            "policy": self.policy or other.policy,
        }
        if self.allow is None or other.allow is None:
            fields["allow"] = self.allow if self.allow is not None else other.allow
        else:
            fields["allow"] = tuple(
                member
                for member in self.allow
                if any(_same_value(member, permitted) for permitted in other.allow)
            )
        # Named only when one side configured one, because ``has_default`` is read off
        # ``model_fields_set``: naming the field unconditionally would turn "no default" into
        # "a default of None" and start injecting it.
        if self.has_default:
            fields["default"] = self.default
        elif other.has_default:
            fields["default"] = other.default
        return ArgumentConstraint.model_validate(fields)

    def inconsistencies(self) -> tuple[str, ...]:
        """Every way this constraint contradicts itself, as sentences an operator can act on.

        A constraint is *data*, so nothing stops one being written that no value can satisfy
        -- ``minimum=100, maximum=10`` constructs without complaint -- or one whose own
        default it would reject. Left alone, both are discovered at call time as a refusal of
        everything, by whoever happens to call next. This is the check that moves that
        discovery to the moment the grant is written, and
        :meth:`~sentrykit.stores.base.GrantStore.grant` runs it there.

        Four things are checked:

        1. The ``pattern`` compiles.
        2. ``minimum`` is not above ``maximum``.
        3. Every ``allow`` member satisfies this constraint's other rules. A permitted value
           the pattern or the bounds reject is dead configuration: a reviewer reading the
           allow-set believes it is reachable.
        4. A configured ``default`` satisfies this constraint. Without this the way to defeat
           a constraint is to *stop proposing a value*, since an omitted argument is filled
           from the default rather than filtered.

        The last two delegate to :meth:`check`, so what a grant promises at the write and
        what the filter enforces at the call cannot drift apart.

        Returns:
            One sentence per problem, or an empty tuple when the constraint is coherent. An
            uncompilable pattern or inverted bounds short-circuit the value-level checks:
            :meth:`check` rejects *everything* under either, so probing the allow-set and the
            default would restate the same fault once per value.
        """
        structural: list[str] = []
        if self.pattern is not None and _compiled(self.pattern) is None:
            structural.append(f"pattern {self.pattern!r} is not a valid regular expression")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            structural.append(
                f"minimum {self.minimum} is above maximum {self.maximum}, "
                "so no value can satisfy both"
            )
        if self.allow is not None and not self.allow:
            # The one rule that can never be satisfied, and the quietest: ``allow: []``
            # constructs and stores without complaint, then rejects every value. It is
            # reported here rather than left to :meth:`check` for the same reason inverted
            # bounds are -- the fault is in the written constraint, not in whoever calls next.
            #
            # Only a *written* constraint reaches this method (a grant write and
            # :func:`parse_ceiling`); an allow-set emptied by
            # :meth:`intersected_with` is never re-checked, so narrowing two disjoint
            # allow-sets to none stays the fail-closed outcome it is meant to be.
            structural.append("an empty allow-set permits no value, so no value can satisfy it")
        if structural:
            return tuple(structural)

        problems: list[str] = []
        for member in self.allow or ():
            rejection = self.check(_PROBE, member)
            if rejection is not None:
                problems.append(
                    f"permitted value {member!r} does not satisfy the constraint's own "
                    f"rules: {rejection.reason}"
                )
        if self.has_default:
            rejection = self.check(_PROBE, self.default)
            if rejection is not None:
                # The default *value* is deliberately absent from the message, for the same
                # reason :meth:`describe` withholds it: a per-principal default can itself be
                # sensitive, and this sentence travels into logs and error payloads.
                problems.append(
                    f"the configured default does not satisfy the constraint's own rules: "
                    f"{rejection.reason}"
                )
        return tuple(problems)

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

    def intersected_with(self, other: ConstraintSet) -> ConstraintSet:
        """Return the set satisfying both, argument by argument.

        Where both sets constrain an argument, the two constraints intersect; where only one
        does, that one applies unchanged. Unlike :meth:`merged_with` this can only ever
        narrow, which is what makes it the safe direction for layering a ceiling declared in
        reviewed policy text over a principal's grants.

        Args:
            other: The set to narrow by.

        Returns:
            The intersected set.
        """
        arguments = dict(self.arguments)
        for name, constraint in other.arguments.items():
            existing = arguments.get(name)
            arguments[name] = (
                constraint if existing is None else existing.intersected_with(constraint)
            )
        return ConstraintSet(arguments=arguments)

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
        *,
        accept_unlisted: bool = False,
    ) -> DefaultsResult:
        """Fill in per-principal defaults for arguments the caller did not supply.

        A default never overrides a value that survived filtering — the caller's own valid
        input wins. Defaults are injected for dropped arguments too, which is what makes
        ``lenient`` handling useful: an over-broad request is narrowed rather than refused.
        Nothing is trimmed to a bound — the value the principal may not have was already
        rejected by :meth:`filter`, and what lands here is the gap it left.

        Every default is checked against its own constraint before it is injected, and one
        that fails is withheld rather than substituted. Without that check the way to defeat
        a constraint would be to *stop proposing a value*: a supplied value is filtered, an
        omitted one is filled in, and only the first path ran a check. The write-time check
        in :meth:`ArgumentConstraint.inconsistencies` is what a grant store enforces so this
        situation cannot be stored at all; this is the backstop for a constraint set that
        reached the decision path some other way, and like :meth:`filter` it reports rather
        than raises.

        Args:
            kept: Arguments that survived :meth:`filter`.
            parameters: Parameter names the target callable actually accepts. Defaults for
                anything else are skipped, so a stale grant cannot make a call fail with an
                unexpected keyword argument.
            accept_unlisted: Whether a default may be injected for a name ``parameters`` does
                not list. A callable declaring ``**kwargs`` accepts names its signature never
                spells, so a default for one of them is deliverable and withholding it would
                turn every constraint on a kwargs-only argument into a rule that rejects and
                refills nothing. It defaults to ``False`` because the caller is the only side
                that knows: for an ordinary signature the name filter above is what keeps a
                stale grant from making a call fail with an unexpected keyword argument, and
                that protection has to stay on unless it is explicitly stood down.

        Returns:
            The completed argument mapping, the subset that was injected, and the defaults
            that were withheld.
        """
        arguments: dict[str, object] = dict(kept)
        applied: dict[str, object] = {}
        withheld: list[RejectedArgument] = []
        for name, constraint in self.arguments.items():
            if name in arguments or not constraint.has_default:
                continue
            if name not in parameters and not accept_unlisted:
                continue
            rejection = constraint.check(name, constraint.default)
            if rejection is not None:
                # Withheld, not substituted and not coerced: the constraint says this value
                # may not be used, and it does not stop saying so because the policy is the
                # one proposing it. The argument then falls to ``missing_required`` if the
                # constraint requires it, and to the callable's own default if it does not.
                _LOGGER.error(
                    "Configured default does not satisfy its own constraint; not injecting",
                    extra={"argument": name, "rule": rejection.rule, "policy": constraint.policy},
                )
                withheld.append(
                    RejectedArgument(
                        name=name,
                        rule=rejection.rule,
                        reason=(
                            "The configured default does not satisfy its own constraint "
                            "and was not applied"
                        ),
                        policy=constraint.policy,
                    )
                )
                continue
            arguments[name] = constraint.default
            applied[name] = constraint.default
        return DefaultsResult(arguments=arguments, applied=applied, withheld=tuple(withheld))

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

    def inconsistencies(self) -> tuple[str, ...]:
        """Every self-contradiction across the whole set, each labelled with its argument.

        The set-level entry point for :meth:`ArgumentConstraint.inconsistencies`, used where
        a whole set is written or loaded at once rather than one constraint at a time.

        Returns:
            One sentence per problem, or an empty tuple when every constraint is coherent.
        """
        return tuple(
            f"argument {name!r}: {problem}"
            for name, constraint in self.arguments.items()
            for problem in constraint.inconsistencies()
        )

    def describe(self) -> dict[str, object]:
        """Summarize every constraint, for the allowed-set half of an error payload."""
        return {name: constraint.describe() for name, constraint in self.arguments.items()}


CEILING_RULES: Final = ("allow", "deny", "pattern", "minimum", "maximum", "required")
"""The rules a policy-declared ceiling may set.

``default`` is absent on purpose. :meth:`ArgumentConstraint.describe` already withholds a
default *value* from callers because a per-principal default can itself be sensitive -- it is
someone's tenant id, not a rule -- so it is grant data, and reviewed policy text is where
rules live. ``policy`` is absent because sentrykit fills it in with the id of the policy that
carried the declaration; a self-reported provenance would be unverifiable.
"""

_BACKREFERENCE: Final = re.compile(r"\\[1-9]")
"""A numbered backreference, which cannot survive being composed with another pattern."""


def parse_ceiling(declaration: str | None, *, policy: str) -> ConstraintSet:
    """Parse an argument ceiling declared in reviewed policy text.

    A ceiling is a compact JSON object mapping an argument name to the rules that bound it::

        {"limit": {"maximum": 100}, "region": {"allow": ["eu", "us"]}}

    It reaches sentrykit as a Cedar annotation value, and Cedar type-checks annotation values
    not at all -- a policy carrying a nonsense one validates clean. Every check is therefore
    ours, and every one of them happens **here**, at load, so a malformed declaration fails
    at wiring rather than silently enforcing nothing at decision time.

    Args:
        declaration: The annotation's value. A valueless annotation arrives as ``None``.
        policy: Id of the policy that carried it, recorded on every constraint so a rejection
            names the reviewed file it came from.

    Returns:
        The declared ceiling.

    Raises:
        ConfigurationError: If the declaration is absent, is not a JSON object of objects,
            names a rule a ceiling may not set, carries a value of the wrong type, declares a
            pattern that will not compile or that carries a backreference, or describes a
            constraint no value could satisfy.
    """
    if declaration is None or not declaration.strip():
        # An annotation that declares nothing enforces nothing, and a reviewer reading the
        # file would believe a ceiling exists. That is the silent failure this whole function
        # is arranged to prevent, so it is an error rather than an empty set.
        raise ConfigurationError(f"policy {policy!r} declares an empty argument ceiling")

    try:
        parsed = json.loads(declaration)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(
            f"policy {policy!r} declares an argument ceiling that is not valid JSON: {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise ConfigurationError(
            f"policy {policy!r} declares an argument ceiling that is not a JSON object; "
            'expected {"<argument>": {"<rule>": <value>}}'
        )

    arguments: dict[str, ArgumentConstraint] = {}
    for name, rules in parsed.items():
        if not isinstance(rules, dict):
            raise ConfigurationError(
                f"policy {policy!r} declares a ceiling for argument {name!r} that is not a "
                "JSON object of rules"
            )
        for rule in rules:
            if rule not in CEILING_RULES:
                raise ConfigurationError(
                    f"policy {policy!r} declares {rule!r} for argument {name!r}; a ceiling "
                    f"may set only {', '.join(CEILING_RULES)}"
                    + (
                        " -- a default is per-principal grant data, not reviewed logic"
                        if rule == "default"
                        else ""
                    )
                )
        # Sequences arrive from JSON as lists; the model wants tuples, and coercing here
        # keeps the error below about the *rule* rather than about a container type.
        fields: dict[str, object] = {
            rule: tuple(value) if isinstance(value, list) else value
            for rule, value in rules.items()
        }
        try:
            constraint = ArgumentConstraint.model_validate({**fields, "policy": policy})
        except ValidationError as exc:
            raise ConfigurationError(
                f"policy {policy!r} declares a ceiling for argument {name!r} that does not "
                f"type-check: {exc.errors()[0]['msg']}"
            ) from exc
        if constraint.pattern is not None and _BACKREFERENCE.search(constraint.pattern):
            raise ConfigurationError(
                f"policy {policy!r} declares a pattern carrying a backreference for argument "
                f"{name!r}; a ceiling's pattern is composed with the principal's own, which "
                "renumbers its groups"
            )
        problems = constraint.inconsistencies()
        if problems:
            raise ConfigurationError(
                f"policy {policy!r} declares a ceiling for argument {name!r} that cannot be "
                "satisfied: " + "; ".join(problems)
            )
        arguments[name] = constraint

    if not arguments:
        raise ConfigurationError(f"policy {policy!r} declares an empty argument ceiling")
    return ConstraintSet(arguments=arguments)
