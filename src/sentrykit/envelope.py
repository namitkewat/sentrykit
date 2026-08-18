"""The ``_authz`` envelope — what sentrykit tells the caller about its own decision.

An authorization layer that silently rewrites a caller's arguments is worse than one that
refuses them: the caller gets a plausible answer to a question they did not ask. The
envelope is the fix. It reports what was processed, what was rejected and why, and what was
defaulted, so a narrowed call is visibly narrowed — to a human reading an HTTP response, and
to a language model deciding what to do next.

Verbosity trades that transparency against leaking policy structure and argument values to
callers who should not see either:

``off``
    No envelope.
``summary``
    The decision, the action and resource, and the *names* and reasons of rejected and
    defaulted arguments — enough to explain the outcome without disclosing values.
``verbose``
    Adds the processed argument values and the offending values on rejections.
``debug``
    Adds the trace: determining policies, the policy-set hash, timings, and the effective
    settings. For development and incident response.

The envelope is a report, not the audit record. The audit record (Phase 2) is written
append-only, masked, and hash-chained regardless of what verbosity shows the caller.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from contextvars import ContextVar
from typing import Literal, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field

from sentrykit.config import Verbosity
from sentrykit.constraints import RejectedArgument

__all__ = [
    "AuthzEnvelope",
    "attach_envelope",
    "build_envelope",
    "last_envelope",
    "set_last_envelope",
]

T = TypeVar("T")

ENVELOPE_KEY: str = "_authz"
"""Key under which the envelope is attached to a mapping result."""

_LAST_ENVELOPE: ContextVar[AuthzEnvelope | None] = ContextVar(
    "sentrykit_last_envelope", default=None
)


class AuthzEnvelope(BaseModel):
    """A caller-facing report of one authorization decision.

    Attributes:
        decision: ``allow`` or ``deny``.
        action: The action that was authorized.
        resource: The resource it was authorized against.
        principal: The acting principal's uid. Omitted below ``verbose``.
        processed: The arguments the callable actually ran with. Omitted below ``verbose``.
        rejected: Arguments the policy refused, with reasons. Values are included only at
            ``verbose`` and above.
        defaults_applied: Arguments filled in from the principal's defaults. Below
            ``verbose`` the keys are still the argument names but every value is ``None``,
            so the field keeps one shape at every verbosity and a caller can always read
            ``defaults_applied.keys()``.
        obligations: Obligations the policy attached to the decision — break-the-glass
            justification, review requirements. Carried through in Phase 1 and discharged
            by the policy pack in Phase 5.
        reason: Why a denial happened, in one sentence.
        determining_policies: The policies that decided it. ``debug`` only, since policy ids
            describe the shape of the rule set.
        trace: Decision trace — policy-set hash, engine errors, timings, effective settings.
            ``debug`` only.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: Literal["allow", "deny"]
    action: str
    resource: str | None = None
    principal: str | None = None
    processed: dict[str, object] = Field(default_factory=dict)
    rejected: tuple[RejectedArgument, ...] = ()
    defaults_applied: dict[str, object] = Field(default_factory=dict)
    obligations: tuple[str, ...] = ()
    reason: str | None = None
    determining_policies: tuple[str, ...] = ()
    trace: dict[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        """Render as a JSON-ready mapping, dropping empty sections.

        Argument values are whatever the protected callable was called with, so they are not
        guaranteed to be JSON-serializable. Anything pydantic cannot render is replaced by
        its ``repr`` rather than raising: a report about a decision must not be able to fail
        the call the decision permitted.

        Returns:
            The envelope with unset and empty fields omitted, so a clean allow stays terse.
        """
        try:
            data = self.model_dump(mode="json", exclude_none=True, warnings=False, fallback=repr)
        except TypeError:  # pydantic < 2.11 has no ``fallback``
            data = self.model_dump(mode="json", exclude_none=True, warnings=False)
        return {
            key: value
            for key, value in data.items()
            if not (isinstance(value, dict | list) and len(value) == 0)
        }


def build_envelope(
    *,
    decision: Literal["allow", "deny"],
    action: str,
    resource: str | None,
    principal: str | None,
    processed: Mapping[str, object],
    rejected: tuple[RejectedArgument, ...],
    defaults_applied: Mapping[str, object],
    obligations: tuple[str, ...] = (),
    reason: str | None = None,
    determining_policies: tuple[str, ...] = (),
    trace: Mapping[str, object] | None = None,
    verbosity: Verbosity,
) -> AuthzEnvelope | None:
    """Build the envelope for one decision, trimmed to ``verbosity``.

    Trimming happens here rather than at render time so that a value excluded by verbosity is
    never carried on the object at all — a report cannot leak a field it does not hold.

    Below ``verbose`` the trimming is: no ``principal``, no ``processed``, no
    ``determining_policies`` and no ``trace``; each rejection is rebuilt without its
    offending ``value``; and ``defaults_applied`` keeps only the *names*, each mapped to
    ``None``. Mapping to ``None`` rather than dropping the section keeps one shape for the
    field across every verbosity, so a caller can always read
    ``envelope.defaults_applied.keys()`` to learn which arguments policy filled in.

    Args:
        decision: The outcome.
        action: Action uid.
        resource: Resource uid, if any.
        principal: Principal uid.
        processed: Final arguments the call ran with.
        rejected: Arguments the policy refused.
        defaults_applied: Arguments filled in from policy defaults.
        obligations: Obligations attached by the policy.
        reason: One-sentence explanation, for denials.
        determining_policies: Policies that decided the outcome.
        trace: Debug trace.
        verbosity: How much to include.

    Returns:
        The envelope, or ``None`` when ``verbosity`` is ``off``.
    """
    if verbosity == "off":
        return None

    with_values = verbosity in ("verbose", "debug")
    with_trace = verbosity == "debug"

    principal_out: str | None
    processed_out: dict[str, object]
    rejected_out: tuple[RejectedArgument, ...]
    defaults_out: dict[str, object]

    if with_values:
        principal_out = principal
        processed_out = dict(processed)
        rejected_out = rejected
        defaults_out = dict(defaults_applied)
    else:
        principal_out = None
        processed_out = {}
        # Rebuilt rather than copied so the offending value is absent from the object,
        # not merely hidden from one rendering of it.
        rejected_out = tuple(
            RejectedArgument(name=item.name, rule=item.rule, reason=item.reason, policy=item.policy)
            for item in rejected
        )
        defaults_out = dict.fromkeys(defaults_applied)

    return AuthzEnvelope(
        decision=decision,
        action=action,
        resource=resource,
        principal=principal_out,
        processed=processed_out,
        rejected=rejected_out,
        defaults_applied=defaults_out,
        obligations=obligations,
        reason=reason,
        determining_policies=determining_policies if with_trace else (),
        trace=dict(trace) if with_trace and trace is not None else None,
    )


def attach_envelope(result: T, envelope: AuthzEnvelope | None) -> T:
    """Attach ``envelope`` to a result and record it as the context's last envelope.

    A mapping result gets the envelope under ``_authz`` in place — which is what an agent
    tool result or a JSON handler return usually is, and the reason the README can promise
    the report travels with the answer. Any other result is returned untouched: rewrapping
    it would change the protected callable's return type and break both static typing and
    every caller. Those callers read :func:`last_envelope` instead, which is how the
    framework providers in Phase 3 attach it to an HTTP response.

    Args:
        result: Whatever the protected callable returned.
        envelope: The envelope, or ``None`` to attach nothing.

    Returns:
        ``result`` — the same object, mutated in place when it is a mapping.
    """
    set_last_envelope(envelope)
    if envelope is None:
        return result
    if isinstance(result, MutableMapping):
        # ``T`` is preserved: the same object comes back, only with one key added. The cast
        # is needed because a narrowing on ``T`` does not tell mypy the keys are strings.
        cast("MutableMapping[str, object]", result)[ENVELOPE_KEY] = envelope.as_dict()
    return result


def last_envelope() -> AuthzEnvelope | None:
    """Return the envelope from the most recent decision in this context.

    Scoped to the current ``ContextVar`` context, so concurrent tasks and threads each see
    their own.

    Returns:
        The most recent envelope, or ``None`` if there has been no decision or verbosity is
        ``off``.
    """
    return _LAST_ENVELOPE.get()


def set_last_envelope(envelope: AuthzEnvelope | None) -> None:
    """Record ``envelope`` as this context's most recent decision.

    Called by the engine on both allow and deny, so a provider rendering an error response
    has the same detail available as one rendering a success.
    """
    _LAST_ENVELOPE.set(envelope)
