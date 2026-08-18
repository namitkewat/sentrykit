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

from collections.abc import Mapping
from contextvars import ContextVar
from typing import Literal, TypeVar

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
        defaults_applied: Arguments filled in from the principal's defaults. Names only
            below ``verbose``.
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

        Returns:
            The envelope with unset and empty fields omitted, so a clean allow stays terse.
        """
        raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError


def last_envelope() -> AuthzEnvelope | None:
    """Return the envelope from the most recent decision in this context.

    Scoped to the current ``ContextVar`` context, so concurrent tasks and threads each see
    their own.

    Returns:
        The most recent envelope, or ``None`` if there has been no decision or verbosity is
        ``off``.
    """
    raise NotImplementedError


def set_last_envelope(envelope: AuthzEnvelope | None) -> None:
    """Record ``envelope`` as this context's most recent decision.

    Called by the engine on both allow and deny, so a provider rendering an error response
    has the same detail available as one rendering a success.
    """
    raise NotImplementedError
