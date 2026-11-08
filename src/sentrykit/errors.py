"""Exception hierarchy for sentrykit.

Every error carries structured, machine-readable detail so context providers can render a
useful response (and so the audit record is precise). Never raise a bare ``Exception``.
"""

from __future__ import annotations

from typing import Any


class SentrykitError(Exception):
    """Base class for all sentrykit errors.

    When :attr:`audit_failure` is set, both halves of it matter. The refusal is *correct*: it
    is the one the decision produced, it stands, and it is not softened because nobody could
    write it down — deciding and recording are separate guarantees, and losing the second does
    not forfeit the first. And the refusal is *unrecorded*: there is no audit record that this
    boundary was tested, so nothing in the trail will later show a caller probing which
    actions exist and which argument values are accepted.

    It lives on the base class because any refusal can arrive this way, and it travels with
    the exception so that whoever renders the refusal — a provider's response, a host's own
    error handler, a report — can say so at the point a reader is looking. The alternative is
    to leave the fact in an operational log, and the operational channel is deliberately not
    the audit trail: a fact that only ever lands there is a fact nobody can prove afterwards.

    Attributes:
        audit_failure: The audit sink failure that stopped this refusal from being recorded,
            or ``None`` — which is what it is on every refusal a reachable sink accepted, so
            on all but a vanishing fraction of them.
    """

    audit_failure: AuditUnavailable | None = None


class ConfigurationError(SentrykitError):
    """Raised when sentrykit is misconfigured (bad settings, missing backend, etc.)."""


class NoContext(SentrykitError):
    """Raised when a protected callable is invoked with no resolvable principal.

    This is a fail-closed condition: no ambient context and no explicit override means the
    call is denied.
    """

    def __init__(self, action: str) -> None:
        self.action = action
        super().__init__(f"no principal in context for action {action!r}; denying (fail-closed)")


class AuthzDenied(SentrykitError):
    """Raised when the coarse Cedar gate denies the invocation.

    ``engine_errors`` separates the two ways a call can fail to be authorized. A plain
    denial has none: a policy said no, or no policy said yes. A denial carrying engine
    errors means Cedar could not evaluate cleanly -- an unparseable policy, a missing
    attribute -- and ``fail_mode="closed"`` turned that failure into a refusal. Operators
    need to tell those apart, because the second is a bug in the policy set, not a correctly
    enforced boundary.
    """

    def __init__(
        self,
        action: str,
        resource: str | None,
        determining_policies: list[str],
        engine_errors: list[str] | None = None,
    ) -> None:
        """Record a refusal.

        Args:
            action: The full Cedar uid of the refused action, e.g. ``Action::"tool.search"``
                -- always the uid spelling, never the bare id, so an error message is
                unambiguous about which entity type was involved.
            resource: The full Cedar uid of the resource, in the same spelling.
            determining_policies: Ids of the policies that decided it, named by their ``@id``
                annotation where they declare one. Empty on a default deny, which means no
                policy matched at all.
            engine_errors: Cedar's own errors when this refusal came from an engine failure,
                and empty when it is an ordinary policy denial.
        """
        self.action = action
        self.resource = resource
        self.determining_policies = determining_policies
        self.engine_errors = engine_errors or []
        detail = (
            f"denied: action={action!r} resource={resource!r} "
            f"determining_policies={determining_policies}"
        )
        if self.engine_errors:
            detail += f" engine_errors={self.engine_errors}"
        super().__init__(detail)


class ReservedKey(SentrykitError):
    """Raised when caller-supplied data spells one of Cedar's reserved ``__`` keys.

    Cedar's request JSON reserves record keys beginning with ``__`` for its own escape
    forms: ``__entity`` promotes a plain record into a typed entity reference, and
    ``__extn`` into an extension value. A caller who can put either key inside an argument
    can therefore hand the evaluator an entity reference of their own choosing, and an
    argument-aware ``forbid`` will read it as a genuine one -- so
    ``forbid ... when { !(context.args.region in Group::"approved") }`` is satisfied by
    passing the approved group itself as the region, because Cedar's ``in`` is reflexive.

    sentrykit refuses the request instead of deciding it, and the refusal is deliberately
    *not* arbitrated by ``fail_mode``: a forged request is not a broken policy set, and
    ``fail_mode="open"`` exists to tolerate operator error, never caller input.

    This closes the *spelling*, not the general question of who chooses an entity's type. A
    parameter a callable annotates as :class:`~sentrykit.cedar.EntityRef` is a caller-chosen
    entity by construction, and the same reflexive ``in`` applies to it -- see
    :func:`~sentrykit.cedar.coerce_value` for how a policy pins that down.

    Attributes:
        key: The reserved key that was supplied.
        path: Where it appeared inside the request context, e.g. ``args.region`` or
            ``args.regions[2].id``. Empty when the value was coerced on its own.
    """

    def __init__(self, key: str, path: str = "") -> None:
        self.key = key
        self.path = path
        located = f" at {path!r}" if path else ""
        super().__init__(
            f"reserved key {key!r}{located} is not permitted in supplied data: keys "
            "beginning with '__' are Cedar's own escape forms and may not be spelled by "
            "a caller"
        )


class ArgumentRejected(SentrykitError):
    """Raised (in strict mode) when a supplied argument violates its policy constraint."""

    def __init__(self, name: str, reason: str, policy: str | None = None) -> None:
        self.name = name
        self.reason = reason
        self.policy = policy
        super().__init__(f"argument {name!r} rejected: {reason}")


class NoValidArguments(SentrykitError):
    """Raised when the caller supplied arguments and the policy rejected every one of them.

    Deliberately raised even when defaults could complete the call. Filling in defaults after
    discarding everything the caller asked for would answer a question they did not ask --
    the caller wanted orders for one customer and would silently get their own. Partial
    rejection is different: some of the request stood, so narrowing the rest to what the
    principal is entitled to is a refinement rather than a substitution.

    ``allowed`` describes what the principal *may* pass, so the caller can retry correctly.
    """

    def __init__(self, allowed: dict[str, Any], rejected: list[dict[str, Any]]) -> None:
        self.allowed = allowed
        self.rejected = rejected
        super().__init__("no valid arguments remain after policy filtering")


class DefaultUnavailable(SentrykitError):
    """Raised when a required argument is missing and no policy default is configured."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"argument {name!r} is required but no policy default is configured")


class ValidationFailed(SentrykitError):
    """Raised when the filtered/defaulted arguments fail the callable's pydantic model.

    ``errors`` mirrors pydantic's structured ``ValidationError.errors()`` output.
    """

    def __init__(self, errors: list[dict[str, Any]]) -> None:
        self.errors = errors
        super().__init__(f"argument validation failed with {len(errors)} error(s)")


class AuditUnavailable(SentrykitError):
    """Raised when an audit record could not be written to its sink.

    An operational failure, not an authorization one — but under ``fail_mode="closed"`` it
    still refuses the governed call, because an action nobody can prove happened is an action
    that should not have happened ("can't prove it, don't do it", per the logging standards).

    ``sink`` names the backend that failed; ``failures`` carries one entry per sink when a
    fan-out composite raised, so an operator can see whether one replica or all of them are
    down.
    """

    def __init__(
        self, sink: str, reason: str, failures: list[dict[str, Any]] | None = None
    ) -> None:
        self.sink = sink
        self.reason = reason
        self.failures = failures or []
        super().__init__(f"audit sink {sink!r} could not accept the record: {reason}")
