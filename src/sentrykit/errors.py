"""Exception hierarchy for sentrykit.

Every error carries structured, machine-readable detail so context providers can render a
useful response (and so the audit record is precise). Never raise a bare ``Exception``.
"""

from __future__ import annotations

from typing import Any


class SentrykitError(Exception):
    """Base class for all sentrykit errors."""


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
