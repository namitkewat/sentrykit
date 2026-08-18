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
    """Raised when the coarse Cedar gate denies the invocation."""

    def __init__(self, action: str, resource: str | None, determining_policies: list[str]) -> None:
        self.action = action
        self.resource = resource
        self.determining_policies = determining_policies
        super().__init__(
            f"denied: action={action!r} resource={resource!r} "
            f"determining_policies={determining_policies}"
        )


class ArgumentRejected(SentrykitError):
    """Raised (in strict mode) when a supplied argument violates its policy constraint."""

    def __init__(self, name: str, reason: str, policy: str | None = None) -> None:
        self.name = name
        self.reason = reason
        self.policy = policy
        super().__init__(f"argument {name!r} rejected: {reason}")


class NoValidArguments(SentrykitError):
    """Raised when every supplied argument was rejected and no defaults can complete the call."""

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
