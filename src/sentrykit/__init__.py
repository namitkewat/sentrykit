"""sentrykit — lightweight, framework-agnostic authorization built on AWS Cedar.

The public API (``protect``, ``establish``, ``configure``, the store/sink/provider
registries, and the error types) is populated during the phased build described in
``dev-docs/implementation.md``. Until Phase 1 lands, this package exposes its version and
the error hierarchy only.
"""

from __future__ import annotations

from sentrykit.errors import (
    ArgumentRejected,
    AuthzDenied,
    ConfigurationError,
    DefaultUnavailable,
    NoContext,
    NoValidArguments,
    SentrykitError,
    ValidationFailed,
)

__all__ = [
    "__version__",
    "SentrykitError",
    "AuthzDenied",
    "NoContext",
    "ArgumentRejected",
    "NoValidArguments",
    "DefaultUnavailable",
    "ValidationFailed",
    "ConfigurationError",
]

__version__ = "0.0.0"
