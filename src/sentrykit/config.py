"""Runtime settings for sentrykit.

Settings are read from the environment with the ``SENTRYKIT_`` prefix (or set explicitly by
the host application through :func:`configure`) and resolved per protected action, so a
single noisy or strict action can deviate from the process-wide default without a second
configuration mechanism.

The knobs and their meaning:

``verbosity``
    How much of the ``_authz`` envelope is rendered — ``off`` emits none at all, ``summary``
    names what happened, ``verbose`` adds the argument values, ``debug`` adds the decision
    trace.
``arg_handling``
    ``lenient`` silently drops arguments the policy rejects; ``strict`` raises
    :class:`~sentrykit.errors.ArgumentRejected` on the first violation.
``fail_mode``
    What to do when the *engine* fails (unparseable policies, a Cedar evaluation error, and
    from Phase 2 an unavailable audit sink) — ``closed`` refuses the call, ``open`` proceeds
    and records the failure. A policy *denial* is not an engine failure: it denies under both
    modes, as does a missing principal.
``redaction``
    Whether sensitive argument values are masked before they leave the engine. Phase 1 wires
    the flag through the envelope; the masking strategies themselves land in Phase 2.
``envelope_on_success``
    Whether a successful invocation gets an envelope attached at all. Denials always carry
    their detail on the raised error, regardless.
"""

from __future__ import annotations

from typing import Final, Literal, TypedDict

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing_extensions import Unpack

__all__ = [
    "ENV_PREFIX",
    "ArgHandling",
    "FailMode",
    "Settings",
    "SettingsOverrides",
    "Verbosity",
    "clear_action_overrides",
    "configure",
    "get_settings",
    "override_action",
    "reset_settings",
    "settings_for",
]

Verbosity = Literal["off", "summary", "verbose", "debug"]
"""How much of the ``_authz`` envelope to render."""

ArgHandling = Literal["lenient", "strict"]
"""Whether a policy-rejected argument is dropped (``lenient``) or fatal (``strict``)."""

FailMode = Literal["closed", "open"]
"""Whether an engine failure refuses the call (``closed``) or lets it through (``open``)."""

ENV_PREFIX: Final = "SENTRYKIT_"
"""Environment-variable prefix, e.g. ``SENTRYKIT_VERBOSITY=debug``."""


class SettingsOverrides(TypedDict, total=False):
    """Keyword overrides accepted by :func:`configure` and :func:`override_action`.

    Declared as a ``TypedDict`` so the variadic keyword arguments of those two functions stay
    fully typed instead of collapsing to ``Any``.
    """

    verbosity: Verbosity
    arg_handling: ArgHandling
    fail_mode: FailMode
    redaction: bool
    envelope_on_success: bool


class Settings(BaseSettings):
    """Process-wide sentrykit configuration.

    Frozen: an effective per-action configuration is produced by copying, never by mutating
    the global, so a per-action override cannot leak into unrelated calls.
    """

    model_config = SettingsConfigDict(env_prefix=ENV_PREFIX, frozen=True, extra="ignore")

    verbosity: Verbosity = "summary"
    arg_handling: ArgHandling = "lenient"
    fail_mode: FailMode = "closed"
    redaction: bool = True
    envelope_on_success: bool = True


def get_settings() -> Settings:
    """Return the process-wide settings, loading them from the environment on first use.

    Returns:
        The cached global :class:`Settings`.

    Raises:
        ConfigurationError: If an environment variable holds a value the model rejects.
    """
    raise NotImplementedError


def configure(**overrides: Unpack[SettingsOverrides]) -> Settings:
    """Replace the process-wide settings with environment values plus ``overrides``.

    Args:
        **overrides: Fields to override on top of what the environment supplies.

    Returns:
        The newly installed global :class:`Settings`.

    Raises:
        ConfigurationError: If the resulting combination is invalid.
    """
    raise NotImplementedError


def reset_settings() -> None:
    """Drop the cached global settings and every per-action override.

    Intended for tests and for hosts that reload configuration at runtime; the next
    :func:`get_settings` re-reads the environment.
    """
    raise NotImplementedError


def override_action(action: str, **overrides: Unpack[SettingsOverrides]) -> None:
    """Register settings that apply only to ``action``.

    Args:
        action: The action this override applies to, either the bare id
            (``"tool.search_orders"``) or the full Cedar uid (``Action::"tool.search_orders"``).
            Both spellings resolve to the same override.
        **overrides: Fields to override for that action only.
    """
    raise NotImplementedError


def clear_action_overrides() -> None:
    """Remove every per-action override, leaving the global settings in place."""
    raise NotImplementedError


def settings_for(action: str | None = None) -> Settings:
    """Resolve the effective settings for ``action``.

    Args:
        action: The action being authorized, or ``None`` for the global settings.

    Returns:
        The global settings, with any override registered for ``action`` applied on top.
    """
    raise NotImplementedError
