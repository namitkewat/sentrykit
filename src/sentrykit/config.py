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
    What to do when the *engine* fails (unparseable policies, a Cedar evaluation error, an
    unavailable audit sink) — ``closed`` refuses the call, ``open`` proceeds
    and records the failure. A policy *denial* is not an engine failure: it denies under both
    modes, as does a missing principal.
``redaction``
    Whether sensitive argument values are masked before they leave the engine. The flag is
    carried through the envelope; the strategies themselves live in
    :mod:`sentrykit.masking`.
``envelope_on_success``
    Whether a successful invocation gets an envelope attached at all. Denials always carry
    their detail on the raised error, regardless.
``audit_sink``
    DSN of the sink decisions are written to — ``jsonl://./audit.jsonl``. Unset means no
    audit trail is emitted at all, which is the right default for a library that must not
    start writing files because it was imported.
``hmac_key``
    Key for the ``hmac`` masking strategy. Held as a ``SecretStr`` so it cannot be printed
    into a debug trace or a repr by accident.
``mask_default``
    Which strategy an unqualified ``mask:`` obligation or a bare ``Sensitive()`` marker
    resolves to. ``hmac`` by default, because it is the only strategy that keeps records
    correlatable without keeping the value.

Note that ``redaction`` governs the caller-facing envelope and the operational logs only. It
does **not** reach the audit path: masking before an immutable write is not configurable,
because that write is the one that cannot be taken back.
"""

from __future__ import annotations

import logging
import re
from typing import Final, Literal, TypedDict

from pydantic import SecretStr, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing_extensions import Unpack

from sentrykit.errors import ConfigurationError

__all__ = [
    "ENV_PREFIX",
    "ArgHandling",
    "FailMode",
    "MaskDefault",
    "Settings",
    "SettingsOverrides",
    "Verbosity",
    "apply_overrides",
    "clear_action_overrides",
    "configure",
    "get_settings",
    "override_action",
    "reset_settings",
    "settings_for",
]

_logger: Final = logging.getLogger("sentrykit.config")

Verbosity = Literal["off", "summary", "verbose", "debug"]
"""How much of the ``_authz`` envelope to render."""

ArgHandling = Literal["lenient", "strict"]
"""Whether a policy-rejected argument is dropped (``lenient``) or fatal (``strict``)."""

FailMode = Literal["closed", "open"]
"""Whether an engine failure refuses the call (``closed``) or lets it through (``open``)."""

MaskDefault = Literal["redact", "partial", "hmac", "tokenize"]
"""Default masking strategy.

Spelled out here rather than imported from :mod:`sentrykit.masking` so that configuration
stays at the bottom of the dependency graph — masking imports config, not the other way
round. The two are kept in step by a unit test.
"""

ENV_PREFIX: Final = "SENTRYKIT_"
"""Environment-variable prefix, e.g. ``SENTRYKIT_VERBOSITY=debug``."""

_ACTION_UID_RE: Final = re.compile(
    r'^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*::"(?P<id>.*)"$'
)
"""Matches a Cedar uid so an override key can be reduced to its bare action id.

Deliberately local: config resolves the two spellings of an action name and nothing more, so
it has no reason to know about :mod:`sentrykit.cedar`.
"""


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
    audit_sink: str | None
    hmac_key: SecretStr | None
    mask_default: MaskDefault


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
    audit_sink: str | None = None
    hmac_key: SecretStr | None = None
    mask_default: MaskDefault = "hmac"


_settings: Settings | None = None
"""The cached process-wide settings. Loaded lazily, so importing sentrykit reads no env."""

_action_overrides: dict[str, SettingsOverrides] = {}
"""Per-action overrides, keyed by the normalized (bare id) spelling of the action."""


def _normalize_action(action: str) -> str:
    """Reduce an action name to the one spelling used as an override key.

    Args:
        action: A full Cedar uid (``Action::"tool.search"``) or a bare id (``tool.search``).

    Returns:
        The bare action id, so both spellings address the same override.
    """
    candidate = action.strip()
    match = _ACTION_UID_RE.match(candidate)
    return match.group("id") if match else candidate


def _describe(exc: ValidationError) -> str:
    """Render a pydantic validation failure as a message naming the offending fields.

    A bad ``SENTRYKIT_FAIL_MODE`` should read as a configuration mistake, not as a pydantic
    traceback the operator has to decode.

    Args:
        exc: The failure raised while building :class:`Settings`.

    Returns:
        A single-line, sentence-case description of every rejected field.
    """
    problems = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "<settings>"
        problems.append(f"{location}: {error['msg']}")
    return f"Invalid sentrykit settings (env prefix {ENV_PREFIX}): {'; '.join(problems)}"


def _build(overrides: SettingsOverrides) -> Settings:
    """Construct :class:`Settings` from the environment plus ``overrides``.

    Args:
        overrides: Fields to set explicitly; the environment supplies the rest.

    Returns:
        The validated settings.

    Raises:
        ConfigurationError: If any resolved value is invalid.
    """
    try:
        return Settings(**overrides)
    except ValidationError as exc:
        raise ConfigurationError(_describe(exc)) from exc


def get_settings() -> Settings:
    """Return the process-wide settings, loading them from the environment on first use.

    Returns:
        The cached global :class:`Settings`.

    Raises:
        ConfigurationError: If an environment variable holds a value the model rejects.
    """
    global _settings
    if _settings is None:
        _settings = _build({})
        _logger.debug("Loaded settings from environment with prefix %s", ENV_PREFIX)
    return _settings


def configure(**overrides: Unpack[SettingsOverrides]) -> Settings:
    """Replace the process-wide settings with environment values plus ``overrides``.

    Args:
        **overrides: Fields to override on top of what the environment supplies.

    Returns:
        The newly installed global :class:`Settings`.

    Raises:
        ConfigurationError: If the resulting combination is invalid.
    """
    global _settings
    _settings = _build(overrides)
    _logger.debug("Configured settings explicitly; fields=%s", sorted(overrides))
    return _settings


def reset_settings() -> None:
    """Drop the cached global settings and every per-action override.

    Intended for tests and for hosts that reload configuration at runtime; the next
    :func:`get_settings` re-reads the environment.
    """
    global _settings
    _settings = None
    _action_overrides.clear()


def override_action(action: str, **overrides: Unpack[SettingsOverrides]) -> None:
    """Register settings that apply only to ``action``.

    Registering twice for the same action replaces the earlier override outright, so what
    applies to an action stays answerable by reading a single call.

    Args:
        action: The action this override applies to, either the bare id
            (``"tool.search_orders"``) or the full Cedar uid (``Action::"tool.search_orders"``).
            Both spellings resolve to the same override.
        **overrides: Fields to override for that action only.
    """
    key = _normalize_action(action)
    _action_overrides[key] = overrides
    _logger.debug("Registered settings override for action %s; fields=%s", key, sorted(overrides))


def clear_action_overrides() -> None:
    """Remove every per-action override, leaving the global settings in place."""
    _action_overrides.clear()


def settings_for(action: str | None = None) -> Settings:
    """Resolve the effective settings for ``action``.

    Args:
        action: The action being authorized, or ``None`` for the global settings.

    Returns:
        The global settings, with any override registered for ``action`` applied on top.
    """
    return apply_overrides(get_settings(), action)


def apply_overrides(base: Settings, action: str | None) -> Settings:
    """Layer the override registered for ``action`` on top of ``base``.

    Split out from :func:`settings_for` so a governor constructed with explicit settings
    still honors per-action overrides -- otherwise configuring a governor would silently
    disable a mechanism the host had already relied on.

    Args:
        base: The settings to start from.
        action: The action being authorized, in either spelling, or ``None``.

    Returns:
        ``base`` unchanged when nothing is registered for ``action``, otherwise a copy with
        the override applied.
    """
    if action is None or not _action_overrides:
        return base
    override = _action_overrides.get(_normalize_action(action))
    if not override:
        return base
    return base.model_copy(update=dict(override))
