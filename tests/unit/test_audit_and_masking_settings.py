"""The audit and masking settings: where records go, what keys them, and how they are masked.

``MaskDefault`` in :mod:`sentrykit.config` and ``MaskStrategyName`` in
:mod:`sentrykit.masking` spell out the same four strategies twice. That duplication is
deliberate — masking imports config, so config cannot import masking without a cycle, and
configuration is meant to sit at the bottom of the dependency graph. Deliberate duplication
still drifts, so keeping the two in step is a test's job rather than a comment's.
"""

from __future__ import annotations

from typing import get_args

import pytest
from pydantic import SecretStr

from sentrykit.config import ENV_PREFIX, MaskDefault, Settings, configure, get_settings
from sentrykit.errors import ConfigurationError
from sentrykit.masking import MaskStrategyName

SECRET = "a-very-secret-hmac-key"


@pytest.mark.unit
def test_the_two_spellings_of_the_strategy_list_stay_in_step() -> None:
    assert set(get_args(MaskDefault)) == set(get_args(MaskStrategyName))


@pytest.mark.unit
def test_the_audit_sink_dsn_is_read_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}AUDIT_SINK", "jsonl://./audit.jsonl")

    assert get_settings().audit_sink == "jsonl://./audit.jsonl"


@pytest.mark.unit
def test_no_audit_sink_is_configured_by_default() -> None:
    assert get_settings().audit_sink is None


@pytest.mark.unit
def test_the_hmac_key_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}HMAC_KEY", SECRET)

    key = get_settings().hmac_key

    assert isinstance(key, SecretStr)
    assert key.get_secret_value() == SECRET


@pytest.mark.unit
def test_the_mask_default_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}MASK_DEFAULT", "partial")

    assert get_settings().mask_default == "partial"


@pytest.mark.unit
def test_hmac_is_the_default_strategy() -> None:
    assert get_settings().mask_default == "hmac"


@pytest.mark.unit
def test_an_invalid_mask_default_is_a_configuration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}MASK_DEFAULT", "obfuscate")

    with pytest.raises(ConfigurationError) as raised:
        get_settings()

    assert "mask_default" in str(raised.value)


@pytest.mark.unit
def test_the_hmac_key_does_not_leak_into_a_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}HMAC_KEY", SECRET)

    settings = get_settings()

    assert SECRET not in repr(settings)
    assert SECRET not in str(settings)
    assert SECRET not in repr(settings.hmac_key)


@pytest.mark.unit
def test_the_hmac_key_does_not_leak_into_a_dumped_settings_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}HMAC_KEY", SECRET)

    dumped = get_settings().model_dump()

    assert SECRET not in str(dumped)
    assert SECRET not in Settings(hmac_key=SecretStr(SECRET)).model_dump_json()


@pytest.mark.unit
def test_the_debug_trace_settings_dump_cannot_carry_the_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``Governor.plan`` puts ``settings.model_dump()`` into the debug trace verbatim."""
    monkeypatch.setenv(f"{ENV_PREFIX}HMAC_KEY", SECRET)
    monkeypatch.setenv(f"{ENV_PREFIX}VERBOSITY", "debug")

    trace = {"settings": get_settings().model_dump()}

    assert SECRET not in str(trace)


@pytest.mark.unit
def test_the_audit_and_masking_settings_can_be_configured_explicitly() -> None:
    settings = configure(
        audit_sink="memory://",
        hmac_key=SecretStr(SECRET),
        mask_default="redact",
    )

    assert settings.audit_sink == "memory://"
    assert settings.mask_default == "redact"
    assert settings.hmac_key is not None
    assert settings.hmac_key.get_secret_value() == SECRET
    assert get_settings() is settings


@pytest.mark.unit
def test_an_explicit_invalid_mask_default_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError):
        configure(mask_default="obfuscate")  # type: ignore[typeddict-item]


@pytest.mark.unit
def test_the_settings_object_stays_frozen() -> None:
    settings = get_settings()

    with pytest.raises(Exception, match=r"frozen|immutable"):
        settings.mask_default = "redact"  # type: ignore[misc]
