"""Settings: where they come from, how they fail, and how an action deviates from them."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentrykit.config import (
    Settings,
    apply_overrides,
    clear_action_overrides,
    configure,
    get_settings,
    override_action,
    reset_settings,
    settings_for,
)
from sentrykit.errors import ConfigurationError


@pytest.mark.unit
def test_defaults_are_the_conservative_ones_when_nothing_is_set() -> None:
    settings = get_settings()

    assert settings.verbosity == "summary"
    assert settings.arg_handling == "lenient"
    assert settings.fail_mode == "closed"
    assert settings.redaction is True
    assert settings.envelope_on_success is True


@pytest.mark.unit
def test_prefixed_environment_variables_are_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTRYKIT_VERBOSITY", "debug")
    monkeypatch.setenv("SENTRYKIT_ARG_HANDLING", "strict")
    monkeypatch.setenv("SENTRYKIT_FAIL_MODE", "open")
    monkeypatch.setenv("SENTRYKIT_REDACTION", "false")
    reset_settings()

    settings = get_settings()

    assert settings.verbosity == "debug"
    assert settings.arg_handling == "strict"
    assert settings.fail_mode == "open"
    assert settings.redaction is False


@pytest.mark.unit
def test_an_unprefixed_variable_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERBOSITY", "debug")
    reset_settings()

    assert get_settings().verbosity == "summary"


@pytest.mark.unit
def test_a_rejected_environment_value_raises_configuration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTRYKIT_FAIL_MODE", "sideways")
    reset_settings()

    with pytest.raises(ConfigurationError):
        get_settings()


@pytest.mark.unit
def test_a_rejected_explicit_value_raises_configuration_error() -> None:
    with pytest.raises(ConfigurationError):
        configure(verbosity="loud")  # type: ignore[typeddict-item]


@pytest.mark.unit
def test_configure_layers_over_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTRYKIT_ARG_HANDLING", "strict")
    reset_settings()

    settings = configure(verbosity="verbose")

    assert settings.verbosity == "verbose"
    assert settings.arg_handling == "strict"
    assert get_settings() == settings


@pytest.mark.unit
def test_reset_makes_the_next_read_see_the_environment_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure(verbosity="debug")
    monkeypatch.setenv("SENTRYKIT_VERBOSITY", "off")

    reset_settings()

    assert get_settings().verbosity == "off"


@pytest.mark.unit
def test_settings_cannot_be_mutated_in_place() -> None:
    settings = get_settings()

    with pytest.raises(ValidationError):
        settings.verbosity = "debug"  # type: ignore[misc]


@pytest.mark.unit
def test_an_action_override_applies_to_that_action_only() -> None:
    override_action("tool.search_orders", arg_handling="strict")

    assert settings_for('Action::"tool.search_orders"').arg_handling == "strict"
    assert settings_for('Action::"tool.export_orders"').arg_handling == "lenient"
    assert settings_for(None).arg_handling == "lenient"
    assert get_settings().arg_handling == "lenient"


@pytest.mark.unit
def test_an_action_override_resolves_from_either_spelling() -> None:
    override_action('Action::"tool.search_orders"', verbosity="debug")

    assert settings_for("tool.search_orders").verbosity == "debug"
    assert settings_for('Action::"tool.search_orders"').verbosity == "debug"


@pytest.mark.unit
def test_an_action_override_only_replaces_the_fields_it_names() -> None:
    configure(verbosity="verbose", fail_mode="open")
    override_action("tool.search_orders", arg_handling="strict")

    effective = settings_for("tool.search_orders")

    assert effective.arg_handling == "strict"
    assert effective.verbosity == "verbose"
    assert effective.fail_mode == "open"


@pytest.mark.unit
def test_clearing_action_overrides_restores_the_global_settings() -> None:
    override_action("tool.search_orders", arg_handling="strict")

    clear_action_overrides()

    assert settings_for("tool.search_orders").arg_handling == "lenient"


@pytest.mark.unit
def test_resetting_settings_also_drops_action_overrides() -> None:
    override_action("tool.search_orders", arg_handling="strict")

    reset_settings()

    assert settings_for("tool.search_orders").arg_handling == "lenient"


@pytest.mark.unit
def test_apply_overrides_honors_an_action_override_on_an_explicit_base() -> None:
    base = Settings(verbosity="verbose", fail_mode="open")
    override_action("tool.search_orders", verbosity="debug")

    effective = apply_overrides(base, "tool.search_orders")

    assert effective.verbosity == "debug"
    assert effective.fail_mode == "open"
    assert base.verbosity == "verbose"


@pytest.mark.unit
def test_apply_overrides_leaves_a_base_alone_when_nothing_is_registered() -> None:
    base = Settings(verbosity="verbose")

    assert apply_overrides(base, "tool.search_orders") == base
    assert apply_overrides(base, None) == base
