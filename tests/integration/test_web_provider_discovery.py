"""Both web providers are reachable by name, through the same door a third party would use.

Built-ins are not special-cased: ``fastapi`` reaches the registry by exactly the
path ``sentrykit-django`` would. That is only demonstrated if the in-process registration the
``@register_context_provider`` decorator made at import time is taken *away* first — otherwise
every assertion below would pass on the decorator alone and the published entry point could be
missing entirely.

So the fixture empties the registry and puts it back afterwards, and what answers ``fastapi://``
in between is the ``sentrykit.context_providers`` entry point in the installed distribution's
metadata.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("flask")

from examples.fastapi_app.policy import POLICY_TEXT

import sentrykit
from sentrykit.integrations.fastapi import FastAPIProvider
from sentrykit.integrations.flask import FlaskProvider
from sentrykit.registry import (
    available,
    build_context_provider,
    clear_registry,
    registrations,
    remember,
)


@pytest.fixture
def undiscovered_providers() -> Iterator[None]:
    """Empty the context-provider registry for one test, and restore it afterwards.

    Both provider modules are imported by the time this runs, so their decorators have already
    fired and will not fire again — clearing the registry really does leave entry-point
    discovery as the only way a provider can be found.
    """
    saved = dict(registrations("context_provider"))
    clear_registry("context_provider")
    yield
    clear_registry("context_provider")
    for plugin in saved.values():
        remember(plugin)


@pytest.mark.integration
def test_the_fastapi_provider_is_reachable_by_its_dsn(undiscovered_providers: None) -> None:
    provider = build_context_provider("fastapi://")

    assert isinstance(provider, FastAPIProvider)
    assert provider.name == "fastapi"


@pytest.mark.integration
def test_the_flask_provider_is_reachable_by_its_dsn(undiscovered_providers: None) -> None:
    provider = build_context_provider("flask://")

    assert isinstance(provider, FlaskProvider)
    assert provider.name == "flask"


@pytest.mark.integration
def test_both_web_providers_are_listed_as_available(undiscovered_providers: None) -> None:
    names = available("context_provider")

    assert "fastapi" in names
    assert "flask" in names


@pytest.mark.integration
def test_a_dsn_built_provider_reads_the_principal_header_the_dsn_names(
    undiscovered_providers: None,
) -> None:
    """A provider built from a bare DSN has no application auth to call, so it reads a header."""
    provider = build_context_provider("fastapi://?header=x-caller")

    assert provider.principal_header == "x-caller"


@pytest.mark.integration
def test_install_accepts_a_context_provider_by_dsn() -> None:
    """``install(context_provider="fastapi://")`` is the no-second-wiring-step form."""
    governor = sentrykit.install(POLICY_TEXT, context_provider="fastapi://")

    assert isinstance(governor.context_provider, FastAPIProvider)
    assert sentrykit.current_governor() is governor


@pytest.mark.integration
def test_install_accepts_an_already_built_context_provider() -> None:
    """The door a host with its own ``identify`` callback comes through."""
    provider = FlaskProvider(identify=lambda request: "alice")

    governor = sentrykit.install(POLICY_TEXT, context_provider=provider)

    assert governor.context_provider is provider
