"""Both agent providers are reachable by name, through the same door a third party would use.

The mirror of `tests/integration/test_web_provider_discovery.py`, and it makes the same point
for the same reason. ADR-004 says built-ins are not special-cased: ``fastmcp`` reaches the
registry by exactly the path ``sentrykit-langchain`` would. That is only demonstrated if the
in-process registration the ``@register_context_provider`` decorator made at import time is
taken *away* first — otherwise every assertion below would pass on the decorator alone and the
published entry point could be missing from the distribution entirely.

So the fixture empties the registry and puts it back afterwards, and what answers ``fastmcp://``
in between is the ``sentrykit.context_providers`` entry point in the installed distribution's
metadata.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

pytest.importorskip("mcp")
pytest.importorskip("pydantic_ai")

from examples.fastmcp_server.policy import POLICY_TEXT

import sentrykit
from sentrykit.integrations.fastmcp import FastMCPProvider
from sentrykit.integrations.pydantic_ai import PydanticAIProvider
from sentrykit.registry import (
    available,
    build_context_provider,
    clear_registry,
    discovered,
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
def test_the_fastmcp_provider_is_reachable_by_its_dsn(undiscovered_providers: None) -> None:
    provider = build_context_provider("fastmcp://")

    assert isinstance(provider, FastMCPProvider)
    assert provider.name == "fastmcp"


@pytest.mark.integration
def test_the_pydantic_ai_provider_is_reachable_by_its_dsn(undiscovered_providers: None) -> None:
    provider = build_context_provider("pydantic-ai://")

    assert isinstance(provider, PydanticAIProvider)
    assert provider.name == "pydantic-ai"


@pytest.mark.integration
def test_both_agent_providers_are_listed_as_available(undiscovered_providers: None) -> None:
    names = available("context_provider")

    assert "fastmcp" in names
    assert "pydantic-ai" in names


@pytest.mark.integration
def test_the_entry_point_sweep_is_what_finds_them(undiscovered_providers: None) -> None:
    """Not "the module happened to be imported": the sweep itself, enumerated.

    :func:`~sentrykit.registry.discovered` reads
    ``importlib.metadata.entry_points(group="sentrykit.context_providers")`` and loads each
    one, so a provider that appears here is published in the distribution's metadata — which
    is the only claim that means anything to a third party.
    """
    found = {plugin.name: plugin for plugin in discovered("context_provider")}

    assert found["fastmcp"].source == "entry-point"
    assert found["pydantic-ai"].source == "entry-point"
    assert found["fastmcp"].factory.__self__ is FastMCPProvider  # type: ignore[attr-defined]
    assert found["pydantic-ai"].factory.__self__ is PydanticAIProvider  # type: ignore[attr-defined]


@pytest.mark.integration
def test_a_dsn_built_mcp_provider_reads_the_meta_key_the_dsn_names(
    undiscovered_providers: None,
) -> None:
    """A provider built from a bare DSN has no application auth to call, so it reads a name.

    On MCP that name addresses a ``_meta`` key rather than a header — same option, different
    carrier, which is exactly why the base class's vocabulary was kept.
    """
    provider = build_context_provider("fastmcp://?header=x-who")

    assert isinstance(provider, FastMCPProvider)
    assert provider.principal_header == "x-who"


@pytest.mark.integration
def test_a_dsn_built_agent_provider_reads_the_deps_attribute_the_dsn_names(
    undiscovered_providers: None,
) -> None:
    """``deps`` is an application's own type, so which field holds the principal is an option."""
    provider = build_context_provider("pydantic-ai://?deps_attribute=user")

    assert isinstance(provider, PydanticAIProvider)
    assert provider.deps_attribute == "user"


@pytest.mark.integration
def test_a_bare_agent_dsn_falls_back_to_the_shipped_names(undiscovered_providers: None) -> None:
    """No options means the defaults, and an *empty* option means the defaults too.

    ``?header=`` is a configuration mistake, and wiring a provider that reads ``""`` would turn
    it into a silent one.
    """
    bare = build_context_provider("pydantic-ai://")
    empty = build_context_provider("pydantic-ai://?deps_attribute=")

    assert isinstance(bare, PydanticAIProvider)
    assert isinstance(empty, PydanticAIProvider)
    assert bare.deps_attribute == "principal"
    assert empty.deps_attribute == "principal"


@pytest.mark.integration
def test_both_agent_providers_establish_the_agent_channel(undiscovered_providers: None) -> None:
    """``when { context.channel == "agent" }`` applies without the server saying anything."""
    mcp_provider = build_context_provider("fastmcp://")
    agent_provider = build_context_provider("pydantic-ai://")

    assert isinstance(mcp_provider, FastMCPProvider)
    assert isinstance(agent_provider, PydanticAIProvider)
    assert mcp_provider.channel == "agent"
    assert agent_provider.channel == "agent"


@pytest.mark.integration
def test_install_accepts_an_agent_context_provider_by_dsn() -> None:
    """``install(context_provider="fastmcp://")`` is the no-second-wiring-step form."""
    governor = sentrykit.install(POLICY_TEXT, context_provider="fastmcp://")

    assert isinstance(governor.context_provider, FastMCPProvider)
    assert sentrykit.current_governor() is governor


@pytest.mark.integration
def test_install_accepts_an_already_built_agent_context_provider() -> None:
    """The door a host with its own ``identify`` callback comes through."""
    provider = PydanticAIProvider(identify=lambda ctx: "alice")

    governor = sentrykit.install(POLICY_TEXT, context_provider=provider)

    assert governor.context_provider is provider
