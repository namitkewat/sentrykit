"""A third-party backend reaches the registry with no change to sentrykit.

This is the one plugin claim that cannot be tested from inside the package: everything else
about the plugin machinery can be exercised through the ``register_*`` decorators, but "an
installed distribution is discovered" is a statement about ``importlib.metadata`` and
``sys.path``, and only a real distribution on disk proves it.

So the test *builds* one — a module plus a ``.dist-info`` directory carrying ``METADATA`` and
an ``entry_points.txt`` — puts it on ``sys.path``, and asks the registry for it by DSN.
Nothing is installed, no subprocess runs, and the fixture takes the path back down afterwards.
The point is that ``sentrykit`` needs no edit for any of it to work: ``dummy`` is not
mentioned anywhere in the package.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from sentrykit.registry import (
    ENTRY_POINT_GROUPS,
    available,
    build_audit_sink,
    clear_registry,
    discovered,
    registrations,
    remember,
)

DISTRIBUTION = "sentrykit-dummy"
VERSION = "9.9.9"
MODULE = "sentrykit_dummy_sink"

MODULE_SOURCE = '''
"""A third-party audit sink. Imports nothing from sentrykit."""

from __future__ import annotations


class DummySink:
    """Structurally an ``AuditSink``; satisfies the protocol without importing it."""

    def __init__(self, target: str = "", options: dict[str, str] | None = None) -> None:
        self.target = target
        self.options = dict(options or {})
        self.written: list[object] = []

    @property
    def name(self) -> str:
        return "dummy"

    @classmethod
    def from_dsn(cls, dsn: object) -> "DummySink":
        return cls(
            target=getattr(dsn, "target", ""),
            options=dict(getattr(dsn, "options", {}) or {}),
        )

    def write(self, record: object) -> None:
        self.written.append(record)

    def query(self, window: object) -> "Iterator[object]":
        return iter(self.written)
'''

METADATA = f"""Metadata-Version: 2.1
Name: {DISTRIBUTION}
Version: {VERSION}
Summary: A throwaway sentrykit audit sink, built on disk by the test suite.
"""

ENTRY_POINTS = f"""[sentrykit.audit_sinks]
dummy = {MODULE}:DummySink
"""


@pytest.fixture
def installed_plugin(tmp_path: Path) -> Iterator[Path]:
    """Put a synthetic distribution on ``sys.path`` and take it back off afterwards."""
    (tmp_path / f"{MODULE}.py").write_text(MODULE_SOURCE, encoding="utf-8")
    dist_info = tmp_path / f"{DISTRIBUTION.replace('-', '_')}-{VERSION}.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(METADATA, encoding="utf-8")
    (dist_info / "entry_points.txt").write_text(ENTRY_POINTS, encoding="utf-8")

    saved = {kind: dict(registrations(kind)) for kind in ENTRY_POINT_GROUPS}
    sys.path.insert(0, str(tmp_path))
    importlib.invalidate_caches()
    clear_registry()
    try:
        yield tmp_path
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop(MODULE, None)
        importlib.invalidate_caches()
        clear_registry()
        for plugins in saved.values():
            for plugin in plugins.values():
                remember(plugin)


@pytest.mark.integration
def test_an_installed_third_party_sink_is_discovered_by_its_dsn(installed_plugin: Path) -> None:
    sink = build_audit_sink("dummy://./somewhere?flush=true")

    plugin_module = importlib.import_module(MODULE)
    assert isinstance(sink, plugin_module.DummySink)
    assert sink.name == "dummy"
    assert sink.target == "./somewhere"
    assert sink.options == {"flush": "true"}


@pytest.mark.integration
def test_a_discovered_sink_is_listed_alongside_the_shipped_ones(installed_plugin: Path) -> None:
    assert "dummy" in available("audit_sink")


@pytest.mark.integration
def test_discovery_records_which_distribution_supplied_the_backend(
    installed_plugin: Path,
) -> None:
    found = {plugin.name: plugin for plugin in discovered("audit_sink")}

    assert "dummy" in found
    assert found["dummy"].source == "entry-point"
    assert found["dummy"].distribution == DISTRIBUTION
    assert found["dummy"].version == VERSION


@pytest.mark.integration
def test_a_discovered_sink_accepts_records_like_any_other(installed_plugin: Path) -> None:
    sink = build_audit_sink("dummy://")

    sink.write({"record_id": "r-1"})

    assert list(sink.query(None)) == [{"record_id": "r-1"}]


@pytest.mark.integration
def test_sentrykit_itself_never_mentions_the_plugin(installed_plugin: Path) -> None:
    """The whole claim: no core change was needed to reach a third-party backend."""
    import sentrykit

    package_root = Path(sentrykit.__file__).parent
    sources = "\n".join(path.read_text(encoding="utf-8") for path in package_root.rglob("*.py"))

    assert MODULE not in sources
    assert DISTRIBUTION not in sources


@pytest.mark.integration
def test_an_in_process_registration_is_not_replaced_by_a_discovered_one(
    installed_plugin: Path,
) -> None:
    """A host that named its own backend must not have it swapped out by an installed one."""
    from sentrykit.registry import register_audit_sink

    @register_audit_sink("dummy")
    class HostSink:
        name = "dummy"

        @classmethod
        def from_dsn(cls, dsn: object) -> HostSink:
            return cls()

        def write(self, record: object) -> None:
            """Discard."""

        def query(self, window: object) -> Iterator[object]:
            return iter(())

    assert isinstance(build_audit_sink("dummy://"), HostSink)


@pytest.mark.integration
def test_the_plugin_disappears_again_once_it_is_off_the_path(tmp_path: Path) -> None:
    """Guards the fixture itself: a leaked ``sys.path`` entry would poison later tests."""
    assert "dummy" not in available("audit_sink")
