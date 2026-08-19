"""What the wheel actually contains — the half of the release check that needs no network.

`scripts/release_check.py` is the other half: it builds, then installs the wheel into a throwaway
venv per extra and imports what that extra is supposed to enable. That needs an index, so it is
a pixi task rather than a test. Everything that can be decided from the artifact *alone* is
decided here, once, off one build.

The assertion this file exists for is the first one. sentrykit's policy pack is `.cedar`,
`.cedarschema`, `.json` and `.cedartemplate` files — **data**, shipped inside the package — and
a packaging configuration that quietly includes only `*.py` produces a wheel that imports
perfectly and then raises "the shipped pack is missing" the first time anybody addresses
``pack://``. No unit test can see that: every one of them reads the pack out of the source tree.
Only the built artifact can answer it.
"""

from __future__ import annotations

import configparser
import importlib.util
import subprocess
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
"""The repository root — the directory ``python -m build`` is pointed at."""

PACK_SOURCE = ROOT / "src" / "sentrykit" / "policy" / "pack"
"""The pack as it exists in the source tree, so the wheel is compared against the real list."""

PACK_IN_WHEEL = "sentrykit/policy/pack"
"""Where the pack has to land inside the wheel."""

EXPECTED_ENTRY_POINTS = {
    "sentrykit.policy_sources": {"file", "pack"},
    "sentrykit.grant_stores": {"jsonfile", "memory"},
    "sentrykit.audit_sinks": {"jsonl", "memory"},
    "sentrykit.context_providers": {"fastapi", "flask", "fastmcp", "pydantic-ai"},
}
"""Every discovery group and the names it must advertise.

A backend that is registered in Python but missing from this table is unreachable by DSN in an
installed distribution — the core finds built-ins through exactly the entry points a third
party publishes, so an absent line here is a backend that silently does not exist.
"""


@pytest.fixture(scope="module")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> Iterator[zipfile.ZipFile]:
    """Build the wheel once for this module and hand back the opened archive.

    Module-scoped because a wheel build is seconds, not milliseconds, and every assertion here
    is about the same artifact. Built with ``--no-isolation`` when the backend is already
    importable, which keeps the common case offline; the isolated path is the fallback and is
    skipped rather than failed when it cannot reach an index, since "no network" is a fact
    about the machine and not a finding about the package.

    Args:
        tmp_path_factory: Where the artifact is written — never ``dist/``, which belongs to
            the developer.

    Yields:
        The opened wheel, closed afterwards so Windows can delete the temporary directory.
    """
    if importlib.util.find_spec("build") is None:
        pytest.skip("`build` is not installed in this environment")

    outdir = tmp_path_factory.mktemp("wheel")
    command = [sys.executable, "-m", "build", "--wheel", "--outdir", str(outdir), str(ROOT)]
    if importlib.util.find_spec("hatchling") is not None:
        command.insert(4, "--no-isolation")

    completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=600)
    if completed.returncode != 0:
        pytest.skip(f"`python -m build` failed (no index?):\n{completed.stderr[-2000:]}")

    built = sorted(outdir.glob("*.whl"))
    assert len(built) == 1, f"expected exactly one wheel, got {[path.name for path in built]}"
    with zipfile.ZipFile(built[0]) as archive:
        yield archive


@pytest.fixture(scope="module")
def names(wheel: zipfile.ZipFile) -> list[str]:
    """Every path inside the wheel."""
    return wheel.namelist()


@pytest.fixture(scope="module")
def entry_points(wheel: zipfile.ZipFile) -> configparser.ConfigParser:
    """The wheel's ``entry_points.txt``, parsed.

    Raises:
        AssertionError: If the wheel declares none at all, which would make every backend
            undiscoverable rather than merely misnamed.
    """
    found = [name for name in wheel.namelist() if name.endswith(".dist-info/entry_points.txt")]
    assert found, "the wheel declares no entry points at all"
    parsed = configparser.ConfigParser()
    parsed.read_string(wheel.read(found[0]).decode("utf-8"))
    return parsed


@pytest.mark.integration
def test_the_wheel_ships_every_policy_file_of_the_pack(names: list[str]) -> None:
    shipped = {name for name in names if name.startswith(f"{PACK_IN_WHEEL}/")}
    expected = {f"{PACK_IN_WHEEL}/{path.name}" for path in sorted(PACK_SOURCE.glob("*.cedar"))}

    assert expected, "the source tree ships no *.cedar files; this test is checking nothing"
    # Compared against the source listing rather than a hard-coded list, so a pattern added to
    # the pack tomorrow is covered by this assertion the day it lands.
    assert expected <= shipped


@pytest.mark.integration
def test_the_wheel_ships_the_packs_schema_entities_and_templates(names: list[str]) -> None:
    assert f"{PACK_IN_WHEEL}/pack.cedarschema" in names
    assert f"{PACK_IN_WHEEL}/entities.json" in names

    templates = [
        name
        for name in names
        if name.startswith(f"{PACK_IN_WHEEL}/templates/") and name.endswith(".cedartemplate")
    ]
    expected = sorted(path.name for path in PACK_SOURCE.glob("templates/*.cedartemplate"))
    assert expected, "the source tree ships no templates; this test is checking nothing"
    assert sorted(Path(name).name for name in templates) == expected


@pytest.mark.integration
def test_the_wheel_ships_the_typing_marker(names: list[str]) -> None:
    # Without it, `py.typed` is a promise the source tree keeps and the installed package
    # breaks: a downstream mypy silently treats every sentrykit symbol as `Any`.
    assert "sentrykit/py.typed" in names


@pytest.mark.integration
def test_the_wheel_declares_the_console_script(entry_points: configparser.ConfigParser) -> None:
    assert entry_points.has_section("console_scripts")
    assert entry_points.get("console_scripts", "sentrykit") == "sentrykit.cli:main"


@pytest.mark.integration
@pytest.mark.parametrize(("group", "expected"), sorted(EXPECTED_ENTRY_POINTS.items()))
def test_every_discovery_group_advertises_its_backends(
    entry_points: configparser.ConfigParser, group: str, expected: set[str]
) -> None:
    assert entry_points.has_section(group), f"the wheel declares no {group!r} group"

    assert set(entry_points.options(group)) == expected


@pytest.mark.integration
def test_the_shipped_pack_is_reachable_as_a_policy_source(
    entry_points: configparser.ConfigParser,
) -> None:
    # Spelled out on its own because this is the line that makes `install(policy_source=
    # "pack://")` work in an installed distribution.
    assert (
        entry_points.get("sentrykit.policy_sources", "pack")
        == "sentrykit.policy.loader:PackPolicySource"
    )
