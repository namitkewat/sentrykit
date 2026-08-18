"""The core imports no web framework and no agent SDK.

Checked *statically*. Walking ``sys.modules`` would pass vacuously — nothing imports FastAPI
in a unit run whether or not the core would — so every core source file is parsed with
``ast`` and its ``import`` statements are read directly. The file list is discovered from the
installed package directory, so a core module added tomorrow is covered without editing this
test; only ``sentrykit/integrations/`` is excluded, because framework imports are exactly
what lives there.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import sentrykit

PACKAGE_ROOT = Path(sentrykit.__file__).parent
INTEGRATIONS_DIR = "integrations"
FORBIDDEN_PACKAGES = frozenset({"fastapi", "flask", "starlette", "mcp", "pydantic_ai"})

DOCUMENTED_CORE_MODULES = frozenset(
    {
        "__init__.py",
        "cedar.py",
        "config.py",
        "constraints.py",
        "context.py",
        "decorator.py",
        "engine.py",
        "envelope.py",
        "errors.py",
    }
)


def _core_sources() -> list[Path]:
    """Every ``.py`` file shipped in the package except the integration adapters."""
    return sorted(
        path
        for path in PACKAGE_ROOT.rglob("*.py")
        if INTEGRATIONS_DIR not in path.relative_to(PACKAGE_ROOT).parts
    )


def _relative(path: Path) -> str:
    return path.relative_to(PACKAGE_ROOT).as_posix()


def _imported_top_level_packages(source: str) -> set[str]:
    """The top-level package name of every absolute import in ``source``."""
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    return imported


@pytest.mark.unit
@pytest.mark.parametrize("source_path", _core_sources(), ids=_relative)
def test_a_core_module_imports_no_web_framework_or_agent_sdk(source_path: Path) -> None:
    imported = _imported_top_level_packages(source_path.read_text(encoding="utf-8"))

    offenders = sorted(FORBIDDEN_PACKAGES & imported)

    assert not offenders, f"{_relative(source_path)} imports {offenders}"


@pytest.mark.unit
def test_the_scan_reaches_every_documented_core_module() -> None:
    scanned = {_relative(path) for path in _core_sources()}

    assert scanned >= DOCUMENTED_CORE_MODULES


@pytest.mark.unit
def test_the_integration_adapters_are_outside_the_scan() -> None:
    assert (PACKAGE_ROOT / INTEGRATIONS_DIR).is_dir()
    assert not any(INTEGRATIONS_DIR in path.parts for path in _core_sources())


@pytest.mark.unit
@pytest.mark.parametrize(
    "source",
    [
        "import fastapi",
        "import fastapi.responses",
        "from flask import Flask",
        "import starlette",
        "from mcp.server import Server",
        "from pydantic_ai import Agent",
        "if True:\n    import fastapi",
        "def late() -> None:\n    from flask import Flask",
    ],
)
def test_the_scanner_would_catch_a_forbidden_import_wherever_it_hides(source: str) -> None:
    assert FORBIDDEN_PACKAGES & _imported_top_level_packages(source)


@pytest.mark.unit
def test_the_scanner_ignores_the_packages_the_core_is_allowed_to_use() -> None:
    allowed = "import cedarpy\nfrom pydantic import BaseModel\nfrom sentrykit.cedar import Entity"

    assert not FORBIDDEN_PACKAGES & _imported_top_level_packages(allowed)
