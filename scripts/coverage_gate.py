"""Enforce the coverage floor over the modules *this* environment can actually import.

`pixi run test-cov` measures the whole package, because `--cov=sentrykit` reports every module
under it whether or not anything imported it. That is the behaviour we want in the ``all``
environment, where every optional extra is installed and a module nobody exercises is a real
finding.

It is not the behaviour we want anywhere else. The four framework integrations import fastapi,
flask, mcp and pydantic-ai, and each of the other three environments deliberately installs only
some of those — that is the point of `tests/unit/test_core_imports.py` and of the extras. A
module whose framework is absent cannot be imported, is reported at 0%, and drags the total
down for a reason that says nothing at all about the code. In the ``default`` environment those
four modules are 475 statements of guaranteed-unreachable, which is the whole difference
between 80% and 95%.

So `pytest --cov` runs with no floor of its own, and this script applies one — over the modules
this interpreter can import, and no others. Nothing is exempted for being hard to test: a
module is skipped **only** when importing it raises `ImportError`, which is a fact about the
environment rather than a judgement about the code. Every module that can be imported counts,
including the integrations, in every environment that has their extra.

Reads `coverage.xml`, which `test-cov` has just written.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Final

REPORT: Final = Path("coverage.xml")
"""Where `pixi run test-cov` writes its Cobertura report."""

FLOOR: Final = 85.0
"""Minimum percentage of statements covered, over the importable modules."""

PACKAGE: Final = "sentrykit"
"""The distribution's import root, used to turn a report filename into a module name."""


def module_name(filename: str) -> str | None:
    """Turn a path from the coverage report into an importable module name.

    Args:
        filename: A path as the report spells it, e.g. ``sentrykit/integrations/flask.py`` or
            the same with backslashes on Windows.

    Returns:
        The dotted module name, or ``None`` when the path is not part of the package.
    """
    parts = Path(filename.replace("\\", "/")).with_suffix("").parts
    if PACKAGE not in parts:
        return None
    trimmed = parts[parts.index(PACKAGE) :]
    if trimmed[-1] == "__init__":
        trimmed = trimmed[:-1]
    return ".".join(trimmed)


def importable(name: str) -> bool:
    """Whether this interpreter can import ``name``.

    Imports it for real rather than trusting :func:`importlib.util.find_spec`: every one of
    these modules *is* found on disk, and what decides the question is whether its optional
    third-party dependency is installed, which only executing the module reveals.

    Args:
        name: A dotted module name.

    Returns:
        ``True`` when the import succeeds, ``False`` when it raises :class:`ImportError`.

    Raises:
        Exception: Anything else the module raises on import. A module that fails for some
            other reason is a bug this gate must not hide.
    """
    if name in sys.modules:
        return True
    try:
        importlib.import_module(name)
    except ImportError:
        return False
    return True


def main() -> int:
    """Apply the floor and report what was counted.

    Returns:
        ``0`` when the floor is met, ``1`` otherwise.
    """
    if not REPORT.exists():
        print(f"coverage gate: {REPORT} is missing; run test-cov first", file=sys.stderr)
        return 1

    # S314 is about parsing *untrusted* XML. This file was written by the `test-cov` task that
    # runs immediately before this one, in the same working tree; if an attacker can choose its
    # contents they can already choose the code under test, and pulling in `defusedxml` as a
    # dependency of the build would buy nothing.
    root = ElementTree.parse(REPORT).getroot()  # noqa: S314
    counted = 0
    covered = 0
    skipped: list[str] = []

    for klass in root.iter("class"):
        name = module_name(klass.get("filename", ""))
        if name is None:
            continue
        if not importable(name):
            skipped.append(name)
            continue
        for line in klass.iter("line"):
            counted += 1
            if line.get("hits", "0") != "0":
                covered += 1

    if counted == 0:
        print("coverage gate: no importable modules were measured", file=sys.stderr)
        return 1

    percent = 100.0 * covered / counted
    if skipped:
        print(
            f"coverage gate: skipped {len(skipped)} module(s) this environment cannot import: "
            f"{', '.join(sorted(skipped))}"
        )
    print(f"coverage gate: {covered}/{counted} statements ({percent:.2f}%), floor {FLOOR:.0f}%")

    if percent + 1e-9 < FLOOR:
        print(
            f"coverage gate: FAIL — {percent:.2f}% is below the {FLOOR:.0f}% floor",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
