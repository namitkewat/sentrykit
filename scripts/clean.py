#!/usr/bin/env python3
"""Remove build, test and docs artifacts.

Backs the ``pixi run clean`` and ``pixi run docs-clean`` tasks. Written in Python rather than
as a shell one-liner because the project's platform list includes ``win-64``, where ``rm -rf``
does not exist — a contributor on Windows would hit a broken governance task on their first
day.

``--docs`` removes only the documentation build tree, which is what you want between doc
edits: a full clean would also throw away the wheel and the coverage database, and rebuilding
those to re-read a page is a minute nobody should spend.

Missing paths are not an error: cleaning an already-clean tree succeeds.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path
from typing import Final

ARTIFACTS: Final[tuple[str, ...]] = (
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".coverage",
    "coverage.xml",
    "htmlcov",
    "dist",
    "build",
)
"""Everything ``clean`` removes. ``dist`` subsumes ``dist/docs``, so a full clean takes the
documentation with it and ``--docs`` is a narrowing rather than an addition."""

DOCS_ARTIFACTS: Final[tuple[str, ...]] = ("dist/docs",)
"""Everything ``docs-clean`` removes: the HTML, the PDF, the intermediate Markdown and both
llms.txt files, all of which are written under one directory for exactly this reason."""


def clean(root: Path, targets: tuple[str, ...] = ARTIFACTS) -> list[str]:
    """Delete every named artifact under ``root``.

    Args:
        root: Repository root.
        targets: Paths to remove, relative to ``root``.

    Returns:
        The paths that were actually removed, relative to ``root``.
    """
    removed: list[str] = []
    for name in targets:
        target = root / name
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
        elif target.exists():
            target.unlink()
        else:
            continue
        removed.append(name)
    return removed


def main() -> int:
    """Clean the repository root and report what went."""
    parser = argparse.ArgumentParser(
        prog="clean",
        description="Remove build, test and docs artifacts.",
    )
    parser.add_argument(
        "--docs",
        action="store_true",
        help="Remove only the documentation build tree (dist/docs).",
    )
    args = parser.parse_args()

    targets = DOCS_ARTIFACTS if args.docs else ARTIFACTS
    removed = clean(Path(__file__).resolve().parent.parent, targets)
    print("removed: " + ", ".join(removed) if removed else "nothing to clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
