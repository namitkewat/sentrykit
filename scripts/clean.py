#!/usr/bin/env python3
"""Remove build, test and docs artifacts.

Backs the ``pixi run clean`` task. Written in Python rather than as a shell one-liner
because the project's platform list includes ``win-64``, where ``rm -rf`` does not exist —
a contributor on Windows would hit a broken governance task on their first day.

Missing paths are not an error: cleaning an already-clean tree succeeds.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ARTIFACTS: tuple[str, ...] = (
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".coverage",
    "coverage.xml",
    "htmlcov",
    "dist",
    "build",
    "site",
)


def clean(root: Path) -> list[str]:
    """Delete every known artifact under ``root``.

    Args:
        root: Repository root.

    Returns:
        The paths that were actually removed, relative to ``root``.
    """
    removed: list[str] = []
    for name in ARTIFACTS:
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
    removed = clean(Path(__file__).resolve().parent.parent)
    print("removed: " + ", ".join(removed) if removed else "nothing to clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
