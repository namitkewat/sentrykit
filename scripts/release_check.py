"""Build the distribution and prove every advertised extra actually installs and imports.

`pyproject.toml` advertises seven extras. Each one is a promise — ``pip install
sentrykit[fastapi]`` gives you a working ``sentrykit.integrations.fastapi`` — and every one of
them is a promise the repository's own test suite structurally cannot check: the tests run
against an editable install of the source tree, in a pixi environment that already has every
framework present. A missing dependency, a typo in an extra's name, or a package-data rule
that ships only ``*.py`` is invisible there and immediate for the first person who installs it.

So this script does what that person does. It builds the real artifacts, then for each extra
creates a throwaway virtual environment, installs the built **wheel** with that extra, and
imports the modules the extra is supposed to enable. It also runs the ``sentrykit`` console
script, because a declared entry point that does not execute is a broken command rather than a
missing one.

It needs an index, which is why it is a task and not a test: `pytest` must stay runnable
offline. The half of this check that needs no network — what the wheel *contains* — lives in
`tests/integration/test_release_artifacts.py` and runs in the ordinary suite.

```bash
pixi run -e all release-check
```

Exits non-zero if any extra fails, so it fits in front of a publish step unchanged.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import venv
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parent.parent
"""The repository root, whatever directory the script was invoked from."""

CORE_MODULES: Final = ("sentrykit", "sentrykit.cli", "sentrykit.policy.loader")
"""Imported for every extra: the core, the command line, and the shipped policy pack's loader.

The loader is in the list because it is the module that reads the pack's ``*.cedar`` files off
disk, so importing it in a fresh install is the cheapest way to notice a wheel that shipped the
Python and left the data behind.
"""

EXTRAS: Final[dict[str, tuple[str, ...]]] = {
    "fastapi": ("sentrykit.integrations.fastapi",),
    "flask": ("sentrykit.integrations.flask",),
    "fastmcp": ("sentrykit.integrations.fastmcp",),
    "pydantic-ai": ("sentrykit.integrations.pydantic_ai",),
    "web": ("sentrykit.integrations.fastapi", "sentrykit.integrations.flask"),
    "agents": ("sentrykit.integrations.fastmcp", "sentrykit.integrations.pydantic_ai"),
    "all": (
        "sentrykit.integrations.fastapi",
        "sentrykit.integrations.flask",
        "sentrykit.integrations.fastmcp",
        "sentrykit.integrations.pydantic_ai",
    ),
}
"""Every extra, and the integration modules installing it must make importable.

The aggregate extras (``web``, ``agents``, ``all``) are listed separately rather than derived,
because what is being checked is that *the extra resolves to what it claims* — deriving the
expectation from the same table the answer comes from would check nothing.
"""

TIMEOUT: Final = 900
"""Seconds allowed for any one subprocess. Generous: a cold `pip install` fetches torch-sized
dependency trees on a bad day, and a timeout here reads as a failure of the extra."""


@dataclass(frozen=True, slots=True)
class Result:
    """What happened for one extra.

    Attributes:
        extra: The extra's name, as it is spelled in ``sentrykit[<extra>]``.
        ok: Whether it installed *and* imported.
        detail: One line for the table — what was proven, or what failed.
    """

    extra: str
    ok: bool
    detail: str


def run(command: list[str], *, label: str) -> subprocess.CompletedProcess[str]:
    """Run one subprocess, capturing everything it said.

    Args:
        command: The argument vector. Never a shell string: every element here is either an
            interpreter path this script computed or a literal, so there is nothing for a
            shell to re-interpret.
        label: What the command is doing, for the progress line.

    Returns:
        The completed process, whatever its exit status — the caller decides what a failure
        means, because a failed *build* aborts and a failed *extra* is one row of the table.
    """
    print(f"  {label} ...", flush=True)
    return subprocess.run(  # noqa: S603 - fixed argv, no shell, no caller-supplied strings
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT,
    )


def build_distribution(dist: Path) -> tuple[Path, Path]:
    """Build the wheel and the sdist, and insist both appeared.

    Both, because they fail differently: a wheel is what `pip install` uses, and an sdist is
    what a downstream distributor rebuilds from. A release that ships one without the other is
    half a release.

    Args:
        dist: The output directory. Cleared of previous artifacts first, so a stale wheel from
            an earlier version cannot be the thing that gets tested.

    Returns:
        The wheel and the sdist.

    Raises:
        SystemExit: If the build fails, or produces only one of the two.
    """
    for stale in [*dist.glob("*.whl"), *dist.glob("*.tar.gz")]:
        stale.unlink()

    completed = run(
        [sys.executable, "-m", "build", "--outdir", str(dist), str(ROOT)],
        label=f"building wheel and sdist into {dist}",
    )
    if completed.returncode != 0:
        print(completed.stdout, file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        raise SystemExit("release check: `python -m build` failed")

    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit(
            f"release check: expected exactly one wheel and one sdist in {dist}; found "
            f"{[path.name for path in wheels]} and {[path.name for path in sdists]}"
        )
    print(f"  built {wheels[0].name} and {sdists[0].name}")
    return wheels[0], sdists[0]


def interpreter_of(environment: Path) -> Path:
    """Return the Python inside a virtual environment, on either platform."""
    candidate = environment / ("Scripts" if sys.platform == "win32" else "bin")
    return candidate / ("python.exe" if sys.platform == "win32" else "python")


def console_script_of(environment: Path) -> Path:
    """Return the installed ``sentrykit`` command inside a virtual environment."""
    candidate = environment / ("Scripts" if sys.platform == "win32" else "bin")
    return candidate / ("sentrykit.exe" if sys.platform == "win32" else "sentrykit")


def check_extra(extra: str, modules: tuple[str, ...], wheel: Path) -> Result:
    """Install the wheel with one extra into a throwaway venv and import what it enables.

    Args:
        extra: The extra to install.
        modules: The integration modules the extra is supposed to make importable.
        wheel: The built wheel.

    Returns:
        The result. Never raises for an ordinary failure: one broken extra must not stop the
        other six from being checked, or the first bad row hides every row after it.
    """
    wanted = (*CORE_MODULES, *modules)
    # ``ignore_cleanup_errors`` because this ships for win-64: deleting a virtual environment
    # whose interpreter has only just exited raises ``PermissionError`` often enough, and a
    # leftover temp directory must not turn a passing extra into a crashed release check.
    with tempfile.TemporaryDirectory(
        prefix=f"sentrykit-{extra}-", ignore_cleanup_errors=True
    ) as workspace:
        environment = Path(workspace) / "venv"
        venv.create(environment, with_pip=True, clear=True)
        python = interpreter_of(environment)

        installed = run(
            [str(python), "-m", "pip", "install", "--quiet", f"{wheel}[{extra}]"],
            label=f"[{extra}] installing the wheel",
        )
        if installed.returncode != 0:
            return Result(extra, ok=False, detail=_last_line(installed.stderr or installed.stdout))

        program = "\n".join(f"import {module}" for module in wanted)
        imported = run(
            [str(python), "-c", program],
            label=f"[{extra}] importing {len(wanted)} module(s)",
        )
        if imported.returncode != 0:
            return Result(extra, ok=False, detail=_last_line(imported.stderr or imported.stdout))

        invoked = run(
            [str(console_script_of(environment)), "--version"],
            label=f"[{extra}] running the sentrykit console script",
        )
        if invoked.returncode != 0:
            return Result(
                extra,
                ok=False,
                detail=f"console script failed: {_last_line(invoked.stderr or invoked.stdout)}",
            )

    return Result(extra, ok=True, detail=f"{len(wanted)} module(s) + console script")


def _last_line(output: str) -> str:
    """Reduce a subprocess's output to the one line worth putting in a table cell."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[-1][:100] if lines else "no output"


def print_table(results: list[Result]) -> None:
    """Print the per-extra outcome as a fixed-width table.

    Args:
        results: One per extra, in the order they were checked.
    """
    width = max((len(result.extra) for result in results), default=5)
    print()
    print(f"{'extra'.ljust(width)}  result  detail")
    print(f"{'-' * width}  ------  {'-' * 40}")
    for result in results:
        verdict = "PASS" if result.ok else "FAIL"
        print(f"{result.extra.ljust(width)}  {verdict.ljust(6)}  {result.detail}")
    print()


def main() -> int:
    """Build, check every extra, and report.

    Returns:
        ``0`` when every extra installed and imported, ``1`` otherwise.
    """
    parser = argparse.ArgumentParser(
        prog="release_check",
        description=(
            "Build the distribution and install the wheel with each advertised extra into a "
            "throwaway virtual environment, importing what that extra should enable. Requires "
            "network access."
        ),
    )
    parser.add_argument(
        "--dist",
        default=str(ROOT / "dist"),
        metavar="DIR",
        help="Where the artifacts are built (default: %(default)s).",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Reuse the artifacts already in --dist instead of rebuilding.",
    )
    parser.add_argument(
        "--extras",
        default=",".join(EXTRAS),
        metavar="LIST",
        help="Comma-separated extras to check (default: every advertised one).",
    )
    args = parser.parse_args()

    dist = Path(args.dist)
    dist.mkdir(parents=True, exist_ok=True)

    requested = [name.strip() for name in str(args.extras).split(",") if name.strip()]
    unknown = [name for name in requested if name not in EXTRAS]
    if unknown:
        print(
            f"release check: unknown extra(s) {unknown}; known: {sorted(EXTRAS)}",
            file=sys.stderr,
        )
        return 1

    if args.skip_build:
        wheels = sorted(dist.glob("*.whl"))
        if len(wheels) != 1:
            print(
                f"release check: --skip-build needs exactly one wheel in {dist}; found "
                f"{[path.name for path in wheels]}",
                file=sys.stderr,
            )
            return 1
        wheel = wheels[0]
        print(f"  reusing {wheel.name}")
    else:
        wheel, _ = build_distribution(dist)

    results = [check_extra(extra, EXTRAS[extra], wheel) for extra in requested]
    print_table(results)

    failed = [result.extra for result in results if not result.ok]
    if failed:
        print(f"release check: FAIL - {len(failed)} extra(s) broken: {', '.join(failed)}")
        return 1
    print(f"release check: PASS - {len(results)} extra(s) install and import from the wheel")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
