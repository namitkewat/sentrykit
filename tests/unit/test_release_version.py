"""The version is declared in one place, and the files that restate it agree with it.

``sentrykit.__version__`` is the single source of truth: ``[tool.hatch.version]`` reads it for
the distribution metadata, and ``.github/workflows/release.yml`` reconciles the pushed tag
against it before it will publish anything. Two repository files restate that number and neither
is checked anywhere else, so both are asserted here.

``CHANGELOG.md`` is the first. The release workflow builds the GitHub release notes by lifting
the ``## [<version>]`` section out of it, and falls back to a one-line pointer when there is no
such section. That fallback is deliberate — a release with thin notes beats a release that fails
on its notes — but it is silent in the only direction that matters: the run goes green and the
missing notes are found later by whoever reads the release. That is exactly how ``0.1.0rc1``
shipped. The heading is cheap to assert, and asserting it here puts the check inside
``pixi run check``, which the release job runs on itself before it publishes anything.

``pixi.toml`` is the second. Its ``[workspace] version`` is descriptive — nothing in the build or
publish path reads it — which is precisely why it sat at ``0.1.0`` while the package was
``0.1.0rc1`` and nothing complained. A restated number that is wrong and harmless today is a
restated number that is wrong and quoted tomorrow.

Both are sources rather than package data, so this module skips rather than fails where they are
absent, which is the case for an installed distribution.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sentrykit import __version__

REPO_ROOT = Path(__file__).resolve().parents[2]


def _source(name: str) -> str:
    """Read a repository source file, skipping where there is no checkout to read."""
    path = REPO_ROOT / name
    if not path.is_file():
        pytest.skip(f"{name} is absent; this is not a source checkout")
    return path.read_text(encoding="utf-8")


def test_changelog_has_a_section_for_this_version() -> None:
    """A release of this version would otherwise publish the fallback notes."""
    heading = f"## [{__version__}]"
    lines = _source("CHANGELOG.md").splitlines()
    assert any(line.startswith(heading) for line in lines), (
        f"CHANGELOG.md has no line starting {heading!r}, so releasing {__version__} would fall "
        f"back to its one-line notes instead of the changelog section."
    )


def test_pixi_workspace_version_matches_the_package() -> None:
    """The one copy of the version that no build or publish step would catch drifting."""
    manifest = _source("pixi.toml")
    # Every `version` key in the file, and there must be exactly one: the manifest declares it
    # in `[workspace]` and nowhere else. Matching the lone key rather than scoping to a table
    # is deliberate — the file's own header comment mentions `[workspace]` in prose, so
    # scoping by that substring finds the comment and asserts against an empty string. If a
    # second `version` key ever appears, this should fail and be read by a person rather than
    # quietly pick one.
    declared = re.findall(r'^version = "([^"]+)"', manifest, re.M)
    assert declared == [__version__], (
        f"pixi.toml declares version(s) {declared!r}; expected exactly one, {__version__!r}. "
        f"sentrykit.__version__ is what the release tag is reconciled against, so this copy "
        f"is the one that drifts."
    )
