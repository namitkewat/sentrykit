"""``cedarpy`` is imported by exactly one module.

`cedar.py`'s own docstring opens by claiming to be "the only module in sentrykit that imports
Cedar", and the rest of the core is built on that being true: everything downstream talks to
`CedarDecision`, a normalized value object, which is what keeps the decision path unit-testable
without a policy set and what leaves room for a different engine binding behind that seam.

Phase 2 nearly broke it. `FilesystemPolicySource` needs Cedar's validator, and reaching for
`cedarpy.validate_policies` directly would have put a second import in a second module — at
which point the claim becomes a comment rather than a property. `cedar.validate_policies` and
`cedar.policy_annotations` exist so the policy layer can get what it needs through the seam.

Checked statically, for the same reason `test_core_imports.py` is: walking `sys.modules` would
pass vacuously.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import sentrykit

PACKAGE_ROOT = Path(sentrykit.__file__).parent
CEDAR_MODULE = "cedar.py"


def _sources() -> list[Path]:
    """Every ``.py`` file shipped in the package."""
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def _relative(path: Path) -> str:
    return path.relative_to(PACKAGE_ROOT).as_posix()


def _imports_cedarpy(source: str) -> bool:
    """Whether ``source`` imports ``cedarpy`` at any level, in any statement form."""
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import) and any(
            alias.name.split(".")[0] == "cedarpy" for alias in node.names
        ):
            return True
        if (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module
            and node.module.split(".")[0] == "cedarpy"
        ):
            return True
    return False


@pytest.mark.unit
@pytest.mark.parametrize(
    "source_path", [path for path in _sources() if path.name != CEDAR_MODULE], ids=_relative
)
def test_no_module_other_than_cedar_imports_cedarpy(source_path: Path) -> None:
    assert not _imports_cedarpy(source_path.read_text(encoding="utf-8")), (
        f"{_relative(source_path)} imports cedarpy; route it through sentrykit.cedar instead"
    )


@pytest.mark.unit
def test_the_scan_is_not_vacuous_because_cedar_itself_trips_it() -> None:
    cedar_source = (PACKAGE_ROOT / CEDAR_MODULE).read_text(encoding="utf-8")

    assert _imports_cedarpy(cedar_source)


@pytest.mark.unit
@pytest.mark.parametrize(
    "source",
    [
        "import cedarpy",
        "import cedarpy.something",
        "from cedarpy import validate_policies",
        "if True:\n    import cedarpy",
        "def late() -> None:\n    from cedarpy import PolicySet",
    ],
)
def test_the_scanner_would_catch_a_cedarpy_import_wherever_it_hides(source: str) -> None:
    assert _imports_cedarpy(source)


@pytest.mark.unit
@pytest.mark.parametrize(
    "source",
    [
        "from sentrykit.cedar import policy_annotations",
        "from sentrykit.cedar import validate_policies",
        "import sentrykit.cedar",
        "cedarpy = 'not an import'",
    ],
)
def test_the_scanner_ignores_going_through_the_seam(source: str) -> None:
    assert not _imports_cedarpy(source)


@pytest.mark.unit
def test_the_policy_layer_can_still_reach_what_it_needs_through_the_seam() -> None:
    from sentrykit.cedar import policy_annotations, validate_policies

    annotations = policy_annotations(
        '@id("p")\n@obligations("notify:secops")\npermit (principal, action, resource);'
    )
    schema = (
        "entity User;\nentity Tool;\n"
        'action "yes" appliesTo { principal: [User], resource: [Tool] };'
    )
    outcome = validate_policies('permit (principal, action == Action::"nope", resource);', schema)

    assert annotations[0].declared_id == "p"
    assert annotations[0].annotation("obligations") == "notify:secops"
    assert not outcome.passed
    assert outcome.describe()
