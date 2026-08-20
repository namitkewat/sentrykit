"""Every part of ``cedarpy`` that :mod:`sentrykit.cedar` reaches for, asserted directly.

``cedar.py`` is the only module that imports ``cedarpy``, and it does so by attribute: it
calls ``cedarpy.PolicySet.from_str``, reads ``result.diagnostics.id_annotations_by_reason``,
and so on. None of that is checked until a decision is actually made, so a dependency
resolving to a version without one of those names produces an ``AttributeError`` at wiring
time — in a host's application, on their first protected call, not here.

The declared floor is what should prevent that, and this file is the check that the floor is
still doing its job. It fails on the *installed* package, so a resolver that drifts below the
surface ``cedar.py`` needs breaks a test rather than a deployment.

Two kinds of assertion, because a name existing is not the same as it behaving:

* the **names** ``cedar.py`` dereferences, each one it actually uses;
* the **shapes** it reads off the returned objects — a decision's diagnostics, a validation
  result's errors, and the policy JSON that annotations are read out of.

There is deliberately no assertion about a ``Policy`` object. ``cedarpy`` exposes no such
class: a parsed ``PolicySet`` is an opaque handle, and the only way to see a policy's
annotations is to render the *text* with ``policies_to_json_str``. That is why obligations and
argument ceilings are read from the policy source rather than from the engine, and a test
asserting a ``Policy.annotations`` attribute would be asserting an API that does not exist.
"""

from __future__ import annotations

import json
from importlib.metadata import requires, version

import cedarpy
import pytest

from sentrykit.cedar import EntityRef, PolicyEngine

POLICIES = """
@id("support-may-search")
@obligations("notify:secops")
permit (
  principal in Role::"support",
  action == Action::"tool.search",
  resource == Tool::"orders"
);

@id("suspended-is-forbidden")
forbid (principal, action, resource)
when { principal has suspended && principal.suspended };
"""

ENTITIES_JSON = json.dumps(
    [
        {"uid": {"type": "Role", "id": "support"}, "attrs": {}, "parents": []},
        {"uid": {"type": "Tool", "id": "orders"}, "attrs": {}, "parents": []},
    ]
)

SCHEMA = """
entity Role;
entity Tool;
entity User in [Role];
action "tool.search" appliesTo { principal: [User], resource: [Tool], context: {} };
"""


# --- the names cedar.py dereferences ----------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "name",
    [
        "Decision",
        "Diagnostics",
        "Entities",
        "PolicySet",
        "Schema",
        "format_policies",
        "is_authorized",
        "policies_to_json_str",
        "validate_policies",
    ],
)
def test_the_module_exposes_every_attribute_the_engine_reaches_for(name: str) -> None:
    assert hasattr(cedarpy, name), f"cedarpy exposes no {name!r}; sentrykit.cedar requires it"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("holder", "name"),
    [
        ("PolicySet", "from_str"),
        ("Entities", "from_json_str"),
        ("Entities", "with_added_json_str"),
        ("Schema", "from_str"),
    ],
)
def test_each_parsed_handle_exposes_the_constructor_the_engine_calls(
    holder: str, name: str
) -> None:
    """``PolicyEngine`` parses once at construction, through exactly these four."""
    assert hasattr(getattr(cedarpy, holder), name)


@pytest.mark.unit
@pytest.mark.parametrize("verdict", ["Allow", "Deny", "NoDecision"])
def test_the_decision_enum_carries_all_three_verdicts(verdict: str) -> None:
    """``_DECISIONS`` maps all three; a missing member would silently become no-decision."""
    assert hasattr(cedarpy.Decision, verdict)


# --- the shapes cedar.py reads off the results -------------------------------------------


@pytest.mark.unit
def test_an_authorization_result_carries_the_three_fields_the_decision_is_built_from() -> None:
    result = cedarpy.is_authorized(
        {
            "principal": {"type": "User", "id": "alice"},
            "action": {"type": "Action", "id": "tool.search"},
            "resource": {"type": "Tool", "id": "orders"},
            "context": {},
        },
        cedarpy.PolicySet.from_str(POLICIES),
        cedarpy.Entities.from_json_str(ENTITIES_JSON),
        None,
    )

    assert hasattr(result, "decision")
    assert hasattr(result, "allowed")
    assert result.decision in (
        cedarpy.Decision.Allow,
        cedarpy.Decision.Deny,
        cedarpy.Decision.NoDecision,
    )


@pytest.mark.unit
def test_diagnostics_carry_the_errors_reasons_and_annotation_index() -> None:
    """All three are read on every decision — the last one names the determining policy."""
    result = cedarpy.is_authorized(
        {
            "principal": {"type": "User", "id": "alice"},
            "action": {"type": "Action", "id": "tool.search"},
            "resource": {"type": "Tool", "id": "orders"},
            "context": {},
        },
        cedarpy.PolicySet.from_str(POLICIES),
        cedarpy.Entities.from_json_str(ENTITIES_JSON),
        None,
    )

    diagnostics = result.diagnostics
    assert hasattr(diagnostics, "errors")
    assert hasattr(diagnostics, "reasons")
    assert hasattr(diagnostics, "id_annotations_by_reason")
    assert list(diagnostics.errors) == []


@pytest.mark.unit
def test_a_validation_result_carries_the_fields_the_validator_reports_from() -> None:
    result = cedarpy.validate_policies(POLICIES, SCHEMA)

    assert hasattr(result, "validation_passed")
    assert hasattr(result, "errors")
    assert hasattr(result, "id_annotations_by_policy_id")
    for error in result.errors:
        assert hasattr(error, "policy_id")
        assert hasattr(error, "error")


@pytest.mark.unit
def test_validation_reports_a_bad_policy_set_rather_than_raising() -> None:
    """``validate_policies`` never raises; the CLI branches on ``validation_passed``."""
    result = cedarpy.validate_policies("this is not a policy", SCHEMA)

    assert result.validation_passed is False
    assert list(result.errors)


@pytest.mark.unit
def test_the_policy_json_carries_the_effect_and_every_annotation() -> None:
    """The only route to an annotation, and what obligations and ceilings are read from."""
    rendered = json.loads(cedarpy.policies_to_json_str(POLICIES))

    static = rendered["staticPolicies"]
    assert len(static) == 2
    effects = {policy["effect"] for policy in static.values()}
    assert effects == {"permit", "forbid"}
    annotations = [policy.get("annotations") or {} for policy in static.values()]
    declared = {key: value for entry in annotations for key, value in entry.items()}
    assert declared["id"] in ("support-may-search", "suspended-is-forbidden")
    assert declared["obligations"] == "notify:secops"


@pytest.mark.unit
def test_the_formatter_takes_a_line_width_and_an_indent_width_positionally() -> None:
    """``format_policies`` is called with both widths positionally, not by keyword."""
    formatted = cedarpy.format_policies("permit (principal, action, resource);", 80, 2)

    assert isinstance(formatted, str)
    assert "permit" in formatted


# --- and the whole surface, exercised the way the engine exercises it ---------------------


@pytest.mark.unit
def test_the_engine_builds_and_decides_against_the_installed_binding() -> None:
    """The integration of all of the above: if any part drifted, this is where it shows."""
    from sentrykit.cedar import CedarRequest, Entity

    engine = PolicyEngine(
        POLICIES,
        (Entity(EntityRef("Role", "support")), Entity(EntityRef("Tool", "orders"))),
        schema=None,
    )
    decision = engine.evaluate(
        CedarRequest(
            principal=EntityRef("User", "alice"),
            action=EntityRef("Action", "tool.search"),
            resource=EntityRef("Tool", "orders"),
            entities=(Entity(EntityRef("User", "alice"), parents=(EntityRef("Role", "support"),)),),
        )
    )

    assert decision.allowed is True
    assert decision.determining_policies == ("support-may-search",)


# --- the floor itself ---------------------------------------------------------------------


@pytest.mark.unit
def test_the_installed_version_satisfies_the_declared_requirement() -> None:
    """The environment and the declared floor have to agree, or one of them is stale.

    Read from the installed distribution's own metadata rather than from a literal here, so
    the assertion follows the packaging manifest instead of drifting from it.
    """
    from packaging.requirements import Requirement

    declared = [
        Requirement(spec)
        for spec in requires("sentrykit") or []
        if Requirement(spec).name == "cedarpy" and Requirement(spec).marker is None
    ]

    assert declared, "sentrykit declares no unconditional cedarpy requirement"
    installed = version("cedarpy")
    for requirement in declared:
        assert requirement.specifier.contains(installed), (
            f"installed cedarpy {installed} does not satisfy {requirement}"
        )


@pytest.mark.unit
@pytest.mark.parametrize("page", ["docs/quickstart.md", "README.md"])
def test_the_documented_range_is_the_range_the_package_declares(page: str) -> None:
    """A published version range that has drifted from the manifest is worse than none.

    Both pages print the supported range as prose, and prose does not move when a constraint
    does. Compared as a set of clauses rather than as a string, so the pages stay free to
    write the bounds in whichever order and spacing reads best.
    """
    import re
    from pathlib import Path

    from packaging.requirements import Requirement

    root = Path(__file__).resolve().parents[2]
    text = (root / page).read_text(encoding="utf-8")

    (declared,) = [
        Requirement(spec)
        for spec in requires("sentrykit") or []
        if Requirement(spec).name == "cedarpy" and Requirement(spec).marker is None
    ]
    expected = {str(clause).replace(" ", "") for clause in declared.specifier}

    printed = [
        {clause.strip().replace(" ", "") for clause in found.split(",")}
        for found in re.findall(r"`cedarpy\s+([^`]+)`", text)
    ]

    assert printed, f"{page} prints no `cedarpy ...` range at all"
    assert expected in printed, (
        f"{page} prints {printed} but the package declares {sorted(expected)}"
    )
