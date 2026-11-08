"""The shape the attack/defence suite rests on, checked without deciding anything.

``examples/scenarios`` makes one claim before it makes any other: that its two arms are the
same function body reached two ways. Everything it prints is a comparison, and a comparison
between two *bodies* would be measuring the bodies -- so a divergence introduced by a careless
edit could be read as something an authorization layer did. The structure is therefore what is
pinned here, because none of it shows up in the output the suite produces and all of it is
what makes that output mean anything.

The rest guards the joins that a rename breaks quietly rather than loudly. An action a tool
declares has to be one the reviewed pack decides, or the tool is governed by nothing at all and
the suite goes on printing a clean table underneath it. A parameter the policy decides must
carry no Python default, or an omitted argument is answered by the application instead of by
policy -- with the one deliberate exception the suite exists to demonstrate. And the planted
instruction has to keep naming the arguments the grants bound, or the injection scenario decays
into a note that asks for nothing and a governed arm that had nothing to narrow.

Nothing here installs a governor, reads a principal or opens the desk. Every assertion is over
a signature, a source file, or the reviewed policy text.
"""

from __future__ import annotations

import ast
import inspect
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import cedarpy
import pytest
from examples.scenarios import attack, desk_tools, governed, policy
from examples.scenarios.scenarios import INJECTION_SCENARIO, SCENARIOS

from sentrykit import is_protected, protected_meta

UNGOVERNED_DEFAULTS: Final = frozenset({"status", "fmt"})
"""The parameters no policy in the suite has an opinion about, and so the ones free to default.

``status`` and ``fmt`` are the caller's own business. They also do mechanical work: a proposal
in which *every* argument was rejected is refused outright rather than completed from defaults,
so a call that is meant to be narrowed needs one argument in it that survives.
"""

SIGNATURE_DEFAULT_EXCEPTION: Final = ("cancel_open_orders", "region")
"""The one governed parameter that keeps a Python default, and the reason the rule is visible.

``cancel_open_orders(region="eu")`` exists precisely to be refused: alice's grant denies ``eu``
and nothing refills it, so proposing no argument at all is answered rather than waved through.
Removing the default would remove the demonstration.
"""

PRINCIPALS: Final = tuple(sorted({step.principal for s in SCENARIOS for step in s.steps}))
"""Whose grants the suite decides against, read off the scenarios rather than written down."""


@dataclass(frozen=True)
class PackPolicy:
    """One static policy of the reviewed pack, as its own text declares it.

    Attributes:
        policy_id: The ``@id`` annotation, or Cedar's generated id when none is declared.
        effect: ``permit`` or ``forbid``.
        actions: The action ids the policy's scope names.
        ceiling: The argument ceiling its ``@constraints`` annotation declares, parsed. Empty
            for a policy that declares none.
    """

    policy_id: str
    effect: str
    actions: frozenset[str] = frozenset()
    ceiling: Mapping[str, object] = field(default_factory=dict)

    def allowed(self, argument: str) -> tuple[str, ...]:
        """The values this policy's ceiling permits for ``argument``, as strings."""
        rules = self.ceiling.get(argument)
        allow = rules.get("allow") if isinstance(rules, Mapping) else None
        if isinstance(allow, Sequence) and not isinstance(allow, str):
            return tuple(str(value) for value in allow)
        return ()


def _scope_actions(scope: object) -> frozenset[str]:
    """The action ids one policy's action scope names, whichever operator it used."""
    if not isinstance(scope, Mapping):
        return frozenset()
    found: list[str] = []
    entity = scope.get("entity")
    if isinstance(entity, Mapping):
        found.append(str(entity.get("id", "")))
    entities = scope.get("entities")
    if isinstance(entities, Sequence) and not isinstance(entities, str):
        found.extend(str(item.get("id", "")) for item in entities if isinstance(item, Mapping))
    return frozenset(name for name in found if name)


def _ceiling(declaration: object) -> Mapping[str, object]:
    """One ``@constraints`` annotation, parsed, or an empty mapping when there is none."""
    if not isinstance(declaration, str) or not declaration.strip():
        return {}
    parsed = json.loads(declaration)
    return parsed if isinstance(parsed, Mapping) else {}


def _pack() -> tuple[PackPolicy, ...]:
    """Read the reviewed pack's policies out of its own text.

    Parsed with Cedar rather than with a regular expression, because the annotations and the
    action scope have to come from the same parse to be joinable at all -- and an id read out
    of a comment would make that join silently wrong.
    """
    rendered = json.loads(cedarpy.policies_to_json_str(policy.POLICY_TEXT))
    read: list[PackPolicy] = []
    for cedar_id, block in sorted(rendered.get("staticPolicies", {}).items()):
        annotations = block.get("annotations") or {}
        read.append(
            PackPolicy(
                policy_id=str(annotations.get("id") or cedar_id),
                effect=str(block.get("effect", "")),
                actions=_scope_actions(block.get("action")),
                ceiling=_ceiling(annotations.get("constraints")),
            )
        )
    return tuple(read)


PACK: Final = _pack()
"""The reviewed pack, parsed once."""


def _governed_arguments() -> dict[str, frozenset[str]]:
    """Every argument the suite's policy decides, keyed by action id.

    Both halves of policies-as-code, grants-as-data: the ceilings declared in the reviewed
    files, and the per-principal constraints the grant store holds. An argument is governed
    when either one bounds it, which is the same union the governor resolves against.
    """
    found: dict[str, set[str]] = {}
    for declared in PACK:
        for action in declared.actions:
            found.setdefault(action, set()).update(declared.ceiling)
    store = policy.build_grants()
    for who in PRINCIPALS:
        principal = store.get_principal(who)
        if principal is None:  # pragma: no cover - every scenario names a seeded principal
            continue
        for action, constraints in principal.constraints.items():
            found.setdefault(action, set()).update(constraints.arguments)
    return {action: frozenset(arguments) for action, arguments in found.items()}


GOVERNED_ARGUMENTS: Final = _governed_arguments()
"""The argument names policy decides, by action id."""


def _public_callables() -> tuple[str, ...]:
    """Every public function :mod:`examples.scenarios.desk_tools` defines itself.

    Derived by inspection rather than listed, so a tool added to that module and left out of
    the governed list fails a test instead of being silently never called by either arm.
    """
    return tuple(
        sorted(
            name
            for name, value in vars(desk_tools).items()
            if inspect.isfunction(value)
            and not name.startswith("_")
            and value.__module__ == desk_tools.__name__
        )
    )


def _imported_modules(source: str) -> set[str]:
    """Every module name ``source`` imports, by either statement form."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            found.add(node.module)
    return found


def _action_of(tool: str) -> str:
    """The action id the governed twin of ``tool`` declares."""
    meta = protected_meta(governed.TOOLS[tool])
    assert meta is not None
    return meta.action.id


def _maximum(who: str, action: str, argument: str) -> int:
    """The upper bound one principal's own grant sets on one argument of one action."""
    principal = policy.build_grants().get_principal(who)
    assert principal is not None
    constraint = principal.constraints[action].arguments[argument]
    assert constraint.maximum is not None
    return int(constraint.maximum)


@pytest.mark.parametrize("tool", sorted(governed.TOOLS))
@pytest.mark.unit
def test_the_two_arms_are_one_body_reached_twice(tool: str) -> None:
    """Protecting a function leaves the target alone, which is what lets both arms share it."""
    protected = governed.TOOLS[tool]
    plain = governed.PLAIN[tool]

    assert is_protected(protected) is True
    assert is_protected(plain) is False
    assert plain is getattr(desk_tools, tool)
    assert protected.__wrapped__ is plain


@pytest.mark.unit
def test_both_arms_cover_every_tool_the_desk_defines() -> None:
    """A tool nobody governed would be a tool neither arm ever called."""
    expected = set(_public_callables())

    assert set(governed.TOOLS) == expected
    assert set(governed.PLAIN) == expected


@pytest.mark.unit
def test_the_ungoverned_arm_imports_no_authorization_vocabulary() -> None:
    """The absence is the measurement: the baseline has to be the application as written.

    Read out of the module's own source rather than out of ``sys.modules``, because anything
    that imported the governed twin first would show sentrykit present in the process either
    way and prove nothing at all about this file.
    """
    source = Path(desk_tools.__file__).read_text(encoding="utf-8")

    offenders = sorted(
        module
        for module in _imported_modules(source)
        if module == "sentrykit" or module.startswith("sentrykit.")
    )
    assert offenders == []


@pytest.mark.unit
def test_every_governed_action_is_one_the_reviewed_pack_decides() -> None:
    """A renamed action un-governs its tool without changing a line of either arm."""
    declared = {_action_of(tool) for tool in governed.TOOLS}
    named_by_pack = {action for item in PACK for action in item.actions}
    permitted_by_pack = {
        action for item in PACK if item.effect == "permit" for action in item.actions
    }

    assert declared == named_by_pack
    assert declared == permitted_by_pack


@pytest.mark.unit
def test_a_parameter_the_policy_decides_carries_no_python_default() -> None:
    """An omitted argument has to be policy's to answer rather than the signature's.

    The one exception is the scenario that demonstrates the rule: a destructive call whose
    Python default is a value its principal's grant denies, kept so that proposing nothing is
    visibly refused instead of quietly served.
    """
    decided_with_defaults: set[tuple[str, str]] = set()
    free_with_defaults: set[tuple[str, str]] = set()
    for tool in governed.TOOLS:
        decided = GOVERNED_ARGUMENTS.get(_action_of(tool), frozenset())
        for parameter in inspect.signature(getattr(desk_tools, tool)).parameters.values():
            if parameter.default is inspect.Parameter.empty:
                continue
            found = decided_with_defaults if parameter.name in decided else free_with_defaults
            found.add((tool, parameter.name))

    assert decided_with_defaults == {SIGNATURE_DEFAULT_EXCEPTION}
    assert {parameter for _tool, parameter in free_with_defaults} == UNGOVERNED_DEFAULTS
    assert _action_of(SIGNATURE_DEFAULT_EXCEPTION[0]) == "desk.cancel"


@pytest.mark.unit
def test_the_planted_instruction_asks_for_the_arguments_the_grants_bound() -> None:
    """An injection naming nothing governed would leave the governed arm nothing to narrow."""
    step = next(s for s in SCENARIOS if s.key == INJECTION_SCENARIO).steps[-1]
    action = _action_of(step.tool)
    tenant = str(step.arguments["tenant_id"])
    limit = str(step.arguments["limit"])

    assert {"tenant_id", "limit"} <= GOVERNED_ARGUMENTS[action]
    # What the scenario proposes is what the planted text demands, so the two cannot drift
    # into a note about one tenant and a call against another.
    assert tenant in attack.INJECTION
    assert limit in attack.INJECTION

    # And both demands are outside what policy would allow, which is what makes them attacks.
    ceiling = next(item for item in PACK if "tenant_id" in item.ceiling)
    assert tenant not in ceiling.allowed("tenant_id")
    assert int(limit) > _maximum("alice", action, "limit")
