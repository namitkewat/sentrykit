"""An argument ceiling declared in reviewed policy text, and the layer it composes with.

Cedar's gate can only deny. A ceiling is the one declaration that reaches sentrykit's
narrow-and-continue path instead, so "you asked for 500, you may not have that -- here is the
call at what you may have" becomes expressible in a version-controlled file rather than only in
mutable grant data. Note what "narrowed" means mechanically: the over-bound value is *rejected*
and the principal's own default fills the hole, which is why the tests below pair a ceiling
with a grant that carries one.

Three properties carry the weight, and each has a test that would fail if it were quietly
dropped: a ceiling **narrows and the call continues**; a ceiling can **only** narrow, so
layering it over a tighter grant does not widen anything; and a declaration that will not load
fails at **wiring**, because Cedar type-checks annotation values not at all and a bad one
would otherwise sit in a validated policy set enforcing nothing.
"""

from __future__ import annotations

import pytest

from sentrykit.audit import AuditTrail
from sentrykit.cedar import Entity, EntityRef
from sentrykit.config import configure
from sentrykit.constraints import ArgumentConstraint, ConstraintSet, parse_ceiling
from sentrykit.context import Principal
from sentrykit.engine import ArgumentSpec, Governor
from sentrykit.errors import (
    AuthzDenied,
    ConfigurationError,
    DefaultUnavailable,
    NoValidArguments,
    SignatureDefaultRejected,
)
from sentrykit.masking import Masker
from sentrykit.stores.base import PolicyBundle
from sentrykit.stores.memory import InMemoryAuditSink

SEARCH_ACTION = EntityRef("Action", "tool.search_orders")
ORDERS_TOOL = EntityRef("Tool", "orders")

CEILING = (
    '\n@id("support-may-search")\n'
    '@constraints("{\\"limit\\": {\\"maximum\\": 100}, '
    '\\"region\\": {\\"allow\\": [\\"eu\\", \\"us\\"]}}")\n'
    "permit (principal, action, resource);\n"
)
"""One permit carrying the ceiling from the policies page, escaped as Cedar requires."""

_CALLED: list[dict[str, object]] = []
"""Every argument set a protected callable in this module actually ran with.

A plan says what sentrykit decided to pass; it does not say what Python then put in the
slots it was passed nothing for. Only the call itself does, so the tests that care about a
signature default read this rather than ``plan.processed``.
"""


def search_orders(limit: int = 10, region: str = "eu") -> dict[str, object]:
    call = {"limit": limit, "region": region}
    _CALLED.append(call)
    return dict(call)


@pytest.fixture(autouse=True)
def _forget_calls() -> None:
    _CALLED.clear()


@pytest.fixture
def spec() -> ArgumentSpec:
    return ArgumentSpec.from_callable(search_orders)


def _governor(policies: str, *, audit: AuditTrail | None = None) -> Governor:
    bundle = PolicyBundle.from_text(policies, entities=(Entity(ORDERS_TOOL),))
    return Governor(bundle.engine(), bundle=bundle, audit=audit)


def _principal(**constraints: ArgumentConstraint) -> Principal:
    return Principal(
        id="alice",
        constraints={'Action::"tool.search_orders"': ConstraintSet(arguments=dict(constraints))},
    )


# --- a ceiling narrows, and the call continues ------------------------------------------


@pytest.mark.unit
def test_a_proposal_above_the_ceiling_is_narrowed_and_the_call_continues(
    spec: ArgumentSpec,
) -> None:
    """Asked for 500, may have 100, gets it at 100 — the behaviour Cedar cannot express."""
    plan = _governor(CEILING).plan(
        spec,
        principal=_principal(limit=ArgumentConstraint(default=100)),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"limit": 500, "region": "eu"},
    )

    assert plan.allowed is True
    assert plan.processed["limit"] == 100
    assert plan.defaults_applied == {"limit": 100}
    assert [item.name for item in plan.rejected] == ["limit"]


@pytest.mark.unit
def test_a_rejection_names_the_reviewed_policy_that_declared_the_ceiling(
    spec: ArgumentSpec,
) -> None:
    plan = _governor(CEILING).plan(
        spec,
        principal=_principal(limit=ArgumentConstraint(default=100)),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"limit": 500, "region": "eu"},
    )

    (rejection,) = plan.rejected
    assert rejection.policy == "support-may-search"
    assert rejection.rule == "maximum"


@pytest.mark.unit
def test_a_proposal_within_the_ceiling_passes_through_untouched(spec: ArgumentSpec) -> None:
    plan = _governor(CEILING).plan(
        spec,
        principal=Principal(id="alice"),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"limit": 50, "region": "eu"},
    )

    assert plan.processed == {"limit": 50, "region": "eu"}
    assert plan.rejected == ()


@pytest.mark.unit
def test_a_ceiling_applies_with_no_grant_at_all(spec: ArgumentSpec) -> None:
    """The point of putting it in the policy: it binds every principal the permit reaches."""
    governor = _governor(CEILING)
    plan = governor.plan(
        spec,
        principal=Principal(id="alice"),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"region": "cn", "limit": 5},
    )

    governor.invoke(search_orders, plan)

    assert "region" not in plan.processed
    assert [item.name for item in plan.rejected] == ["region"]
    # ``processed`` is only half the answer, and on its own it is the half that hides this:
    # with no grant there is nothing to refill ``region``, so Python filled the slot from the
    # signature. ``"eu"`` is inside the declared allow-set, which is why the call runs at all
    # -- and the name is reported, because the caller did not choose that value.
    assert _CALLED == [{"limit": 5, "region": "eu"}]
    assert plan.signature_defaults == ("region",)


# --- a ceiling only narrows --------------------------------------------------------------


@pytest.mark.unit
def test_a_looser_ceiling_does_not_widen_a_tighter_grant(spec: ArgumentSpec) -> None:
    plan = _governor(CEILING).plan(
        spec,
        principal=_principal(limit=ArgumentConstraint(maximum=10, default=10)),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"limit": 50, "region": "eu"},
    )

    assert plan.processed["limit"] == 10
    assert [item.rule for item in plan.rejected] == ["maximum"]


@pytest.mark.unit
def test_a_looser_allow_set_in_the_ceiling_does_not_widen_a_tighter_grant(
    spec: ArgumentSpec,
) -> None:
    with pytest.raises(DefaultUnavailable):
        _governor(CEILING).plan(
            spec,
            principal=_principal(region=ArgumentConstraint(allow=("eu",), required=True)),
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"region": "us", "limit": 5},
        )


@pytest.mark.unit
def test_two_determining_permits_intersect_rather_than_widen(spec: ArgumentSpec) -> None:
    """Cedar's permits are disjunctive; their ceilings are not. The tighter one binds."""
    both = """
@id("broad")
@constraints("{\\"limit\\": {\\"maximum\\": 100}}")
permit (principal, action, resource);

@id("narrow")
@constraints("{\\"limit\\": {\\"maximum\\": 20}}")
permit (principal, action, resource);
"""

    plan = _governor(both).plan(
        spec,
        principal=Principal(id="alice"),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"limit": 50, "region": "eu"},
    )

    assert "limit" not in plan.processed
    assert [item.policy for item in plan.rejected] == ["narrow"]


@pytest.mark.unit
def test_a_ceiling_on_a_policy_that_did_not_decide_the_call_does_not_apply(
    spec: ArgumentSpec,
) -> None:
    """Ceilings come from the determining permits, so an unrelated one is inert."""
    mixed = """
@id("the-one-that-fires")
permit (principal, action == Action::"tool.search_orders", resource);

@id("about-a-different-action")
@constraints("{\\"limit\\": {\\"maximum\\": 1}}")
permit (principal, action == Action::"tool.export_orders", resource);
"""

    plan = _governor(mixed).plan(
        spec,
        principal=Principal(id="alice"),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"limit": 500},
    )

    assert plan.processed["limit"] == 500


@pytest.mark.unit
def test_a_grant_default_the_ceiling_forbids_is_withheld(spec: ArgumentSpec) -> None:
    """The two layers compose: a default is checked against the intersection, not the grant."""
    plan = _governor(CEILING).plan(
        spec,
        principal=_principal(region=ArgumentConstraint(default="cn")),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"limit": 5},
    )

    assert "region" not in plan.processed
    assert [item.name for item in plan.rejected] == ["region"]


@pytest.mark.unit
def test_a_ceiling_can_make_an_argument_required(spec: ArgumentSpec) -> None:
    required = """
@id("must-name-a-region")
@constraints("{\\"region\\": {\\"required\\": true}}")
permit (principal, action, resource);
"""

    with pytest.raises(DefaultUnavailable) as caught:
        _governor(required).plan(
            spec, principal=Principal(id="alice"), action=SEARCH_ACTION, resource=ORDERS_TOOL
        )

    assert caught.value.name == "region"


@pytest.mark.unit
def test_a_proposal_with_nothing_left_standing_is_refused_rather_than_narrowed(
    spec: ArgumentSpec,
) -> None:
    """Narrowing refines a proposal; it does not replace one.

    ``NoValidArguments`` fires when the caller supplied arguments and every one was rejected,
    because completing such a call from defaults answers a question nobody asked. A ceiling
    does not change that: it narrows the part of a proposal that stands, and a proposal with
    no part standing is still a refusal. The refusal describes the *intersected* set, so a
    caller is told the bound that actually applies.
    """
    with pytest.raises(NoValidArguments) as caught:
        _governor(CEILING).plan(
            spec,
            principal=_principal(limit=ArgumentConstraint(default=100)),
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"limit": 500},
        )

    assert caught.value.allowed["limit"]["maximum"] == 100


# --- a ceiling reaches the callable's own default too -------------------------------------
#
# A ceiling says what *anybody* may pass, so the one value it must not miss is the one nobody
# passes: with no grant to refill a rejected argument, Python fills the slot from the
# signature. Until that value answered to the ceiling, a declared maximum of 10 over a
# parameter defaulting to 1000 ran the body at 1000 -- more than the caller had asked for,
# from a file whose whole purpose is to state the maximum.
#
# A ceiling refusing the default is told apart from a grant refusing it, because the two are
# different problems for different people. A ceiling is reviewed, version-controlled text, so
# the disagreement is between an operator's policy file and their own code and it reaches
# every caller of the action; a grant is one principal's data.

CAPPED = (
    '\n@id("search-is-capped")\n'
    '@constraints("{\\"limit\\": {\\"maximum\\": 10}}")\n'
    "permit (principal, action, resource);\n"
)
"""A declared bound well below the wide signature default below it."""

NO_PROD = (
    '\n@id("nobody-may-wipe-prod")\n'
    '@constraints("{\\"target\\": {\\"deny\\": [\\"prod\\"]}}")\n'
    "permit (principal, action, resource);\n"
)
"""The deny-set half: the value forbidden here is the one the signature falls back to."""

WIPE_ACTION = EntityRef("Action", "tool.wipe")


def search_with_a_wide_default(q: str = "", limit: int = 1000) -> dict[str, object]:
    """Its own default is far above anything :data:`CAPPED` permits."""
    call = {"q": q, "limit": limit}
    _CALLED.append(call)
    return dict(call)


def search_with_a_modest_default(q: str = "", limit: int = 5) -> dict[str, object]:
    """Its own default is inside :data:`CAPPED`, so the ceiling has no quarrel with it."""
    call = {"q": q, "limit": limit}
    _CALLED.append(call)
    return dict(call)


def wipe(target: str = "prod", confirm: bool = False) -> dict[str, object]:
    """``confirm`` is ungoverned, so it survives and the call reaches the signature check."""
    call = {"target": target, "confirm": confirm}
    _CALLED.append(call)
    return dict(call)


@pytest.mark.unit
@pytest.mark.parametrize(
    "proposed",
    [{"q": "x", "limit": 500}, {"q": "x"}],
    ids=["proposed-and-rejected", "never-proposed"],
)
def test_a_signature_default_above_a_declared_ceiling_refuses_the_call(
    proposed: dict[str, object],
) -> None:
    """Asked for 500 or asked for nothing, the slot would have taken 1000 either way."""
    with pytest.raises(SignatureDefaultRejected) as caught:
        _governor(CAPPED).plan(
            ArgumentSpec.from_callable(search_with_a_wide_default),
            principal=Principal(id="alice"),
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed=proposed,
        )

    assert caught.value.name == "limit"
    assert caught.value.declared is True
    assert caught.value.policy == "search-is-capped"
    assert _CALLED == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "proposed",
    [{"q": "x", "limit": 500}, {"q": "x"}],
    ids=["proposed-and-rejected", "never-proposed"],
)
def test_a_signature_default_the_ceiling_accepts_runs_the_call_and_names_it(
    proposed: dict[str, object],
) -> None:
    """Inside the declared bound, so the call runs on it -- reported, and still Python's own.

    ``processed`` is the set sentrykit decided to pass and the name is deliberately not in it:
    the ceiling checked this value and declined to replace it, which is a different fact from
    a default policy supplied.
    """
    sink = InMemoryAuditSink()
    governor = _governor(CAPPED, audit=AuditTrail(sink, masker=Masker(key=b"k")))
    plan = governor.plan(
        ArgumentSpec.from_callable(search_with_a_modest_default),
        principal=Principal(id="alice"),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed=proposed,
    )
    envelope = plan.envelope()

    governor.invoke(search_with_a_modest_default, plan)

    assert _CALLED == [{"q": "x", "limit": 5}]
    assert "limit" not in plan.processed
    assert plan.defaults_applied == {}
    assert envelope is not None
    assert envelope.signature_defaults == ("limit",)
    assert sink.records[0].signature_defaults == ("limit",)


@pytest.mark.unit
@pytest.mark.parametrize(
    "proposed",
    [{"target": "prod", "confirm": True}, {"confirm": True}],
    ids=["proposed-and-rejected", "never-proposed"],
)
def test_a_declared_deny_set_also_binds_the_callables_own_default(
    proposed: dict[str, object],
) -> None:
    """The costly shape: a reviewed file forbids ``prod`` and the parameter defaults to it."""
    with pytest.raises(SignatureDefaultRejected) as caught:
        _governor(NO_PROD).plan(
            ArgumentSpec.from_callable(wipe),
            principal=Principal(id="alice"),
            action=WIPE_ACTION,
            resource=ORDERS_TOOL,
            proposed=proposed,
        )

    assert caught.value.name == "target"
    assert caught.value.declared is True
    assert _CALLED == []


@pytest.mark.unit
def test_a_ceiling_and_a_grant_that_both_refuse_the_default_report_the_reviewed_one() -> None:
    """Ceilings are checked first so the provenance survives the intersection.

    Both layers refuse 1000 here, and the intersected set no longer remembers which side a
    rule came from. Reporting the grant would send an operator looking through per-principal
    data for a conflict that is in their policy file and affects everyone.
    """
    with pytest.raises(SignatureDefaultRejected) as caught:
        _governor(CAPPED).plan(
            ArgumentSpec.from_callable(search_with_a_wide_default),
            principal=_principal(limit=ArgumentConstraint(maximum=20, policy="grant-limit")),
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"q": "x", "limit": 500},
        )

    assert caught.value.declared is True
    assert caught.value.policy == "search-is-capped"


# --- composing with the forbid backstop ---------------------------------------------------


BACKSTOPPED = """
@id("support-may-search")
@constraints("{\\"limit\\": {\\"maximum\\": 100}}")
permit (principal, action, resource);

@id("absurd-limits-are-forbidden")
forbid (principal, action, resource)
when { context.args has limit && context.args.limit > 1000 };
"""


@pytest.mark.unit
def test_the_backstop_still_denies_before_anything_is_narrowed(spec: ArgumentSpec) -> None:
    """The gate runs first, so a `forbid` refuses the call rather than having it narrowed."""
    with pytest.raises(AuthzDenied) as caught:
        _governor(BACKSTOPPED).plan(
            spec,
            principal=Principal(id="alice"),
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"limit": 5000},
        )

    assert list(caught.value.determining_policies) == ["absurd-limits-are-forbidden"]


@pytest.mark.unit
def test_a_value_the_backstop_allows_is_still_narrowed_by_the_ceiling(
    spec: ArgumentSpec,
) -> None:
    plan = _governor(BACKSTOPPED).plan(
        spec,
        principal=Principal(id="alice"),
        action=SEARCH_ACTION,
        resource=ORDERS_TOOL,
        proposed={"limit": 500, "region": "eu"},
    )

    assert plan.allowed is True
    assert "limit" not in plan.processed
    assert [item.policy for item in plan.rejected] == ["support-may-search"]


# --- the fail-open path -------------------------------------------------------------------


@pytest.mark.unit
def test_an_engine_failure_refuses_under_fail_open_when_the_bundle_declares_a_ceiling(
    spec: ArgumentSpec,
) -> None:
    """A failed decision reports no determining policies, therefore no ceilings.

    Letting the call through would drop every declared bound at exactly the moment the engine
    is least trustworthy, so a bundle that declares any refuses instead. The check lives on
    the fail-open path rather than at wiring because ``fail_mode`` is per-action overridable
    on every call.
    """
    configure(fail_mode="open")
    unevaluable = """
@id("reads-an-attribute-nobody-has")
@constraints("{\\"limit\\": {\\"maximum\\": 100}}")
permit (principal, action, resource)
when { principal.clearance == "high" };
"""

    with pytest.raises(AuthzDenied) as caught:
        _governor(unevaluable).plan(
            spec,
            principal=Principal(id="alice"),
            action=SEARCH_ACTION,
            resource=ORDERS_TOOL,
            proposed={"limit": 500},
        )

    assert caught.value.engine_errors


@pytest.mark.unit
def test_a_bundle_with_no_ceilings_still_fails_open(spec: ArgumentSpec) -> None:
    configure(fail_mode="open")
    unevaluable = """
@id("reads-an-attribute-nobody-has")
permit (principal, action, resource)
when { principal.clearance == "high" };
"""

    plan = _governor(unevaluable).plan(
        spec, principal=Principal(id="alice"), action=SEARCH_ACTION, resource=ORDERS_TOOL
    )

    assert plan.allowed is True


# --- a declaration that will not load fails at wiring -------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("declaration", "expected"),
    [
        ('"not json"', "not valid JSON"),
        ('"[]"', "not a JSON object"),
        ('"{\\"limit\\": 100}"', "not a JSON object of rules"),
        ('"{\\"region\\": {\\"default\\": \\"eu\\"}}"', "per-principal grant data"),
        ('"{\\"region\\": {\\"policy\\": \\"mine\\"}}"', "a ceiling may set only"),
        ('"{\\"limit\\": {\\"maximum\\": \\"lots\\"}}"', "does not type-check"),
        ('"{\\"limit\\": {\\"minimum\\": 100, \\"maximum\\": 10}}"', "cannot be satisfied"),
        ('"{\\"region\\": {\\"pattern\\": \\"[unclosed\\"}}"', "cannot be satisfied"),
        ('"{}"', "empty argument ceiling"),
        ("", "empty argument ceiling"),
    ],
    ids=[
        "not-json",
        "not-an-object",
        "rules-not-an-object",
        "declares-a-default",
        "declares-its-own-provenance",
        "wrong-type",
        "unsatisfiable",
        "uncompilable-pattern",
        "declares-nothing",
        "valueless",
    ],
)
def test_a_malformed_declaration_is_refused_at_load(declaration: str, expected: str) -> None:
    annotation = f"@constraints({declaration})" if declaration else "@constraints"
    text = f'@id("p")\n{annotation}\npermit (principal, action, resource);'

    with pytest.raises(ConfigurationError) as caught:
        PolicyBundle.from_text(text)

    assert expected in str(caught.value)


@pytest.mark.unit
def test_a_ceiling_on_a_forbid_is_a_load_error_rather_than_a_silent_no_op() -> None:
    """A determining forbid has already refused, so there is no narrowed call to bound."""
    text = (
        '@id("no-exports")\n'
        '@constraints("{\\"limit\\": {\\"maximum\\": 10}}")\n'
        "forbid (principal, action, resource);"
    )

    with pytest.raises(ConfigurationError) as caught:
        PolicyBundle.from_text(text)

    assert "is a forbid and cannot declare an argument ceiling" in str(caught.value)


@pytest.mark.unit
def test_a_pattern_carrying_a_backreference_is_refused() -> None:
    """A ceiling's pattern is composed with the principal's own, which renumbers its groups."""
    with pytest.raises(ConfigurationError) as caught:
        parse_ceiling('{"region": {"pattern": "(a)\\\\1"}}', policy="p")

    assert "backreference" in str(caught.value)


@pytest.mark.unit
def test_a_declared_ceiling_records_the_namespaced_policy_id() -> None:
    bundle = PolicyBundle.from_text(CEILING, namespace="hr")

    ceiling = bundle.provenance[0].ceiling
    assert ceiling is not None
    assert ceiling.arguments["limit"].policy == "hr/support-may-search"


@pytest.mark.unit
def test_a_bundle_reports_whether_it_declares_any_ceiling() -> None:
    assert PolicyBundle.from_text(CEILING).declares_ceilings is True
    assert (
        PolicyBundle.from_text("permit (principal, action, resource);").declares_ceilings is False
    )


# --- the intersection itself ---------------------------------------------------------------


@pytest.mark.unit
def test_bounds_move_inward_from_either_side() -> None:
    tightened = ArgumentConstraint(minimum=1, maximum=1000).intersected_with(
        ArgumentConstraint(minimum=10, maximum=100)
    )

    assert (tightened.minimum, tightened.maximum) == (10, 100)


@pytest.mark.unit
def test_allow_sets_intersect_and_deny_sets_union() -> None:
    narrowed = ArgumentConstraint(allow=("eu", "uk", "us"), deny=("cn",)).intersected_with(
        ArgumentConstraint(allow=("eu", "us"), deny=("ru",))
    )

    assert narrowed.allow == ("eu", "us")
    assert narrowed.deny == ("cn", "ru")


@pytest.mark.unit
def test_two_patterns_must_both_match_in_full() -> None:
    both = ArgumentConstraint(pattern="[a-z]+").intersected_with(ArgumentConstraint(pattern=".."))

    assert both.check("region", "ab") is None
    assert both.check("region", "abc") is not None
    assert both.check("region", "AB") is not None


@pytest.mark.unit
def test_required_is_sticky_and_a_default_survives_from_the_receiver() -> None:
    combined = ArgumentConstraint(default="eu").intersected_with(ArgumentConstraint(required=True))

    assert combined.required is True
    assert combined.has_default is True
    assert combined.default == "eu"


@pytest.mark.unit
def test_intersecting_two_constraints_with_no_default_does_not_invent_one() -> None:
    """``has_default`` is read off the fields that were set, so naming it would inject None."""
    combined = ArgumentConstraint(maximum=100).intersected_with(ArgumentConstraint(minimum=1))

    assert combined.has_default is False


@pytest.mark.unit
def test_disjoint_allow_sets_intersect_to_nothing_and_nothing_passes() -> None:
    empty = ArgumentConstraint(allow=("eu",)).intersected_with(ArgumentConstraint(allow=("us",)))

    assert empty.allow == ()
    assert empty.check("region", "eu") is not None
    assert empty.check("region", "us") is not None


@pytest.mark.unit
def test_a_set_intersects_argument_by_argument_and_keeps_the_ones_only_one_side_names() -> None:
    combined = ConstraintSet(
        arguments={"limit": ArgumentConstraint(maximum=1000), "region": ArgumentConstraint()}
    ).intersected_with(
        ConstraintSet(
            arguments={"limit": ArgumentConstraint(maximum=100), "fmt": ArgumentConstraint()}
        )
    )

    assert set(combined.arguments) == {"limit", "region", "fmt"}
    assert combined.arguments["limit"].maximum == 100
