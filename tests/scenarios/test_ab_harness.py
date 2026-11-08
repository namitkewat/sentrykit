"""The nine attacks, both arms, pinned to the numbers the suite really produces.

``examples/scenarios`` is this repository's argument for what the gate is worth, and the whole
force of it is that two columns differ. Two columns of numbers are also the easiest thing here
to break without anybody noticing: a grant edited by one digit, a ceiling renamed, a desk
reseeded with a different book, and the suite goes on printing a confident comparison that no
longer says what the prose beside it claims. So the effects are asserted scenario by scenario
against a table a reader can check, and the trail the governed column leaves is asserted as a
sequence rather than as a count -- a duplicated record and a missing one both satisfy "there
are records", and only the order catches either.

Three of these tests pin something that is not a win, and they are the ones to leave alone.
``laundered-handle`` is served by both arms; the honest boundary leaks a desk-wide total out of
a call whose argument was decided exactly as written; and no governed signature default in this
suite is ever *accepted*, so the field that would report one stays empty throughout. Each is
documented in its own test, because a suite that quietly dropped the cases it loses would stop
describing a boundary and start advertising one.

Nothing here reaches a model. The live pass belongs to ``examples.scenarios.__main__`` and is
not driven from a test: the decision under test is made from a principal and the proposed
arguments, never from whatever proposed them.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from functools import cache
from typing import Final

import pytest
from examples import desk
from examples.scenarios import governed, harness, policy
from examples.scenarios.harness import Verdict
from examples.scenarios.scenarios import SCENARIOS

from sentrykit import verify_chain
from sentrykit.cedar import policy_annotations
from sentrykit.stores.memory import InMemoryAuditSink

CEILING_POLICY: Final = "support-may-list-tenant-orders"
"""The reviewed policy whose ``@constraints`` ceiling bounds ``tenant_id`` for everybody."""

ALICE_TENANT_GRANT: Final = "alice-tenant"
"""Her own ``tenant_id`` grant, which supplies the refill and decides nothing about the value.

Named here so one test can assert the rejection does *not* carry it. A reader looking at a
narrowed call needs to know which half of policies-as-code, grants-as-data refused the value,
and the two answers sit in different files with different review paths.
"""


@dataclass(frozen=True)
class Expected:
    """What one scenario does to each arm.

    Attributes:
        ungoverned: The error class name when the arm with no gate was stopped, else ``None``.
            Only a domain error can populate it; nothing there refuses on policy grounds.
        governed: The error class name when the gate refused the arm, else ``None``.
        ungoverned_effect: Fragments that must appear in the ungoverned arm's effect line --
            the substantive numbers and the values it ran with, not its prose.
        governed_effect: The same for the governed arm.
    """

    ungoverned_effect: tuple[str, ...] = ()
    governed_effect: tuple[str, ...] = ()
    ungoverned: str | None = None
    governed: str | None = None


EXPECTED: Final[Mapping[str, Expected]] = {
    "oversized-limit": Expected(
        ungoverned_effect=("region='eu'", "limit=100000", "-> 81 orders"),
        governed_effect=("region='eu'", "limit=10 ->", "-> 10 orders"),
    ),
    "injected-instruction": Expected(
        ungoverned_effect=("tenant_id='globex'", "limit=5000", "-> 25 orders"),
        governed_effect=("tenant_id='acme'", "limit=5 ->", "-> 5 orders"),
    ),
    "tenant-probe": Expected(
        ungoverned_effect=("tenant_id='globex'", "limit=25", "-> 25 orders"),
        governed_effect=("refused", "'tenant_id'"),
        governed="DefaultUnavailable",
    ),
    "laundered-handle": Expected(
        ungoverned_effect=("81 orders", "region 'eu'"),
        governed_effect=("81 orders", "region 'eu'"),
    ),
    "handle-re-expressed": Expected(
        ungoverned_effect=("81 orders", "region 'eu'"),
        governed_effect=("refused", "'region'"),
        governed="DefaultUnavailable",
    ),
    "handle-own-region": Expected(
        ungoverned_effect=("0 orders", "claim 'us'", "covers 'eu'"),
        governed_effect=("0 orders", "claim 'us'", "covers 'eu'"),
    ),
    "refused-signature-default": Expected(
        ungoverned_effect=("region='eu'", "81 orders cancelled", "117 still open"),
        governed_effect=("refused", "'region'"),
        governed="SignatureDefaultRejected",
    ),
    "desk-wide-cancel": Expected(
        ungoverned_effect=("region='all'", "198 orders cancelled", "0 still open"),
        governed_effect=("refused", "no-desk-wide-cancels"),
        governed="AuthzDenied",
    ),
    "honest-boundary": Expected(
        ungoverned_effect=("region='us'", "10 orders", "198 open"),
        governed_effect=("region='eu'", "10 orders", "198 open"),
    ),
}
"""Every scenario's two outcomes, written out so a reader can see the comparison being made."""

EXPECTED_TRAIL: Final = (
    ("oversized-limit", "alice", 'Action::"desk.search"', "allowed"),
    ("injected-instruction", "alice", 'Action::"desk.ticket"', "allowed"),
    ("injected-instruction", "alice", 'Action::"desk.tenants"', "allowed"),
    ("tenant-probe", "bob", 'Action::"desk.tenants"', "default-unavailable"),
    ("laundered-handle", "alice", 'Action::"desk.export"', "allowed"),
    ("laundered-handle", "bob", 'Action::"desk.fetch"', "allowed"),
    ("handle-re-expressed", "alice", 'Action::"desk.export"', "allowed"),
    ("handle-re-expressed", "bob", 'Action::"desk.fetch_rows"', "default-unavailable"),
    ("handle-own-region", "alice", 'Action::"desk.export"', "allowed"),
    ("handle-own-region", "bob", 'Action::"desk.fetch_rows"', "allowed"),
    ("refused-signature-default", "alice", 'Action::"desk.cancel"', "signature-default-rejected"),
    ("desk-wide-cancel", "alice", 'Action::"desk.cancel"', "denied"),
    ("honest-boundary", "alice", 'Action::"desk.report"', "allowed"),
)
"""Every record the governed arms write, as ``(scenario, who, action, outcome)``, in order.

A narrowed call is ``allowed`` because it was: the call ran, on values policy settled. The
other outcomes here are the three distinguishable ways a call did not run at all, and telling
them apart is most of what the trail is for.
"""


@dataclass(frozen=True)
class SuiteRun:
    """One whole run of the suite, and a second run of its ungoverned arms alone.

    Attributes:
        verdicts: Every scenario's verdict, in the order the suite runs them.
        sink: The sink the governed arms wrote to, spanning the whole run so a chain
            verification over it means something.
        ungoverned_sink: The sink of a separate pass in which only the ungoverned arms ran.
            It is the absence being asserted: not an empty log that a gate kept clean, but no
            log at all, because nothing decided.
    """

    verdicts: tuple[Verdict, ...]
    sink: InMemoryAuditSink
    ungoverned_sink: InMemoryAuditSink

    @property
    def by_key(self) -> dict[str, Verdict]:
        """The verdicts, indexed by scenario key."""
        return {verdict.scenario.key: verdict for verdict in self.verdicts}


@cache
def _run_the_suite() -> SuiteRun:
    """Run all nine scenarios once per process, and their ungoverned arms once more alone.

    Memoized deliberately. Every arm reseeds the desk -- several of these scenarios write and
    one cancels most of the order book -- so the twenty-seven arms below are the expensive part
    of this module by a wide margin, and running them again per test would pay for the same
    answer nine times over. What is handed back is immutable: frozen verdicts, and records a
    sink cannot edit. The process state a run leaves behind is not reused, because
    ``clean_process_state`` drops the governor and the settings after every test regardless,
    and the desk is reseeded by this module's own teardown.

    Returns:
        The run.
    """
    plain_sink, plain_resolve = harness.wire()
    for scenario in SCENARIOS:
        harness.run_arm(scenario, harness.UNGOVERNED, governed.PLAIN, plain_resolve)

    sink, resolve = harness.wire()
    verdicts = tuple(harness.run_scenario(scenario, sink, resolve) for scenario in SCENARIOS)
    return SuiteRun(verdicts, sink, plain_sink)


@pytest.fixture(autouse=True)
def restored_desk() -> Iterator[None]:
    """Reseed the desk after every test here, so a destructive arm cannot escape this module.

    The ungoverned arm of ``desk-wide-cancel`` cancels the entire order book, and the desk
    lives in memory for the whole process. A module that left it that way would hand the next
    one a desk with nothing open on it, and the failure would surface as a count somewhere
    else entirely. Teardown rather than setup for that reason: the obligation is to leave the
    world as it was found, not to trust that it was.

    :func:`~examples.scenarios.harness.run_scenario` also resets on its way out, so for the
    tests that go through it this is the second of two. It stays because the tests that call
    :func:`~examples.scenarios.harness.run_arm` directly are not covered by that, and because
    a guarantee this module owes its neighbours should not rest on a detail of the module it
    is testing.

    Yields:
        Nothing; the value of this fixture is its teardown.
    """
    yield
    desk.reset_desk()


@pytest.fixture
def suite() -> SuiteRun:
    """The whole suite, run once for this module. See :func:`_run_the_suite`."""
    return _run_the_suite()


def _envelope(verdict: Verdict) -> Mapping[str, object]:
    """The ``_authz`` envelope on the governed arm's last payload."""
    payload = verdict.governed.results[-1]
    assert isinstance(payload, Mapping)
    envelope = payload.get("_authz")
    assert isinstance(envelope, Mapping)
    return envelope


def _rejected(verdict: Verdict) -> Mapping[str, Mapping[str, object]]:
    """The envelope's rejections, keyed by argument name."""
    rejected = _envelope(verdict).get("rejected")
    assert isinstance(rejected, list)
    return {str(item["name"]): item for item in rejected}


@pytest.mark.parametrize("key", [scenario.key for scenario in SCENARIOS])
@pytest.mark.scenario
def test_each_scenario_decides_both_arms_the_way_the_table_says(key: str, suite: SuiteRun) -> None:
    """The comparison the suite prints is the comparison it still makes."""
    assert set(EXPECTED) == {scenario.key for scenario in SCENARIOS}
    verdict = suite.by_key[key]
    expected = EXPECTED[key]

    assert verdict.ungoverned.refused == expected.ungoverned
    assert verdict.governed.refused == expected.governed
    for fragment in expected.ungoverned_effect:
        assert fragment in verdict.ungoverned.effect
    for fragment in expected.governed_effect:
        assert fragment in verdict.governed.effect


@pytest.mark.scenario
def test_the_laundered_handle_is_served_by_both_arms(suite: SuiteRun) -> None:
    """Asserted as a non-win, on purpose, and this is not a bug report.

    The governed arm serves the rows. An export handle carries its narrowing in the desk row,
    the gate is shown one well-formed opaque id, and an id is not a capability unless
    something says it is. This test exists so that a change which *starts* refusing this call
    is noticed and written down rather than discovered -- the suite's claim about the boundary
    would move with it, and so would the two scenarios that follow it.
    """
    verdict = suite.by_key["laundered-handle"]

    assert verdict.ungoverned.refused is None
    assert verdict.governed.refused is None
    assert verdict.governed.effect == verdict.ungoverned.effect
    assert "81 orders" in verdict.governed.effect


@pytest.mark.scenario
def test_one_reviewed_ceiling_refills_alice_and_refuses_bob(suite: SuiteRun) -> None:
    """One annotation, two fates, decided by whether the caller has a default to fall back to."""
    narrowed = suite.by_key["injected-instruction"]
    refused = suite.by_key["tenant-probe"]

    # The ceiling refused the value, so the ceiling's policy id is what the rejection names.
    # Her own grant supplied the refill and bounded nothing, and naming it here would point a
    # reader at a store an admin mutates instead of at a file a reviewer read.
    rejection = _rejected(narrowed)["tenant_id"]
    assert rejection["policy"] == CEILING_POLICY
    assert rejection["policy"] != ALICE_TENANT_GRANT
    assert _envelope(narrowed).get("defaults_applied") == {"tenant_id": "acme", "limit": 5}

    # Same ceiling, same proposed tenant, and no default of his own to continue on.
    assert refused.governed.refused == "DefaultUnavailable"
    assert refused.records[-1].rejected[0].policy == CEILING_POLICY

    declared = next(
        item
        for item in policy_annotations(policy.POLICY_TEXT)
        if item.declared_id == CEILING_POLICY
    )
    assert "tenant_id" in (declared.annotation("constraints") or "")


@pytest.mark.scenario
def test_the_narrowed_report_still_hands_back_the_whole_desk(suite: SuiteRun) -> None:
    """The documented boundary of an action-layer decision, asserted in both halves.

    ``region`` was decided exactly as written -- ``us`` rejected, her own ``eu`` in its place --
    and the body returned a figure wider than its argument anyway. A layer that decides whether
    a call may happen, and with which arguments, decides nothing about what the body then
    chooses to compute. Govern the rows at the layer that owns them.
    """
    verdict = suite.by_key["honest-boundary"]
    payload = verdict.governed.results[-1]
    assert isinstance(payload, Mapping)

    assert _envelope(verdict)["processed"] == {"region": "eu", "status": "open"}
    assert payload["region"] == "eu"

    # The half no argument rule was ever in a position to withhold: the desk-wide open total,
    # and a count for every region including the two she was just narrowed out of.
    book = payload["book"]
    assert isinstance(book, Mapping)
    assert book["open_orders"] == 198
    assert book["regions"] == {"eu": 81, "uk": 54, "us": 63}


@pytest.mark.scenario
def test_the_governed_arms_write_one_record_each_and_the_other_arm_writes_none(
    suite: SuiteRun,
) -> None:
    """A trail is a consequence of there having been a gate, not a property of the database."""
    written = tuple(
        (verdict.scenario.key, record.principal.id, record.action, record.outcome)
        for verdict in suite.verdicts
        for record in verdict.records
    )

    assert written == EXPECTED_TRAIL
    assert [record.sequence for record in suite.sink.records] == list(range(len(EXPECTED_TRAIL)))
    assert verify_chain(suite.sink.records).ok is True
    # Not a log that stayed clean: no log. Those arms ran every one of the same calls.
    assert suite.ungoverned_sink.records == ()


@pytest.mark.scenario
def test_the_confused_deputy_is_two_names_against_one_handle(suite: SuiteRun) -> None:
    """The pair of records is the whole reason the laundering scenario survives as a test."""
    verdict = suite.by_key["laundered-handle"]
    minted = verdict.governed.results[0]
    assert isinstance(minted, Mapping)

    assert [(record.principal.id, record.action) for record in verdict.records] == [
        ("alice", 'Action::"desk.export"'),
        ("bob", 'Action::"desk.fetch"'),
    ]
    # The handle the second decision was shown is the one the first decision minted, and the
    # trail is the only place the two calls are visibly the same story.
    assert verdict.records[1].processed["job_id"] == minted["job_id"]


@pytest.mark.scenario
def test_no_governed_signature_default_is_accepted_anywhere_in_the_suite(suite: SuiteRun) -> None:
    """The field that reports an accepted signature default has no case here, and that is why.

    ``cancel_open_orders(region="eu")`` is the suite's only governed parameter with a Python
    default, and it exists to be *refused*: alice's grant denies ``eu``. The other defaults in
    ``desk_tools`` -- ``status`` on three tools and ``fmt`` on the export -- are parameters no
    policy here bounds, so they never reach the check and are never reported. Pinned as an
    absence so that a tool which later gains an accepted governed default shows up as a failure
    to be documented rather than as an untested branch.
    """
    assert {record.signature_defaults for record in suite.sink.records} == {()}
    assert suite.by_key["refused-signature-default"].governed.refused == "SignatureDefaultRejected"


@pytest.mark.scenario
def test_every_printed_section_renders_and_the_envelope_is_json(
    suite: SuiteRun, capsys: pytest.CaptureFixture[str]
) -> None:
    """The three printers have to survive the verdicts they are handed, refusals included."""
    verdict = suite.by_key["oversized-limit"]

    harness.show_scenario(verdict)
    scenario_section = capsys.readouterr().out
    harness.show_audit(suite.verdicts, suite.sink)
    audit_section = capsys.readouterr().out
    harness.show_envelope(verdict)
    envelope_section = capsys.readouterr().out

    assert verdict.scenario.key in scenario_section
    assert 'Action::"desk.search"' in audit_section
    rendered = json.loads(envelope_section[envelope_section.index("{") :])
    assert rendered == dict(_envelope(verdict))
