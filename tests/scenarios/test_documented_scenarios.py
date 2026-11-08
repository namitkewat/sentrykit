"""The scenario pages say what the suite does, down to the numbers in the tables.

`docs/scenarios.md` and `examples/scenarios/README.md` both carry a nine-row comparison, and
the whole argument on those pages is that two columns differ. A table is the easiest kind of
documentation to leave behind: the numbers in it were true when somebody pasted them, and a
grant edited by one digit or a reseeded book moves the suite without touching the page. A
reader then trusts the page, copies the shape of the policy it describes, and debugs the wrong
thing.

So the pages are checked against a real run rather than against each other. Three different
strengths, on purpose:

* **The trail block is byte-identical.** `docs/scenarios.md` reproduces what the suite prints,
  so that block is regenerated and compared line for line. Nothing about it is
  interpretation, which makes exactness the right standard.
* **Every row is accounted for.** Both pages must name all nine scenarios, in the order the
  suite runs them, and a row whose arm the suite *refuses* must say so by naming the error.
  Documenting a refusal as an allow, or the reverse, is the mistake with consequences.
* **Each arm's headline number appears in its own cell.** Not every number in the effect line
  -- a cell is prose and may summarise -- but the count or the row total has to be there, so a
  figure cannot drift while the sentence around it still reads plausibly.

Nothing here reaches a model.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from functools import cache
from pathlib import Path
from typing import Final

import pytest
from examples import desk
from examples.scenarios import harness
from examples.scenarios.harness import Verdict
from examples.scenarios.scenarios import SCENARIOS

from sentrykit.stores.memory import InMemoryAuditSink

ROOT: Final = Path(__file__).resolve().parents[2]
DOCS_PAGE: Final = ROOT / "docs" / "scenarios.md"
README: Final = ROOT / "examples" / "scenarios" / "README.md"
ROOT_README: Final = ROOT / "README.md"

PAGES: Final = (DOCS_PAGE, README)
"""Both pages carry the comparison, and both have to carry the same one."""

TRAIL_OPENS_WITH: Final = "   #  scenario"
"""How the reproduced audit-trail block begins, in `docs/scenarios.md`."""

README_TRAIL_ROWS: Final = ("   4  laundered-handle", "   5  laundered-handle")
"""The two trail lines the README quotes: the confused deputy, as evidence."""

ROOT_README_SECTION: Final = "### What that is worth, measured rather than asserted"
"""The heading of the root README's four-row summary of the suite."""

ROOT_README_SCENARIOS: Final = (
    "oversized-limit",
    "injected-instruction",
    "refused-signature-default",
    "laundered-handle",
)
"""Which four the root README summarises. It labels them in prose rather than by key, because
it is a landing page -- so they are named here instead, and the figures are what gets checked."""


@pytest.fixture(autouse=True)
def restored_desk() -> Iterator[None]:
    """Reseed the desk on the way out, so a destructive arm cannot escape this module.

    Yields:
        Nothing; the value of this fixture is its teardown.
    """
    yield
    desk.reset_desk()


@cache
def _verdicts() -> tuple[Verdict, ...]:
    """Run the whole suite once for this module, and keep the verdicts.

    Returns:
        One verdict per scenario, in order.
    """
    sink, resolve = harness.wire()
    return tuple(harness.run_scenario(scenario, sink, resolve) for scenario in SCENARIOS)


def _rows(page: Path) -> dict[str, str]:
    """Read a page's nine-row comparison table, keyed by the scenario it names.

    Args:
        page: The Markdown file.

    Returns:
        Scenario key to the whole row, as written. A row is matched to a scenario by the key
        appearing in its first cell, which is how both pages label them.
    """
    found: dict[str, str] = {}
    for line in page.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        first = line.split("|")[1]
        for scenario in SCENARIOS:
            if scenario.key in first:
                found[scenario.key] = line
    return found


def _counts(effect: str) -> set[str]:
    """Pull the figures out of an arm's effect line that a table cell has to carry.

    Args:
        effect: The arm's effect line.

    Returns:
        The integers that quantify the outcome -- rows served, orders cancelled -- and not the
        ones that were merely proposed. ``limit=100000 -> 81 orders`` yields ``{"81"}``,
        because 81 is what happened and 100000 is what was asked for.
    """
    return set(re.findall(r"(\d+) (?:orders|rows)", effect))


@pytest.mark.scenario
@pytest.mark.parametrize("page", PAGES, ids=lambda path: path.name)
def test_both_pages_list_every_scenario_in_the_order_the_suite_runs_them(page: Path) -> None:
    """A page missing a row, or holding a renamed one, is a page describing a different suite."""
    rows = _rows(page)
    text = page.read_text(encoding="utf-8")
    positions = [text.index(rows[scenario.key]) for scenario in SCENARIOS if scenario.key in rows]

    assert set(rows) == {scenario.key for scenario in SCENARIOS}
    assert positions == sorted(positions)


@pytest.mark.scenario
@pytest.mark.parametrize("page", PAGES, ids=lambda path: path.name)
def test_a_refused_arm_is_documented_as_a_refusal_and_named(page: Path) -> None:
    """The one drift with consequences: a page that reads as an allow where the suite refuses.

    Checked in both directions. A row for a scenario the suite allows must not name an error
    class either, because a reader counting wins off these tables would then count wrong.
    """
    rows = _rows(page)
    for verdict in _verdicts():
        row = rows[verdict.scenario.key]
        for arm in (verdict.ungoverned, verdict.governed):
            if arm.refused is not None:
                assert arm.refused in row, f"{verdict.scenario.key}: {arm.refused} not in the row"
        named = [arm.refused for arm in (verdict.ungoverned, verdict.governed) if arm.refused]
        for error in ("AuthzDenied", "DefaultUnavailable", "SignatureDefaultRejected"):
            if error not in named:
                assert error not in row, f"{verdict.scenario.key}: row names {error} unprompted"


@pytest.mark.scenario
@pytest.mark.parametrize("page", PAGES, ids=lambda path: path.name)
def test_each_arms_headline_figure_appears_in_its_own_row(page: Path) -> None:
    """A number in a cell has to be a number the suite produced."""
    rows = _rows(page)
    for verdict in _verdicts():
        row = rows[verdict.scenario.key]
        for arm in (verdict.ungoverned, verdict.governed):
            if arm.refused is not None:
                continue
            for count in _counts(arm.effect):
                assert count in row, (
                    f"{verdict.scenario.key}: the {arm.label} arm reported {count} and the row "
                    f"does not mention it"
                )


@pytest.mark.scenario
def test_the_trail_the_docs_page_reproduces_is_the_trail_the_suite_prints(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Byte-identical, because that block is output and not description."""
    verdicts = _verdicts()
    sink = _sink_of(verdicts)

    harness.show_audit(verdicts, sink)
    printed = [line for line in capsys.readouterr().out.splitlines() if line.strip()]

    page = _code_block(DOCS_PAGE, TRAIL_OPENS_WITH)
    assert page, f"{DOCS_PAGE.name} has no block opening with {TRAIL_OPENS_WITH!r}"
    # The section opens with its own banner and closes with three paragraphs of prose, neither
    # of which the page reproduces, so the comparison starts at the header row the page quotes.
    start = printed.index(page[0])
    assert printed[start : start + len(page)] == page


@pytest.mark.scenario
def test_the_two_rows_the_readme_quotes_are_the_confused_deputy_as_the_suite_wrote_it() -> None:
    """One handle, alice on the export and bob on the fetch, quoted without being retyped."""
    verdicts = _verdicts()
    trail = _code_block(README, README_TRAIL_ROWS[0])

    assert len(trail) == len(README_TRAIL_ROWS)
    laundered = next(v for v in verdicts if v.scenario.key == "laundered-handle")
    principals = [record.principal.id for record in laundered.records]
    actions = [record.action for record in laundered.records]

    assert principals == ["alice", "bob"]
    assert actions == ['Action::"desk.export"', 'Action::"desk.fetch"']
    for row, expected in zip(trail, README_TRAIL_ROWS, strict=True):
        assert row.startswith(expected)
        assert "allowed" in row


def _code_block(page: Path, opens_with: str) -> list[str]:
    """Return the non-blank lines of the one fenced block whose first line starts as given.

    Args:
        page: The Markdown file.
        opens_with: How the block's first line begins.

    Returns:
        The block's lines, blanks dropped so the page's own spacing is not the assertion.
    """
    text = page.read_text(encoding="utf-8")
    blocks = [
        block
        for block in re.findall(r"^```[a-z]*\n(.*?)^```", text, re.S | re.M)
        if block.lstrip("\n").startswith(opens_with)
    ]
    assert len(blocks) == 1, f"{page.name} has {len(blocks)} blocks opening with {opens_with!r}"
    return [line for line in blocks[0].splitlines() if line.strip()]


def _sink_of(verdicts: tuple[Verdict, ...]) -> InMemoryAuditSink:
    """Rebuild a sink holding exactly the records the run wrote, in order.

    :func:`harness.show_audit` reads the sink for the whole-log chain check as well as the
    per-scenario records, and the verdicts carry only the second. A sink filled from them is
    the same log by a different route, which is what keeps this test from needing
    :func:`harness.wire` to hand its sink back a second time.

    Args:
        verdicts: The run.

    Returns:
        A sink holding every record, oldest first.
    """
    sink = InMemoryAuditSink(name="documented")
    for verdict in verdicts:
        for record in verdict.records:
            sink.write(record)
    return sink


@pytest.mark.scenario
def test_the_root_readme_summary_carries_the_figures_the_suite_produces() -> None:
    """The landing page quotes four of the nine, and a landing page is read the most.

    It labels its rows in prose rather than by key, so the rows cannot be matched the way the
    two full tables are. The figures can be, and they are the part that goes stale.
    """
    verdicts = {verdict.scenario.key: verdict for verdict in _verdicts()}
    text = ROOT_README.read_text(encoding="utf-8")
    start = text.index(ROOT_README_SECTION)
    section = text[start : text.index("\n## ", start)]

    for key in ROOT_README_SCENARIOS:
        verdict = verdicts[key]
        for arm in (verdict.ungoverned, verdict.governed):
            if arm.refused is not None:
                assert "refused" in section, f"{key}: the {arm.label} arm is refused, unsaid"
                continue
            for count in _counts(arm.effect):
                assert count in section, (
                    f"{key}: the {arm.label} arm reported {count} and the section does not "
                    f"mention it"
                )
