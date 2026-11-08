"""The suite never reaches a live model, and this is the test that keeps it that way.

``tests/conftest.py`` empties both live tiers for every test. That is a property worth pinning
rather than trusting, because the failure is silent and expensive: nothing breaks, the examples
simply start sending real, billable requests to a third party, and every assertion that touches
a model answer starts depending on which model answered this week.

The guard is also easy to lose by accident. The autouse fixture deletes every ``SENTRYKIT_*``
variable, and for both tiers deleting the variable is the *dangerous* direction -- an unset URL
means "look", not "do not look". The frontier tier is the worse of the two, because the key that
enables it is called ``OPENROUTER_API_KEY`` and carries no prefix, so it survives the sweep and
is read from ``.env`` when the environment does not carry it. One tidying commit that folds the
two explicit ``setenv`` lines into the loop above them would re-open both.

These tests use no ``monkeypatch`` of their own on purpose. They assert what the *shared*
fixture leaves behind, so they fail if that fixture stops doing it.
"""

from __future__ import annotations

import os

import pytest
from examples import models


@pytest.mark.unit
def test_no_live_model_is_reachable_from_a_test() -> None:
    """The one assertion that matters: under the suite's own environment, there is no model."""
    assert models.choose().tier is models.Tier.NONE


@pytest.mark.unit
def test_both_tiers_are_switched_off_rather_than_merely_unconfigured() -> None:
    """Empty, not absent — for both, and for the same reason.

    An absent value is the permissive reading in each case, so a fixture that deleted these
    would read as careful and do the opposite.
    """
    assert os.environ["SENTRYKIT_OPENROUTER_URL"] == ""
    assert os.environ["SENTRYKIT_OLLAMA_URL"] == ""


@pytest.mark.unit
def test_the_reason_names_both_tiers_so_a_reader_knows_why_nothing_answered() -> None:
    reason = models.choose().reason

    assert "SENTRYKIT_OPENROUTER_URL" in reason
    assert "SENTRYKIT_OLLAMA_URL" in reason


@pytest.mark.unit
def test_the_key_variable_is_out_of_the_sweeps_reach_which_is_why_the_switch_exists() -> None:
    """Pins the reason, not just the mitigation.

    The autouse fixture clears variables by prefix. The key that enables the frontier tier does
    not carry that prefix, so no amount of sweeping reaches it and the tier has to be switched
    off by its own URL instead. If this ever stops being true the extra line becomes belt and
    braces rather than the only thing between the suite and a paid API — which is a change
    worth noticing deliberately.
    """
    assert not models.OPENROUTER_KEY_ENV_VAR.startswith("SENTRYKIT_")
    assert models.OPENROUTER_URL_ENV_VAR.startswith("SENTRYKIT_")
