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
three explicit ``setenv`` lines into the loop above them would re-open both.

Most of these use no ``monkeypatch`` of their own on purpose: they assert what the *shared*
fixture leaves behind, so they fail if that fixture stops doing it. The one exception sets a
fake key, and has to -- "a key is not enough, the URL switch is what decides" cannot be checked
by a test that depends on whoever ran it keeping a real key in ``.env``.
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
    """Empty, not absent — for all three, and for the same reason.

    An absent value is the permissive reading in each case, so a fixture that deleted these
    would read as careful and do the opposite. The key is here too: deleting it sends
    :func:`examples.models._api_key` to the repository's ``.env``, which on a developer's
    machine is exactly where a real one lives.
    """
    assert os.environ["SENTRYKIT_OPENROUTER_URL"] == ""
    assert os.environ["SENTRYKIT_OLLAMA_URL"] == ""
    assert os.environ[models.OPENROUTER_KEY_ENV_VAR] == ""


@pytest.mark.unit
def test_the_reason_names_the_missing_key_when_the_suite_has_emptied_it() -> None:
    """Under the shared fixture alone, and therefore the same sentence on every machine."""
    reason = models.choose().reason

    assert models.OPENROUTER_KEY_ENV_VAR in reason
    assert "SENTRYKIT_OLLAMA_URL" in reason


@pytest.mark.unit
def test_a_key_is_not_enough_because_the_url_switch_is_what_decides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With a key present, the tier is still off, and the reason says which switch did it.

    The fake key is the point. Asserting this against a real one would make the test pass on a
    machine that has it and fail on a machine that does not, which is how the suite came to
    have an expectation that depended on who ran it.
    """
    monkeypatch.setenv(models.OPENROUTER_KEY_ENV_VAR, "not-a-key")

    choice = models.choose()

    assert choice.tier is models.Tier.NONE
    assert models.OPENROUTER_URL_ENV_VAR in choice.reason
    assert "SENTRYKIT_OLLAMA_URL" in choice.reason


@pytest.mark.unit
def test_the_key_variable_is_out_of_the_sweeps_reach_which_is_why_the_switch_exists() -> None:
    """Pins the reason, not just the mitigation.

    The autouse fixture clears variables by prefix. The key that enables the frontier tier does
    not carry that prefix, so no amount of sweeping reaches it, and that is why the fixture has
    to name both the tier's URL and the key itself rather than relying on the sweep. Each of
    those two lines would hold on its own; they are both there because the failure is silent and
    the bill is somebody else's. If the key ever grows the prefix, this asymmetry stops being
    the reason — which is a change worth noticing deliberately rather than inheriting.
    """
    assert not models.OPENROUTER_KEY_ENV_VAR.startswith("SENTRYKIT_")
    assert models.OPENROUTER_URL_ENV_VAR.startswith("SENTRYKIT_")
