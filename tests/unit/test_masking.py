"""Masking strategies and the three ways a field selects one.

Precedence is the part worth pinning down: a policy obligation beats a signature annotation,
which beats the configured default. That ordering is deliberate — an obligation is *reviewed
logic*, so it must be able to tighten what a developer declared, and it must not be possible
for a signature to loosen what a policy demanded.

The property-based tests cover the claim that matters more than any individual example: for
``redact`` and ``hmac``, the raw value must not survive anywhere in the output. An
example-based test proves that for the examples someone thought of.
"""

from __future__ import annotations

import string
from typing import Annotated

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sentrykit.config import Settings
from sentrykit.constraints import RejectedArgument
from sentrykit.engine import ArgumentSpec
from sentrykit.errors import ConfigurationError
from sentrykit.masking import (
    HmacStrategy,
    Masker,
    PartialStrategy,
    RedactStrategy,
    Sensitive,
    TokenizeStrategy,
    sensitive_fields,
)
from sentrykit.stores.memory import InMemoryTokenVault

# The autouse reset in ``tests/conftest.py`` is function-scoped; hypothesis re-runs the body
# many times inside one fixture setup, which is safe here because none of these tests touch
# the process-wide state the fixture guards.
_HYPOTHESIS = settings(suppress_health_check=[HealthCheck.function_scoped_fixture])

KEY = b"a-test-hmac-key"

# No ``*``, so a partial mask's placeholder can never be confused with a character that was
# genuinely revealed from the raw value.
SAFE = string.ascii_letters + string.digits + "-_.@"
LONG_VALUES = st.text(alphabet=SAFE, min_size=12, max_size=64)
ANY_VALUES = st.text(alphabet=SAFE, min_size=1, max_size=40)


def lookup(
    account: Annotated[str, Sensitive("hmac")] = "",
    note: Annotated[str, Sensitive()] = "",
    region: str = "eu-west",
) -> None:
    """A protected callable carrying both spellings of the sensitive marker."""


# --- individual strategies -----------------------------------------------------------------


@pytest.mark.unit
def test_redaction_leaves_nothing_of_the_value() -> None:
    masked = RedactStrategy().mask("4111-1111-1111-1111", field="card")

    assert "4111" not in str(masked)
    assert masked == "[redacted]"


@pytest.mark.unit
def test_a_partial_mask_keeps_only_the_configured_suffix() -> None:
    masked = PartialStrategy(keep=4).mask("4111111111111234", field="card")

    assert str(masked).endswith("1234")
    assert "4111111111111234" not in str(masked)
    assert str(masked).count("*") == len("4111111111111234") - 4


@pytest.mark.unit
def test_a_value_no_longer_than_the_kept_suffix_is_masked_outright() -> None:
    masked = PartialStrategy(keep=4).mask("abc", field="card")

    assert set(str(masked)) == {"*"}


@pytest.mark.unit
def test_a_partial_mask_honours_its_placeholder() -> None:
    masked = PartialStrategy(keep=2, placeholder="#").mask("abcdef", field="card")

    assert str(masked) == "####ef"


@pytest.mark.unit
def test_an_hmac_is_stable_for_the_same_value_in_the_same_field() -> None:
    strategy = HmacStrategy(KEY)

    first = strategy.mask("customer-42", field="customer_id")
    second = strategy.mask("customer-42", field="customer_id")

    assert first == second
    assert str(first).startswith("hmac:")


@pytest.mark.unit
def test_an_hmac_is_bound_to_its_field_so_two_fields_do_not_correlate() -> None:
    strategy = HmacStrategy(KEY)

    assert strategy.mask("shared", field="a") != strategy.mask("shared", field="b")


@pytest.mark.unit
def test_an_hmac_is_bound_to_its_key() -> None:
    assert HmacStrategy(KEY).mask("v", field="f") != HmacStrategy(b"other").mask("v", field="f")


@pytest.mark.unit
def test_an_hmac_without_a_key_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError):
        HmacStrategy(b"")


@pytest.mark.unit
def test_a_token_is_reversible_only_through_the_vault() -> None:
    vault = InMemoryTokenVault()
    strategy = TokenizeStrategy(vault)

    masked = str(strategy.mask("4111-1111-1111-1111", field="card"))

    assert "4111" not in masked
    assert masked.startswith("token:")
    assert vault.resolve(masked.removeprefix("token:")) == "4111-1111-1111-1111"


@pytest.mark.unit
def test_a_token_is_stable_for_a_repeated_value() -> None:
    strategy = TokenizeStrategy(InMemoryTokenVault())

    assert strategy.mask("same", field="f") == strategy.mask("same", field="f")


@pytest.mark.unit
def test_every_strategy_reports_the_name_the_audit_record_will_carry() -> None:
    assert RedactStrategy().name == "redact"
    assert PartialStrategy().name == "partial"
    assert HmacStrategy(KEY).name == "hmac"
    assert TokenizeStrategy(InMemoryTokenVault()).name == "tokenize"


# --- selecting a strategy ------------------------------------------------------------------


@pytest.mark.unit
def test_a_signature_annotation_declares_which_fields_are_sensitive() -> None:
    declared = sensitive_fields(ArgumentSpec.from_callable(lookup).model)

    assert declared == {"account": "hmac", "note": None}


@pytest.mark.unit
def test_a_callable_with_no_markers_declares_nothing() -> None:
    def plain(a: str = "", b: int = 0) -> None: ...

    assert sensitive_fields(ArgumentSpec.from_callable(plain).model) == {}


@pytest.mark.unit
def test_a_declared_field_with_no_strategy_falls_back_to_the_default() -> None:
    masker = Masker(key=KEY, default="redact")

    plan = masker.plan(declared={"note": None})

    assert plan["note"] == "redact"


@pytest.mark.unit
def test_a_declared_strategy_is_honoured() -> None:
    plan = Masker(key=KEY, default="redact").plan(declared={"account": "hmac"})

    assert plan["account"] == "hmac"


@pytest.mark.unit
def test_an_obligation_overrides_a_signature_declaration() -> None:
    masker = Masker(key=KEY)

    plan = masker.plan(declared={"account": "partial"}, obligations=("redact:account",))

    assert plan["account"] == "redact"


@pytest.mark.unit
def test_an_unqualified_mask_obligation_uses_the_configured_default() -> None:
    masker = Masker(key=KEY, default="redact")

    plan = masker.plan(obligations=("mask:customer_id",))

    assert plan["customer_id"] == "redact"


@pytest.mark.unit
def test_an_obligation_can_name_a_field_the_signature_never_declared() -> None:
    plan = Masker(key=KEY).plan(declared={"account": "hmac"}, obligations=("redact:secret",))

    assert plan == {"account": "hmac", "secret": "redact"}


@pytest.mark.unit
@pytest.mark.parametrize("obligation", ["notify:secops", "justify", "escalate:oncall"])
def test_an_obligation_that_is_not_a_masking_instruction_is_left_for_the_host(
    obligation: str,
) -> None:
    assert Masker(key=KEY).plan(obligations=(obligation,)) == {}


@pytest.mark.unit
def test_nothing_is_masked_when_nothing_asked_for_it() -> None:
    assert Masker(key=KEY).plan() == {}


# --- applying a plan -----------------------------------------------------------------------


@pytest.mark.unit
def test_masking_a_mapping_leaves_the_input_untouched() -> None:
    masker = Masker(key=KEY)
    values = {"account": "ACCT-SECRET", "region": "eu-west"}

    masked = masker.mask_mapping(values, {"account": "redact"})

    assert values == {"account": "ACCT-SECRET", "region": "eu-west"}
    assert masked["account"] == "[redacted]"
    assert masked["region"] == "eu-west"


@pytest.mark.unit
def test_a_plan_naming_a_field_that_is_absent_changes_nothing() -> None:
    masked = Masker(key=KEY).mask_mapping({"region": "eu"}, {"account": "redact"})

    assert masked == {"region": "eu"}


@pytest.mark.unit
def test_the_value_carried_on_a_rejection_is_masked_too() -> None:
    masker = Masker(key=KEY)
    rejected = (
        RejectedArgument(
            name="account",
            rule="allow-set",
            reason="Not in the allowed set",
            policy="grant-accounts",
            value="ACCT-SECRET",
        ),
        RejectedArgument(name="limit", rule="maximum", reason="Too large", value=9000),
    )

    masked = masker.mask_rejections(rejected, {"account": "redact"})

    assert [item.name for item in masked] == ["account", "limit"]
    assert masked[0].value == "[redacted]"
    assert masked[0].reason == "Not in the allowed set"
    assert masked[0].policy == "grant-accounts"
    assert masked[1].value == 9000


@pytest.mark.unit
def test_masking_with_a_strategy_the_masker_does_not_have_is_a_configuration_error() -> None:
    masker = Masker(key=KEY)  # no vault, so tokenize cannot be built

    with pytest.raises(ConfigurationError):
        masker.mask_value("card", "4111", "tokenize")


# --- building from settings ----------------------------------------------------------------


@pytest.mark.unit
def test_a_masker_built_from_settings_uses_the_configured_default() -> None:
    settings_with_key = Settings(mask_default="redact", hmac_key="k")  # type: ignore[arg-type]

    masker = Masker.from_settings(settings_with_key)

    assert masker.plan(declared={"note": None})["note"] == "redact"


@pytest.mark.unit
def test_a_masker_with_no_key_still_masks_the_strategies_that_need_none() -> None:
    """A missing key is only a fault at the point something actually asks for a digest."""
    masker = Masker.from_settings(Settings(mask_default="redact", hmac_key=None))

    assert masker.mask_value("secret", "raw", "redact") == "[redacted]"
    assert "raw" not in str(masker.mask_value("secret", "raw-value-here", "partial"))


@pytest.mark.unit
def test_asking_an_unkeyed_masker_for_an_hmac_is_a_configuration_error() -> None:
    masker = Masker.from_settings(Settings(mask_default="redact", hmac_key=None))

    with pytest.raises(ConfigurationError):
        masker.mask_value("secret", "raw", "hmac")


@pytest.mark.unit
def test_asking_a_vaultless_masker_to_tokenize_is_a_configuration_error() -> None:
    masker = Masker.from_settings(Settings(mask_default="redact", hmac_key=None))

    with pytest.raises(ConfigurationError):
        masker.mask_value("card", "4111", "tokenize")


@pytest.mark.unit
def test_a_tokenize_default_works_once_a_vault_is_supplied() -> None:
    masker = Masker.from_settings(
        Settings(mask_default="tokenize", hmac_key=None), vault=InMemoryTokenVault()
    )

    assert str(masker.mask_value("card", "4111", "tokenize")).startswith("token:")


# --- properties ----------------------------------------------------------------------------


@pytest.mark.unit
@_HYPOTHESIS
@given(raw=LONG_VALUES)
def test_a_redacted_value_never_contains_the_value_it_replaced(raw: str) -> None:
    assert raw not in str(RedactStrategy().mask(raw, field="secret"))


@pytest.mark.unit
@_HYPOTHESIS
@given(raw=LONG_VALUES)
def test_an_hmac_never_contains_the_value_it_digested(raw: str) -> None:
    assert raw not in str(HmacStrategy(KEY).mask(raw, field="secret"))


@pytest.mark.unit
@_HYPOTHESIS
@given(raw=ANY_VALUES, keep=st.integers(min_value=1, max_value=8))
def test_a_partial_mask_reveals_at_most_the_trailing_characters_it_promised(
    raw: str, keep: int
) -> None:
    masked = str(PartialStrategy(keep=keep).mask(raw, field="secret"))

    if len(raw) > keep:
        assert raw[-keep:] in masked
        assert raw[-(keep + 1) :] not in masked
    else:
        assert raw not in masked


@pytest.mark.unit
@pytest.mark.parametrize("strategy_name", ["redact", "partial", "hmac", "tokenize"])
@_HYPOTHESIS
@given(raw=ANY_VALUES)
def test_masking_the_same_value_twice_gives_the_same_answer(raw: str, strategy_name: str) -> None:
    masker = Masker(key=KEY, vault=InMemoryTokenVault())

    first = masker.mask_value("secret", raw, strategy_name)  # type: ignore[arg-type]
    second = masker.mask_value("secret", raw, strategy_name)  # type: ignore[arg-type]

    assert first == second
