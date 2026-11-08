"""The shared half of every context provider, tested without a framework in sight.

`sentrykit/integrations/base.py` lives under `integrations/` but imports no web framework and
no agent SDK — it is the *contract* the adapters share, not an adapter. So it belongs here, in
the unit suite, where it runs in the `default` environment with neither FastAPI nor Flask
installed. That it can be tested at all from this file is itself the assertion that the
boundary holds.

Two things are pinned hardest, because both providers inherit them and a regression in either
is invisible until it is expensive:

* **The refusal rendering is built from the exception**, so it is identical whether the raising
  callable ran on the event loop, in a worker thread, or nowhere near HTTP at all.
* **`release()` is total.** A provider that established nothing must still leave the context
  clean, or the next request on a pooled thread inherits the last one's principal.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import pytest

from sentrykit.cedar import EntityRef
from sentrykit.config import Settings, configure
from sentrykit.context import (
    ContextScope,
    Principal,
    current_environment,
    current_principal,
    establish,
)
from sentrykit.envelope import last_envelope, set_last_envelope
from sentrykit.errors import (
    ArgumentRejected,
    AuditUnavailable,
    AuthzDenied,
    ConfigurationError,
    DefaultUnavailable,
    NoContext,
    NoValidArguments,
    SentrykitError,
    ValidationFailed,
)
from sentrykit.integrations.base import (
    DEFAULT_PRINCIPAL_HEADER,
    DEFAULT_REQUEST_ID_HEADER,
    STATUS_BY_ERROR,
    BaseContextProvider,
    action_of,
    error_envelope,
    error_payload,
    reason_for,
    status_for,
)
from sentrykit.stores.base import GrantSpec
from sentrykit.stores.memory import InMemoryGrantStore

SEARCH = 'Action::"orders.search"'
ORDERS = 'Tool::"orders"'


@dataclass
class FakeRequest:
    """The least a request can be: a case-insensitive bag of headers."""

    headers: dict[str, str] = field(default_factory=dict)

    def get(self, name: str) -> str | None:
        """Read one header, case-insensitively, as every real framework does."""
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None


class FakeProvider(BaseContextProvider[FakeRequest]):
    """A provider for a framework that does not exist, implementing only the four seams.

    Written from the same four methods a real adapter implements, so what it proves about
    :class:`BaseContextProvider` applies to FastAPI and Flask unchanged.
    """

    @property
    def name(self) -> str:
        """``fake``."""
        return "fake"

    def narrow(self, request: object) -> FakeRequest:
        """Accept only a :class:`FakeRequest`."""
        if isinstance(request, FakeRequest):
            return request
        raise ConfigurationError(f"the fake provider cannot use a {type(request).__name__}")

    def read_header(self, request: FakeRequest, name: str) -> str | None:
        """Read one header."""
        return request.get(name)

    def render_error(self, error: Exception) -> tuple[int, dict[str, object]]:
        """Render as the shared ``(status, body)`` pair; a real adapter wraps this."""
        return self.error_response(error)


@pytest.fixture
def store() -> InMemoryGrantStore:
    """A grant store holding one principal, ``alice``, in ``Role::"support"``."""
    grants = InMemoryGrantStore()
    grants.grant(GrantSpec(principal=EntityRef("User", "alice"), kind="role", subject="support"))
    return grants


@pytest.fixture
def provider(store: InMemoryGrantStore) -> FakeProvider:
    """A provider identifying callers by the default principal header."""
    return FakeProvider(grants=store)


# --- status mapping ------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (AuthzDenied(SEARCH, ORDERS, []), 403),
        (NoContext(SEARCH), 403),
        (ArgumentRejected("region", "Not permitted"), 400),
        (NoValidArguments(allowed={}, rejected=[]), 400),
        (DefaultUnavailable("region"), 400),
        (ValidationFailed([{"loc": ("limit",), "msg": "not an int", "type": "int_parsing"}]), 422),
        (AuditUnavailable("jsonl", "disk full"), 500),
        (ConfigurationError("bad DSN"), 500),
        (SentrykitError("something"), 500),
    ],
)
def test_each_sentrykit_error_maps_to_its_documented_status(
    error: Exception, expected: int
) -> None:
    assert status_for(error) == expected


@pytest.mark.unit
def test_a_host_subclass_inherits_its_base_errors_status() -> None:
    """The MRO walk, which is why a host extending an error does not get a surprise 500."""

    class TenantDenied(AuthzDenied):
        """A host's own refusal."""

    assert status_for(TenantDenied(SEARCH, ORDERS, ["p"])) == 403


@pytest.mark.unit
def test_an_error_sentrykit_has_never_heard_of_is_a_server_error() -> None:
    assert status_for(ValueError("not ours")) == 500


@pytest.mark.unit
def test_the_status_table_covers_every_shipped_error() -> None:
    """A new error class must be given a status, not left to fall through to 500."""
    shipped = {
        ArgumentRejected,
        AuditUnavailable,
        AuthzDenied,
        ConfigurationError,
        DefaultUnavailable,
        NoContext,
        NoValidArguments,
        SentrykitError,
        ValidationFailed,
    }

    assert shipped <= set(STATUS_BY_ERROR)


# --- action and reason ---------------------------------------------------------------------


@pytest.mark.unit
def test_the_errors_that_name_an_action_expose_it_for_per_action_verbosity() -> None:
    assert action_of(AuthzDenied(SEARCH, ORDERS, [])) == SEARCH
    assert action_of(NoContext(SEARCH)) == SEARCH


@pytest.mark.unit
def test_an_error_that_names_no_action_resolves_to_the_global_settings() -> None:
    assert action_of(NoValidArguments(allowed={}, rejected=[])) is None
    assert action_of(ValueError("not ours")) is None


@pytest.mark.unit
@pytest.mark.parametrize(
    ("error", "fragment"),
    [
        (AuthzDenied(SEARCH, ORDERS, []), "denied action"),
        (NoContext(SEARCH), "No principal in context"),
        (ArgumentRejected("region", "Value is not permitted"), "Value is not permitted"),
        (NoValidArguments(allowed={}, rejected=[]), "Every supplied argument"),
        (DefaultUnavailable("region"), "no policy default"),
        (ValidationFailed([{"loc": ("limit",), "msg": "nope", "type": "x"}]), "1 error(s)"),
        (ConfigurationError("secret DSN"), "could not be completed"),
        (AuditUnavailable("jsonl", "disk full"), "could not be completed"),
    ],
)
def test_every_refusal_explains_itself_in_one_sentence(error: Exception, fragment: str) -> None:
    assert fragment in reason_for(error)


@pytest.mark.unit
def test_an_operator_side_failure_does_not_leak_its_detail_to_the_caller() -> None:
    """A bad DSN is the operator's problem; the caller learns only that it failed."""
    reason = reason_for(ConfigurationError("jsonl://Z:/secret-share/audit.jsonl is unreachable"))

    assert "secret-share" not in reason


# --- envelope trimming ---------------------------------------------------------------------


@pytest.mark.unit
def test_verbosity_off_renders_no_envelope_at_all() -> None:
    assert error_envelope(AuthzDenied(SEARCH, ORDERS, ["p"]), verbosity="off") is None


@pytest.mark.unit
def test_a_denial_names_its_action_and_resource_from_summary_upwards() -> None:
    envelope = error_envelope(AuthzDenied(SEARCH, ORDERS, ["p"]), verbosity="summary")

    assert envelope == {
        "decision": "deny",
        "reason": reason_for(AuthzDenied(SEARCH, ORDERS, ["p"])),
        "action": SEARCH,
        "resource": ORDERS,
    }


@pytest.mark.unit
def test_a_denial_withholds_the_determining_policies_below_debug() -> None:
    """Policy ids describe the shape of the rule set, so they are debug-only."""
    error = AuthzDenied(SEARCH, ORDERS, ["support-may-search"])

    assert "determining_policies" not in (error_envelope(error, verbosity="verbose") or {})
    assert (error_envelope(error, verbosity="debug") or {})["determining_policies"] == [
        "support-may-search"
    ]


@pytest.mark.unit
def test_a_denial_from_an_engine_failure_shows_the_engine_errors_at_debug() -> None:
    """The distinction operators need: a policy said no, or Cedar could not evaluate."""
    error = AuthzDenied(SEARCH, ORDERS, [], engine_errors=["attribute `tier` not found"])

    envelope = error_envelope(error, verbosity="debug") or {}

    assert envelope["trace"] == {"engine_errors": ["attribute `tier` not found"]}


@pytest.mark.unit
def test_a_denial_with_no_engine_errors_carries_no_trace() -> None:
    envelope = error_envelope(AuthzDenied(SEARCH, ORDERS, ["p"]), verbosity="debug") or {}

    assert "trace" not in envelope


@pytest.mark.unit
def test_a_denial_with_no_resource_omits_the_key_rather_than_nulling_it() -> None:
    envelope = error_envelope(AuthzDenied(SEARCH, None, []), verbosity="summary") or {}

    assert "resource" not in envelope


@pytest.mark.unit
def test_a_missing_principal_names_the_action_it_was_missing_for() -> None:
    envelope = error_envelope(NoContext(SEARCH), verbosity="summary") or {}

    assert envelope["action"] == SEARCH
    assert envelope["decision"] == "deny"


@pytest.mark.unit
def test_a_strict_mode_rejection_reports_the_argument_and_its_provenance() -> None:
    error = ArgumentRejected("region", "Value is not one of the permitted values", "alice-region")

    envelope = error_envelope(error, verbosity="summary") or {}

    assert envelope["rejected"] == [
        {
            "name": "region",
            "reason": "Value is not one of the permitted values",
            "policy": "alice-region",
        }
    ]


@pytest.mark.unit
def test_a_rejection_with_no_known_policy_omits_the_provenance_key() -> None:
    envelope = error_envelope(ArgumentRejected("region", "No"), verbosity="summary") or {}

    assert envelope["rejected"] == [{"name": "region", "reason": "No"}]


@pytest.mark.unit
def test_the_allowed_set_a_caller_needs_to_retry_is_withheld_below_verbose() -> None:
    """It is the caller's own entitlement, but still a shape worth not volunteering."""
    error = NoValidArguments(
        allowed={"region": {"allow": ["eu", "uk"]}},
        rejected=[{"name": "region", "rule": "allow-set", "reason": "Not permitted"}],
    )

    summary = error_envelope(error, verbosity="summary") or {}
    verbose = error_envelope(error, verbosity="verbose") or {}

    assert "allowed" not in summary
    assert summary["rejected"] == [
        {"name": "region", "rule": "allow-set", "reason": "Not permitted"}
    ]
    assert verbose["allowed"] == {"region": {"allow": ["eu", "uk"]}}


@pytest.mark.unit
def test_a_missing_default_reads_as_a_rejection_of_the_argument_it_is_missing_for() -> None:
    envelope = error_envelope(DefaultUnavailable("region"), verbosity="summary") or {}

    assert envelope["rejected"] == [
        {"name": "region", "reason": "No policy default is configured."}
    ]


@pytest.mark.unit
def test_validation_errors_are_reported_without_the_value_that_failed() -> None:
    """Pydantic's ``input`` key holds the caller's own data — same rule as every other value."""
    error = ValidationFailed(
        [
            {
                "loc": ("limit",),
                "msg": "Input should be a valid integer",
                "type": "int_parsing",
                "input": "not-a-number",
                "url": "https://errors.pydantic.dev/2.13/v/int_parsing",
            }
        ]
    )

    summary = error_envelope(error, verbosity="summary") or {}
    verbose = error_envelope(error, verbosity="verbose") or {}

    assert summary["errors"] == [
        {"loc": ("limit",), "msg": "Input should be a valid integer", "type": "int_parsing"}
    ]
    assert verbose["errors"][0]["input"] == "not-a-number"  # type: ignore[index]
    assert "url" not in verbose["errors"][0]  # type: ignore[operator]


@pytest.mark.unit
def test_an_operator_side_failure_renders_a_bare_deny_with_no_detail() -> None:
    envelope = error_envelope(AuditUnavailable("jsonl", "disk full"), verbosity="debug") or {}

    assert envelope == {"decision": "deny", "reason": reason_for(AuditUnavailable("jsonl", "x"))}


# --- the whole payload ---------------------------------------------------------------------


@pytest.mark.unit
def test_the_refusal_body_carries_a_detail_a_machine_readable_error_and_the_envelope() -> None:
    body = error_payload(AuthzDenied(SEARCH, ORDERS, []), settings=Settings(verbosity="summary"))

    assert body["error"] == "AuthzDenied"
    assert body["detail"] == reason_for(AuthzDenied(SEARCH, ORDERS, []))
    assert isinstance(body["_authz"], dict)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("error", "phrase"),
    [
        (AuthzDenied(SEARCH, ORDERS, []), "Forbidden"),
        (NoValidArguments(allowed={}, rejected=[]), "Bad Request"),
        (ValidationFailed([]), "Unprocessable Entity"),
        (ConfigurationError("bad"), "Internal Server Error"),
    ],
)
def test_verbosity_off_collapses_a_refusal_to_its_status_phrase(
    error: Exception, phrase: str
) -> None:
    """``off`` means the caller learns nothing beyond the status — not even which action."""
    body = error_payload(error, settings=Settings(verbosity="off"))

    assert body == {"detail": phrase}


@pytest.mark.unit
def test_the_refusal_body_honours_the_process_verbosity_when_none_is_passed() -> None:
    configure(verbosity="off")

    assert error_payload(AuthzDenied(SEARCH, ORDERS, [])) == {"detail": "Forbidden"}


@pytest.mark.unit
def test_a_per_action_override_reaches_the_refusal_body_too() -> None:
    """The action is read off the error, so an action configured ``debug`` refuses at ``debug``."""
    from sentrykit.config import override_action

    configure(verbosity="summary")
    override_action(SEARCH, verbosity="debug")

    body = error_payload(AuthzDenied(SEARCH, ORDERS, ["support-may-search"]))

    assert body["_authz"]["determining_policies"] == ["support-may-search"]  # type: ignore[index]


# --- identity resolution -------------------------------------------------------------------


@pytest.mark.unit
def test_a_principal_id_is_materialized_through_the_grant_store(provider: FakeProvider) -> None:
    """The whole split: the app names the caller, the store supplies their authority."""
    request = FakeRequest({DEFAULT_PRINCIPAL_HEADER: "alice"})

    resolved = provider.resolve_principal(request)

    assert resolved is not None
    assert resolved.roles == ("support",)


@pytest.mark.unit
def test_an_entity_reference_names_the_principal_type_explicitly(
    store: InMemoryGrantStore,
) -> None:
    provider = FakeProvider(identify=lambda _: EntityRef("User", "alice"), grants=store)

    resolved = provider.resolve_principal(FakeRequest())

    assert resolved is not None
    assert resolved.uid == EntityRef("User", "alice")


@pytest.mark.unit
def test_a_ready_made_principal_bypasses_the_store_entirely() -> None:
    """The escape hatch for an app that materializes principals its own way."""
    supplied = Principal(id="carol", roles=("auditor",))
    provider = FakeProvider(identify=lambda _: supplied)

    assert provider.resolve_principal(FakeRequest()) is supplied


@pytest.mark.unit
def test_an_unauthenticated_caller_resolves_to_no_principal(provider: FakeProvider) -> None:
    assert provider.resolve_principal(FakeRequest()) is None


@pytest.mark.unit
def test_an_id_the_store_has_never_heard_of_is_not_an_error(provider: FakeProvider) -> None:
    """It fails closed a few frames later, as a refusal the caller can be shown."""
    assert provider.resolve_principal(FakeRequest({DEFAULT_PRINCIPAL_HEADER: "mallory"})) is None


@pytest.mark.unit
def test_resolving_an_identity_with_no_grant_store_is_a_configuration_error() -> None:
    provider = FakeProvider(identify=lambda _: "alice")

    with pytest.raises(ConfigurationError, match="no grant store is configured"):
        provider.resolve_principal(FakeRequest())


@pytest.mark.unit
def test_the_grant_store_falls_back_to_the_installed_governors(
    store: InMemoryGrantStore,
) -> None:
    """So ``install(grant_store=..., context_provider=...)`` needs no second wiring step."""
    from sentrykit.engine import install

    install("permit (principal, action, resource);", grant_store=store)
    provider = FakeProvider(identify=lambda _: "alice")

    resolved = provider.resolve_principal(FakeRequest())

    assert resolved is not None
    assert resolved.roles == ("support",)


@pytest.mark.unit
def test_with_neither_a_provider_store_nor_a_governor_there_is_no_store() -> None:
    assert FakeProvider().grants is None


@pytest.mark.unit
def test_a_provider_reports_which_header_its_default_identify_reads() -> None:
    """Public so a host debugging a 403 can ask the provider rather than read the source."""
    assert FakeProvider().principal_header == DEFAULT_PRINCIPAL_HEADER
    assert FakeProvider(principal_header="x-user").principal_header == "x-user"


# --- environment ---------------------------------------------------------------------------


@pytest.mark.unit
def test_every_request_establishes_a_channel_and_a_correlation_id(
    provider: FakeProvider,
) -> None:
    environment = provider.environment_for(FakeRequest())

    assert environment["channel"] == "http"
    assert isinstance(environment["request_id"], str)
    assert environment["request_id"]


@pytest.mark.unit
def test_a_callers_own_correlation_id_is_carried_through(provider: FakeProvider) -> None:
    """What makes one trace span a gateway and the service behind it."""
    request = FakeRequest({DEFAULT_REQUEST_ID_HEADER: " req-42 "})

    assert provider.request_id(request) == "req-42"


@pytest.mark.unit
def test_a_blank_correlation_id_is_replaced_rather_than_established_empty(
    provider: FakeProvider,
) -> None:
    assert provider.request_id(FakeRequest({DEFAULT_REQUEST_ID_HEADER: "   "}))


@pytest.mark.unit
def test_two_requests_get_two_different_correlation_ids(provider: FakeProvider) -> None:
    assert provider.request_id(FakeRequest()) != provider.request_id(FakeRequest())


@pytest.mark.unit
def test_an_app_supplied_environment_is_merged_over_the_providers(
    store: InMemoryGrantStore,
) -> None:
    """An app with a better request id than ours should win."""
    provider = FakeProvider(
        grants=store,
        environment=lambda _: {"auth_strength": "mfa", "request_id": "app-chosen"},
    )

    environment = provider.environment_for(FakeRequest())

    assert environment["auth_strength"] == "mfa"
    assert environment["request_id"] == "app-chosen"


@pytest.mark.unit
def test_an_agent_provider_can_declare_a_different_channel(store: InMemoryGrantStore) -> None:
    """The agent providers establish ``agent`` through the same constructor."""
    provider = FakeProvider(grants=store, channel="agent")

    assert provider.channel == "agent"
    assert provider.environment_for(FakeRequest())["channel"] == "agent"


# --- the lifecycle -------------------------------------------------------------------------


@pytest.mark.unit
def test_establishing_makes_the_caller_the_ambient_principal(provider: FakeProvider) -> None:
    scope = provider.establish(FakeRequest({DEFAULT_PRINCIPAL_HEADER: "alice"}))

    principal = current_principal()
    assert principal is not None
    assert principal.id == "alice"
    assert current_environment()["channel"] == "http"
    assert isinstance(scope, ContextScope)


@pytest.mark.unit
def test_releasing_takes_the_principal_back_down_again(provider: FakeProvider) -> None:
    scope = provider.establish(FakeRequest({DEFAULT_PRINCIPAL_HEADER: "alice"}))

    provider.release(scope)

    assert current_principal() is None
    assert current_environment() == {}


@pytest.mark.unit
def test_an_unauthenticated_request_establishes_nothing_and_gets_no_scope(
    provider: FakeProvider,
) -> None:
    assert provider.establish(FakeRequest()) is None


@pytest.mark.unit
def test_an_unauthenticated_request_clears_whatever_was_left_behind(
    provider: FakeProvider,
) -> None:
    """ "No principal" has to mean *no* principal, not "whatever the last request left"."""
    establish(Principal(id="leftover", roles=("admin",)))

    provider.establish(FakeRequest())

    assert current_principal() is None


@pytest.mark.unit
def test_releasing_nothing_still_leaves_the_context_clean(provider: FakeProvider) -> None:
    """``release(None)`` is the documented, total form — never a special case at the call site."""
    establish(Principal(id="leftover", roles=("admin",)))

    provider.release(None)

    assert current_principal() is None


@pytest.mark.unit
def test_releasing_drops_the_last_decisions_envelope_too(provider: FakeProvider) -> None:
    """A pooled worker must not be able to report the previous request's decision as its own."""
    scope = provider.establish(FakeRequest({DEFAULT_PRINCIPAL_HEADER: "alice"}))
    set_last_envelope(None)  # baseline, then simulate a decision having happened
    from sentrykit.envelope import AuthzEnvelope

    set_last_envelope(AuthzEnvelope(decision="allow", action=SEARCH))

    provider.release(scope)

    assert last_envelope() is None


@pytest.mark.unit
def test_a_request_from_the_wrong_framework_is_a_configuration_error(
    provider: FakeProvider,
) -> None:
    with pytest.raises(ConfigurationError, match="cannot use a"):
        provider.establish(object())


# --- the seams a subclass must supply --------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("seam", ["name", "narrow", "read_header", "render_error"])
def test_the_base_provider_refuses_to_pretend_it_is_a_framework(seam: str) -> None:
    """Each seam raises rather than returning something plausible-but-wrong."""
    bare = BaseContextProvider[FakeRequest]()

    with pytest.raises(NotImplementedError):
        if seam == "name":
            _ = bare.name
        elif seam == "narrow":
            bare.narrow(FakeRequest())
        elif seam == "read_header":
            bare.read_header(FakeRequest(), "x-user")
        else:
            bare.render_error(NoContext(SEARCH))


@pytest.mark.unit
def test_the_shared_error_response_is_the_status_and_the_body_together(
    provider: FakeProvider,
) -> None:
    """Both shipped adapters call exactly this, which is what makes their 403s identical."""
    configure(verbosity="summary")

    status, body = provider.error_response(AuthzDenied(SEARCH, ORDERS, []))

    assert status == 403
    assert body == error_payload(AuthzDenied(SEARCH, ORDERS, []))


# --- the header fallback announces itself ----------------------------------------------------

WARNING_MESSAGE = "was built without identify="
"""The opening of the construction-time warning, matched on rather than quoted whole.

The sentence names the provider class and the key it reads, both of which vary by provider, so
a test that pinned the whole string would be asserting the wording of the remedy rather than
that the warning fires at all.
"""


def header_fallback_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Return the captured records announcing the caller-supplied-principal fallback.

    Args:
        caplog: The capture fixture.

    Returns:
        The matching records, in the order they were emitted.
    """
    return [record for record in caplog.records if WARNING_MESSAGE in record.getMessage()]


@pytest.mark.unit
def test_a_provider_with_no_identify_says_so_at_construction(
    store: InMemoryGrantStore, caplog: pytest.LogCaptureFixture
) -> None:
    """The insecure-but-documented default must be reached by choice, not by omission.

    A provider built with no ``identify`` resolves whoever the request *claims* to be, so a
    caller who sets the principal header is materialized with that principal's roles. That is
    correct for an example app and wrong everywhere else, and the difference between the two
    is a judgement only the deploying engineer can make — which they cannot make if the
    library never mentions it.
    """
    with caplog.at_level(logging.WARNING, logger="sentrykit"):
        FakeProvider(grants=store)

    warnings = header_fallback_warnings(caplog)
    assert len(warnings) == 1
    assert warnings[0].levelno == logging.WARNING
    assert warnings[0].name == "sentrykit.integrations"
    message = warnings[0].getMessage()
    assert "FakeProvider" in message
    assert DEFAULT_PRINCIPAL_HEADER in message
    assert "identify=" in message


@pytest.mark.unit
def test_only_the_provider_that_falls_back_to_the_request_is_warned_about(
    store: InMemoryGrantStore, caplog: pytest.LogCaptureFixture
) -> None:
    """The warning marks one wiring as risky, and must stay silent for the safe one.

    Two providers are built here so the discrimination is the assertion rather than two
    separate counts: a warning that also fires on the correct wiring is a warning operators
    filter out, which costs the insecure case the only notice it gets. The two are told apart
    by the key each names, which is also how a server reading a non-default key — the MCP
    provider reads the same name out of an ``_meta`` object — is told about *that* key.
    """
    with caplog.at_level(logging.WARNING, logger="sentrykit"):
        FakeProvider(grants=store, identify=lambda request: "alice", principal_header="x-resolved")
        FakeProvider(grants=store, principal_header="x-asserted")

    named = [record.getMessage() for record in header_fallback_warnings(caplog)]
    assert len(named) == 1
    assert "x-asserted" in named[0]
    assert "x-resolved" not in named[0]


@pytest.mark.unit
def test_the_warning_is_once_per_provider_and_not_once_per_request(
    store: InMemoryGrantStore, caplog: pytest.LogCaptureFixture
) -> None:
    """Wiring is a one-off; serving is the hot path, and a line per request is a flood.

    The count is the assertion: three requests through a provider that keeps warning would
    emit four records, and the one that matters would be the one nobody reads.
    """
    with caplog.at_level(logging.WARNING, logger="sentrykit"):
        provider = FakeProvider(grants=store)
        for _ in range(3):
            scope = provider.establish(FakeRequest({DEFAULT_PRINCIPAL_HEADER: "alice"}))
            provider.release(scope)

    assert len(header_fallback_warnings(caplog)) == 1


@pytest.mark.unit
def test_the_warning_carries_the_names_as_structured_fields_too(
    store: InMemoryGrantStore, caplog: pytest.LogCaptureFixture
) -> None:
    """An aggregator must be able to find every such provider without parsing prose.

    Both names are on the record as fields as well as in the sentence, because the sentence is
    what a developer reads on stderr and the fields are what a fleet-wide query reads.
    """
    with caplog.at_level(logging.WARNING, logger="sentrykit"):
        FakeProvider(grants=store)

    record = header_fallback_warnings(caplog)[0]
    assert record.provider == "FakeProvider"  # type: ignore[attr-defined]
    assert record.principal_header == DEFAULT_PRINCIPAL_HEADER  # type: ignore[attr-defined]


@pytest.mark.unit
def test_the_warning_carries_no_principal_name_from_any_request(
    store: InMemoryGrantStore, caplog: pytest.LogCaptureFixture
) -> None:
    """Construction happens before any request, so there is no identity to leak into it.

    The operational channel never carries values, and this warning is about a key rather than
    whatever a caller later puts in it — asserted here because the obvious way to make the
    message more helpful is to quote the principal it just trusted.
    """
    with caplog.at_level(logging.WARNING, logger="sentrykit"):
        provider = FakeProvider(grants=store)
        provider.release(provider.establish(FakeRequest({DEFAULT_PRINCIPAL_HEADER: "alice"})))

    assert "alice" not in header_fallback_warnings(caplog)[0].getMessage()
