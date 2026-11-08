"""What every framework provider shares: identity resolution, lifecycle, and refusal rendering.

sentrykit has **one decorator and N context providers**. A provider is small on
purpose — it does exactly two things, and both of them are the same on every framework:

1. **Establish** ambient context at the boundary, from the framework's request plus an
   app-supplied *auth → principal-id* callback, resolving that id through a
   :class:`~sentrykit.stores.base.GrantStore` so the principal arrives at the decision path
   already materialized (roles, parent edges, attributes, argument constraints, expiries
   already applied).
2. **Render** a sentrykit refusal as an HTTP response carrying the ``_authz`` envelope at
   whatever the effective verbosity allows.

Everything genuinely framework-specific — how a header is read, how a response is built, which
hook runs at teardown — is a handful of methods on the subclass. The status mapping and the
envelope renderer live here so a FastAPI 403 and a Flask 403 are the *same* 403.

## The per-request lifecycle is establish-then-reset, and the reset is correctness

A provider **must** release the context it established, in a `finally` or in the framework's
teardown hook. This is not tidiness — it is the failure mode: Flask runs a request on a
pooled worker thread and its test client runs one in the caller's own context, so an
un-reset :class:`~contextvars.ContextVar` from request *N* is still ambient when request
*N+1* starts. Request *N+1* would then be authorized as request
*N*'s principal — the worst failure this library can have.

So the contract is:

```python
scope = provider.establish(request)      # at the boundary
try:
    ...                                  # the handler, and anything it calls
finally:
    provider.release(scope)              # ALWAYS, even on the error path
```

:meth:`BaseContextProvider.release` is deliberately total: it resets the scope when there is
one, clears the ambient context outright when there is not, and drops the last envelope
either way, so nothing about request *N* survives into request *N+1*.

An **unauthenticated** request establishes no principal and gets no scope. That is the
fail-closed rule doing its job: every protected call inside such a request
raises :class:`~sentrykit.errors.NoContext`, which renders as a 403. The provider still
clears the context on the way in, because "no principal" must mean *no* principal rather than
"whatever the last request left behind".

## Refusals are rendered from the exception, not from ambient state

Ambient state is not reliably there when a refusal is rendered. A sync FastAPI route runs in
an AnyIO worker thread, which receives a *copy* of the context — so a ``ContextVar`` written
inside it, including the one :func:`~sentrykit.envelope.last_envelope` reads, is discarded
on return and is simply not there when the exception handler runs. FastAPI's
yield-dependency teardown has the same problem from the other direction: it unwinds *before*
the exception handler.

Every sentrykit error already carries structured detail — the refused action and its
determining policies, the offending argument name and reason, the allowed set, pydantic's
field errors — so :func:`error_envelope` reads the exception and nothing else. The rendering
is then identical on every framework and on every code path, which is the only way the tests
can mean anything.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Final, Generic, TypeVar

from sentrykit.cedar import EntityRef
from sentrykit.config import Settings, Verbosity, settings_for
from sentrykit.context import Channel, ContextScope, Principal, clear_context, establish
from sentrykit.envelope import current_recorder, record_decisions, set_last_envelope
from sentrykit.errors import (
    ArgumentRejected,
    AuditUnavailable,
    AuthzDenied,
    ConfigurationError,
    DefaultUnavailable,
    NoContext,
    NoValidArguments,
    ReservedKey,
    SentrykitError,
    ValidationFailed,
)
from sentrykit.stores.base import ContextProvider, GrantStore

__all__ = [
    "DEFAULT_PRINCIPAL_HEADER",
    "DEFAULT_REQUEST_ID_HEADER",
    "DEFAULT_STATUS",
    "NARROWED_ARGUMENTS_HEADER",
    "NARROWED_HEADER",
    "STATUS_BY_ERROR",
    "STATUS_PHRASES",
    "BaseContextProvider",
    "ContextProvider",
    "EnvironmentFactory",
    "Identify",
    "Identity",
    "action_of",
    "error_envelope",
    "error_payload",
    "narrowing_headers",
    "reason_for",
    "status_for",
]

_LOGGER: Final = logging.getLogger("sentrykit.integrations")

RequestT = TypeVar("RequestT")
"""The framework's request type — ``starlette.requests.Request``, ``flask.Request``, …"""

Identity = str | EntityRef | Principal
"""What an app's auth callback may hand back.

A ``str`` is a principal id and is read as ``User::"<id>"``; an
:class:`~sentrykit.cedar.EntityRef` names the type explicitly. Both are resolved through
:meth:`~sentrykit.stores.base.GrantStore.get_principal`, which is the point — roles, group
edges and per-argument constraints come from the store, not from the request.

A ready-made :class:`~sentrykit.context.Principal` is accepted as the escape hatch for an app
that has no grant store, or that materializes principals its own way. It is used as-is.
"""

Identify = Callable[[RequestT], Identity | None]
"""An app's auth → identity callback. ``None`` means "unauthenticated", not "error"."""

EnvironmentFactory = Callable[[RequestT], Mapping[str, object]]
"""Extra Cedar request context contributed per request — auth strength, tenant, break-glass."""

DEFAULT_PRINCIPAL_HEADER: Final = "x-sentrykit-principal"
"""Header the DSN-built default :attr:`~BaseContextProvider.identify` reads a principal id from.

A provider built from a bare DSN (``fastapi://``) has no application auth to call into, so it
falls back to a header. That is enough for an example app, a smoke test, or a service behind
a gateway that has already authenticated the caller — and nowhere near enough for anything
else, which the docs say in as many words. Real deployments pass ``identify=``.
"""

DEFAULT_REQUEST_ID_HEADER: Final = "x-request-id"
"""Header a correlation id is taken from when the caller supplies one."""

NARROWED_HEADER: Final = "x-sentrykit-narrowed"
"""Response header announcing that a value the caller proposed did not survive.

Emitted **only when something was narrowed**, which is the same discipline
:meth:`~sentrykit.envelope.AuthzEnvelope.as_dict` applies to the ``narrowed`` field: the
exceptional outcome is the one worth a line, and two headers on every ordinary response is a
cost paid by every caller to say "nothing happened". See ADR-029.
"""

NARROWED_ARGUMENTS_HEADER: Final = "x-sentrykit-narrowed-arguments"
"""Response header naming the narrowed arguments, comma-separated, first-seen order."""

_HEADER_SAFE: Final = re.compile(r"\A[A-Za-z0-9_.-]+\Z")
"""What may go in a header value without encoding.

Python parameter names are identifiers, and an identifier may contain non-ASCII characters —
``def search(región: str)`` is legal. An HTTP field value is visible ASCII, so a name outside
this set cannot be spelled here at all.
"""


def narrowing_headers(narrowed: bool, arguments: Sequence[str]) -> dict[str, str]:
    """Build the response headers that report narrowing, for any framework.

    Lives here rather than in each adapter so the two web providers cannot disagree about the
    header names or about when to emit them — the kind of drift that makes a documented
    contract a per-framework surprise.

    Deliberately excludes :attr:`~sentrykit.envelope.AuthzEnvelope.guidance`. It is a
    sentence of prose, it can exceed 300 characters, and one of its two forms contains an em
    dash, which is not spellable in an HTTP field value without encoding. A header is for a
    fact a machine acts on; the prose belongs in the body or in
    :func:`~sentrykit.envelope.last_envelope`. ADR-029 records that decision and its cost.

    Args:
        narrowed: Whether anything was narrowed while serving this response.
        arguments: The narrowed argument names.

    Returns:
        The headers to add, empty when nothing was narrowed. The argument header is omitted
        — while :data:`NARROWED_HEADER` is still emitted — if any name cannot be spelled in a
        field value, so the caller is told *that* narrowing happened even when it cannot be
        told *which*, and is never handed a list that silently dropped an entry.
    """
    if not narrowed:
        return {}
    headers = {NARROWED_HEADER: "true"}
    if arguments and all(_HEADER_SAFE.match(name) for name in arguments):
        headers[NARROWED_ARGUMENTS_HEADER] = ", ".join(arguments)
    return headers


STATUS_BY_ERROR: Final[Mapping[type[BaseException], int]] = {
    # Authorization refusals. A missing principal is a 403 and not a 401 on purpose: sentrykit
    # is not the authenticator and has no ``WWW-Authenticate`` challenge to offer, so claiming
    # otherwise would send callers to a scheme it knows nothing about.
    AuthzDenied: 403,
    NoContext: 403,
    # A supplied value spelled one of Cedar's reserved escape keys. The request was never
    # decided, so this is a refusal rather than a 400: telling the caller which spelling was
    # rejected would be telling them what to try next.
    ReservedKey: 403,
    # The caller proposed something policy will not accept. Their request, their fix.
    ArgumentRejected: 400,
    NoValidArguments: 400,
    DefaultUnavailable: 400,
    # Well-formed request, arguments that do not satisfy the callable's model.
    ValidationFailed: 422,
    # Ours, not theirs.
    AuditUnavailable: 500,
    ConfigurationError: 500,
    SentrykitError: 500,
}
"""Exception → HTTP status. Looked up along the MRO, so a subclass inherits its base's status."""

DEFAULT_STATUS: Final = 500
"""Status for a sentrykit error that predates its own entry in :data:`STATUS_BY_ERROR`."""

STATUS_PHRASES: Final[Mapping[int, str]] = {
    400: "Bad Request",
    403: "Forbidden",
    422: "Unprocessable Entity",
    500: "Internal Server Error",
}
"""Generic reason phrases, used as the whole body when verbosity is ``off``."""


def status_for(error: Exception) -> int:
    """Map a sentrykit error to its HTTP status.

    Walks ``type(error).__mro__`` so a host that subclasses one of the shipped errors gets its
    base's status rather than a surprise 500.

    Args:
        error: The raised exception.

    Returns:
        The status code, defaulting to :data:`DEFAULT_STATUS`.
    """
    for klass in type(error).__mro__:
        status = STATUS_BY_ERROR.get(klass)
        if status is not None:
            return status
    return DEFAULT_STATUS


def action_of(error: Exception) -> str | None:
    """Return the action an error refers to, when it names one.

    :class:`~sentrykit.errors.AuthzDenied` and :class:`~sentrykit.errors.NoContext` both carry
    the action; the argument errors do not. The action doubles as the key for a per-action
    verbosity override, so resolving it here means an action configured ``verbosity="debug"``
    gets a debug-level refusal body too.

    Args:
        error: The raised exception.

    Returns:
        The action uid, or ``None``.
    """
    action = getattr(error, "action", None)
    return action if isinstance(action, str) else None


def reason_for(error: Exception) -> str:
    """One sentence explaining a refusal, safe to show at ``summary`` verbosity.

    Safe means: no argument values, no policy ids, no internal detail. Names of things the
    caller already knows — the action they invoked, the argument they passed — are fine, and a
    constraint's own ``reason`` is written to be shown to a caller.

    Args:
        error: The raised exception.

    Returns:
        A sentence-case explanation.
    """
    match error:
        case AuthzDenied():
            return f"The policy denied action {error.action}."
        case NoContext():
            return f"No principal in context for action {error.action}; the call was denied."
        case ReservedKey():
            return "The request contained a reserved key and was denied."
        case ArgumentRejected():
            return f"Argument {error.name!r} was rejected: {error.reason}"
        case NoValidArguments():
            return "Every supplied argument was rejected by policy."
        case DefaultUnavailable():
            return f"Argument {error.name!r} is required and no policy default is configured."
        case ValidationFailed():
            return f"Argument validation failed with {len(error.errors)} error(s)."
        case _:
            # Configuration and audit failures are operator problems. The caller gets a
            # refusal, the operator gets the exception in the logs.
            return "The authorization decision could not be completed."


def error_envelope(error: Exception, *, verbosity: Verbosity) -> dict[str, object] | None:
    """Build the ``_authz`` body for a refusal, trimmed to ``verbosity``.

    Built from the exception alone — see this module's docstring for why ambient state is not
    available on every path. The field names match :class:`~sentrykit.envelope.AuthzEnvelope`
    so a caller reads one vocabulary whether the call was allowed or refused, and the trimming
    rules match it too:

    ``off``
        No envelope at all.
    ``summary``
        The decision, the action and resource where the error names them, the reason, and the
        *names* and reasons of rejected arguments. No values.
    ``verbose``
        Adds the offending values, the allowed set a caller needs in order to retry, and the
        raw input pydantic rejected.
    ``debug``
        Adds the determining policies and the engine errors behind a refusal.

    Args:
        error: The raised exception.
        verbosity: How much to include.

    Returns:
        The envelope body, or ``None`` when ``verbosity`` is ``off``.
    """
    if verbosity == "off":
        return None

    with_values = verbosity in ("verbose", "debug")
    with_trace = verbosity == "debug"

    envelope: dict[str, object] = {"decision": "deny", "reason": reason_for(error)}

    match error:
        case AuthzDenied():
            envelope["action"] = error.action
            if error.resource is not None:
                envelope["resource"] = error.resource
            if with_trace:
                envelope["determining_policies"] = list(error.determining_policies)
                if error.engine_errors:
                    envelope["trace"] = {"engine_errors": list(error.engine_errors)}
        case NoContext():
            envelope["action"] = error.action
        case ArgumentRejected():
            rejection: dict[str, object] = {"name": error.name, "reason": error.reason}
            if error.policy is not None:
                rejection["policy"] = error.policy
            envelope["rejected"] = [rejection]
        case NoValidArguments():
            # ``rejected`` is already the value-free ``as_detail()`` rendering, so it is safe
            # at ``summary``. ``allowed`` describes what this principal *may* pass, which is
            # the caller's own entitlement but still a shape worth withholding by default.
            envelope["rejected"] = [dict(item) for item in error.rejected]
            if with_values:
                envelope["allowed"] = dict(error.allowed)
        case DefaultUnavailable():
            envelope["rejected"] = [
                {"name": error.name, "reason": "No policy default is configured."}
            ]
        case ValidationFailed():
            envelope["errors"] = [_validation_error(item, with_values) for item in error.errors]
        case _:
            pass

    return envelope


def _validation_error(item: Mapping[str, object], with_values: bool) -> dict[str, object]:
    """Render one pydantic field error, dropping the rejected input below ``verbose``.

    Pydantic's ``input`` key holds the caller's own value. Echoing it back is harmless in
    development and is exactly the kind of thing that ends up in a shared log at 3am, so it
    follows the same rule as every other value in the envelope.

    Args:
        item: One entry from :attr:`~sentrykit.errors.ValidationFailed.errors`.
        with_values: Whether ``verbosity`` is ``verbose`` or above.

    Returns:
        The field error, with ``input`` present only when values are allowed.
    """
    rendered = {key: value for key, value in item.items() if key != "input" and key != "url"}
    if with_values and "input" in item:
        rendered["input"] = item["input"]
    return rendered


def error_payload(error: Exception, *, settings: Settings | None = None) -> dict[str, object]:
    """Build the whole JSON body for a refusal.

    Shaped so it reads naturally to both audiences: ``detail`` is what FastAPI and Flask
    callers already expect to find on an error, ``error`` is the machine-readable class name a
    client can branch on, and ``_authz`` is the same envelope the success path attaches to a
    mapping result.

    At ``verbosity="off"`` the body collapses to a generic reason phrase — no action names, no
    reasons, no envelope — because ``off`` means the caller is told nothing beyond the status.

    Args:
        error: The raised exception.
        settings: Effective settings. Defaults to the process settings resolved for the
            action the error names, so a per-action ``verbosity`` override reaches the refusal
            body as well as the success envelope.

    Returns:
        A JSON-ready mapping.
    """
    effective = settings or settings_for(action_of(error))
    status = status_for(error)
    if effective.verbosity == "off":
        return {"detail": STATUS_PHRASES.get(status, "Error")}
    body: dict[str, object] = {
        "detail": reason_for(error),
        "error": type(error).__name__,
    }
    envelope = error_envelope(error, verbosity=effective.verbosity)
    if envelope is not None:
        body["_authz"] = envelope
    return body


class BaseContextProvider(Generic[RequestT]):
    """Everything a context provider does that is not framework-specific.

    A subclass supplies four small things — :meth:`narrow`, :meth:`read_header`,
    :meth:`render_error`, and a :attr:`name` — and inherits identity resolution, environment
    construction, the establish/release lifecycle, and the shared refusal rendering.

    ### Omitting identify is logged, once, at construction

    A provider built without ``identify`` resolves identity with its own fallback, and every
    shipped fallback ends at something the request supplies — :attr:`principal_header` here,
    an ``_meta`` key or a ``deps`` attribute in the agent providers. So whoever can set that
    chooses who they are. That is the right wiring for an example app and for a service whose
    gateway has already authenticated the caller, and the wrong one everywhere else — a
    distinction only the deploying engineer can draw, and one they cannot draw from a default
    that says nothing. So construction emits a ``WARNING`` on the ``sentrykit.integrations``
    logger naming the provider class and the key it will read. It fires once per provider, not
    once per request, and not at all when ``identify`` is given.

    Args:
        identify: The app's auth → identity callback. Given the framework request, it returns
            a principal id, an :class:`~sentrykit.cedar.EntityRef`, a ready-made
            :class:`~sentrykit.context.Principal`, or ``None`` for an unauthenticated caller.
            Defaults to reading :attr:`principal_header`, which is enough for an example app
            and not enough for anything else, and is warned about when it is what you get.
        grants: Where a principal id is materialized. Defaults to the installed governor's
            grant store, resolved lazily at request time so ``install()`` and the provider can
            be wired in either order.
        environment: Extra Cedar request context per request, merged over ``channel``,
            ``request_id`` and the principal type. Policies read these as ``context.*``.
        principal_header: Header the default :attr:`identify` reads.
        request_id_header: Header an incoming correlation id is taken from.
        channel: The ``channel`` established for every request. ``http`` for a web provider;
            the agent providers pass ``agent``.
    """

    __slots__ = (
        "_channel",
        "_environment",
        "_grants",
        "_identify",
        "_principal_header",
        "_request_id_header",
    )

    def __init__(
        self,
        *,
        identify: Identify[RequestT] | None = None,
        grants: GrantStore | None = None,
        environment: EnvironmentFactory[RequestT] | None = None,
        principal_header: str = DEFAULT_PRINCIPAL_HEADER,
        request_id_header: str = DEFAULT_REQUEST_ID_HEADER,
        channel: Channel = "http",
    ) -> None:
        self._identify = identify
        self._grants = grants
        self._environment = environment
        self._principal_header = principal_header
        self._request_id_header = request_id_header
        self._channel = channel
        if identify is None:
            # Once, here, rather than once per request: wiring is a one-off and serving is the
            # hot path, so a line per decision would bury this one in its own volume. Both
            # names are interpolated into the sentence as well as carried in ``extra``,
            # because a library configures no handlers -- so what a developer actually sees
            # is ``logging``'s last-resort stderr line, which renders the message alone.
            _LOGGER.warning(
                "%s was built without identify=, so its own fallback decides who the caller "
                "is, and that fallback ends at the request-supplied %r: whoever can set that "
                "is authorized as the principal they name, with that principal's roles and "
                "grants. Pass identify= to resolve identity from the application's own "
                "authentication",
                type(self).__name__,
                principal_header,
                extra={"provider": type(self).__name__, "principal_header": principal_header},
            )

    @property
    def name(self) -> str:
        """Short name for this provider, e.g. ``fastapi``.

        Returns:
            The provider's DSN scheme.

        Raises:
            NotImplementedError: Always; every subclass names itself.
        """
        raise NotImplementedError

    @property
    def channel(self) -> Channel:
        """The channel this provider establishes — ``http`` for a web boundary."""
        return self._channel

    @property
    def principal_header(self) -> str:
        """Header the default :attr:`identify` reads a principal id from."""
        return self._principal_header

    @property
    def grants(self) -> GrantStore | None:
        """The grant store principals are materialized from.

        Falls back to the installed governor's store when none was passed, so
        ``install(grant_store=..., context_provider=...)`` needs no second wiring step and the
        two can be configured in either order.

        Returns:
            The store, or ``None`` when neither the provider nor the governor has one — in
            which case only an ``identify`` returning a whole
            :class:`~sentrykit.context.Principal` can produce one.
        """
        if self._grants is not None:
            return self._grants
        from sentrykit.engine import current_governor

        governor = current_governor()
        return governor.grants if governor is not None else None

    # --- framework seams -----------------------------------------------------------------

    def narrow(self, request: object) -> RequestT:
        """Check that ``request`` is this framework's request type, and return it as such.

        The one place the boundary between "some object arrived" and "a Starlette request
        arrived" is crossed. It is a method rather than a cast so a provider wired to the
        wrong framework fails with a configuration error naming both, instead of an
        ``AttributeError`` three frames deeper.

        Args:
            request: The object the framework hook handed over.

        Returns:
            The same object, typed.

        Raises:
            NotImplementedError: Always; every subclass narrows to its own request type.
        """
        raise NotImplementedError

    def read_header(self, request: RequestT, name: str) -> str | None:
        """Read one request header, case-insensitively.

        Args:
            request: The framework request.
            name: The header name.

        Returns:
            The value, or ``None`` when the header is absent.

        Raises:
            NotImplementedError: Always; header access is framework-specific.
        """
        raise NotImplementedError

    def render_error(self, error: Exception) -> object:
        """Render a sentrykit refusal as this framework's response.

        Args:
            error: A :class:`~sentrykit.errors.SentrykitError`.

        Returns:
            The framework-native response, carrying the ``_authz`` envelope at whatever the
            effective verbosity allows.

        Raises:
            NotImplementedError: Always; building a response is framework-specific.
        """
        raise NotImplementedError

    # --- shared behaviour ----------------------------------------------------------------

    def error_response(self, error: Exception) -> tuple[int, dict[str, object]]:
        """Resolve the status and JSON body for a refusal.

        The whole of :meth:`render_error` that is not framework-specific. Both shipped
        providers call this and then wrap the result, which is what makes a FastAPI 403 and a
        Flask 403 byte-identical below the framework's own serialization.

        Args:
            error: The raised exception.

        Returns:
            ``(status, body)``.
        """
        return status_for(error), error_payload(error)

    def identity_of(self, request: RequestT) -> Identity | None:
        """Run the app's auth callback, or fall back to the principal header.

        Args:
            request: The framework request.

        Returns:
            The identity, or ``None`` for an unauthenticated caller.
        """
        if self._identify is not None:
            return self._identify(request)
        return self.read_header(request, self._principal_header)

    def resolve_principal(self, request: RequestT) -> Principal | None:
        """Turn a request into a materialized principal.

        The identity comes from the app; the *authority* comes from the grant store. Resolving
        through :meth:`~sentrykit.stores.base.GrantStore.get_principal` is what makes roles,
        group edges, per-argument constraints and expiries part of the decision without the
        web layer knowing any of them exist.

        Args:
            request: The framework request.

        Returns:
            The principal, or ``None`` when the caller is unauthenticated or the store has
            never heard of them. Both are ``None`` on purpose: an unknown id is not an error
            the boundary should raise, it is a call that fails closed a few frames later with
            a refusal the caller can be shown.
        """
        identity = self.identity_of(request)
        if identity is None:
            return None
        if isinstance(identity, Principal):
            return identity
        store = self.grants
        if store is None:
            raise ConfigurationError(
                f"the {self.name} context provider resolved the identity {identity!r} but no "
                "grant store is configured; pass grants= to the provider, grant_store= to "
                "install(), or have identify= return a Principal"
            )
        principal = store.get_principal(identity)
        if principal is None:
            _LOGGER.info(
                "No principal in the grant store for %r; the request continues unauthenticated",
                identity if isinstance(identity, str) else str(identity),
            )
        return principal

    def environment_for(self, request: RequestT) -> dict[str, object]:
        """Build the Cedar request context for one request.

        ``channel`` and ``request_id`` are always present — the first so a policy can say "not
        over HTTP", the second so the decision, the operational logs and the audit record share
        one key. Anything the app's ``environment`` factory returns is merged on top, including
        over those two, because an app that has a better request id than we do should win.

        Args:
            request: The framework request.

        Returns:
            The environment to establish.
        """
        environment: dict[str, object] = {
            "channel": self._channel,
            "request_id": self.request_id(request),
        }
        if self._environment is not None:
            environment.update(self._environment(request))
        return environment

    def request_id(self, request: RequestT) -> str:
        """Return the correlation id for one request.

        Args:
            request: The framework request.

        Returns:
            The caller's :attr:`request_id_header` when they supplied one, otherwise a fresh
            UUID4. Trusting the caller's id is deliberate — it is what makes a trace span a
            gateway and a service — and it is never used as anything but a label.
        """
        supplied = self.read_header(request, self._request_id_header)
        return supplied.strip() if supplied and supplied.strip() else str(uuid.uuid4())

    def establish(self, request: object) -> ContextScope | None:
        """Establish ambient context for one request, at the boundary.

        Args:
            request: The framework's request object.

        Returns:
            A :class:`~sentrykit.context.ContextScope` to hand to :meth:`release` at teardown,
            or ``None`` when the caller is unauthenticated. ``None`` is not a failure: the
            context has still been cleared, and every protected call inside the request will
            fail closed with :class:`~sentrykit.errors.NoContext`.

        Raises:
            ConfigurationError: If the request is not this framework's, or an identity
                resolved with no grant store to materialize it from.
        """
        # Installed before anything protected can run, and unconditionally -- including for an
        # unauthenticated caller, so the shape is the same on both paths and a boundary never
        # has to ask whether a recorder exists. It is the only channel that survives a
        # decision made inside a copied context, which is every sync framework route.
        record_decisions()
        narrowed = self.narrow(request)
        principal = self.resolve_principal(narrowed)
        if principal is None:
            # Not merely "establish nothing": actively neutralize whatever a previous request
            # on this thread or task may have left behind. See the module docstring.
            clear_context()
            return None
        return establish(principal, **self.environment_for(narrowed))

    def narrowing(self) -> tuple[bool, tuple[str, ...]]:
        """What the boundary should report about narrowing, for this request.

        Reads the :class:`~sentrykit.envelope.EnvelopeRecorder`
        :meth:`establish` installed, so it answers even when the decision was made in a sync
        route's context copy -- where :func:`~sentrykit.envelope.last_envelope` returns
        ``None``. The union across every decision in the request is what a response-level
        report needs: one route may make several protected calls.

        Returns:
            Whether anything was narrowed, and the argument names, in first-seen order. Both
            empty when nothing was narrowed, when verbosity is ``off``, or when no recorder
            is installed.
        """
        recorder = current_recorder()
        if recorder is None:
            return False, ()
        return recorder.narrowed, recorder.narrowed_arguments

    def release(self, scope: ContextScope | None) -> None:
        """Undo :meth:`establish`, at teardown. Always safe to call.

        Total by design: it resets the scope when there is one, clears the context outright
        when there is not, and drops the last envelope either way. A pooled worker thread that
        served principal *A* must start the next request holding nothing of *A* — not the
        principal, not the environment, and not the envelope of *A*'s last decision.

        Args:
            scope: Whatever :meth:`establish` returned, including ``None``.
        """
        if scope is not None:
            scope.reset()
        else:
            clear_context()
        set_last_envelope(None)
        recorder = current_recorder()
        if recorder is not None:
            recorder.close()
