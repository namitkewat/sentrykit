"""The Governor — the decision pipeline every protected call runs through.

One pass, in a fixed order, described in architecture §2:

```
gate  ->  filter args  ->  inject defaults  ->  validate  ->  invoke  ->  envelope
```

The order is not arbitrary. The coarse Cedar gate runs first because there is no point
reasoning about arguments for a call that is not permitted at all. Filtering precedes
defaults so that a dropped argument can be *replaced* by the principal's default rather than
leaving a hole. Validation runs last, on the final argument set, so the callable never sees
a value that policy did not sanction — and so a validation failure is genuinely about types,
not about authorization.

The split between :meth:`Governor.plan` and :meth:`Governor.invoke` exists so the decision
can be made without performing the side effect. Agent-side ``list_tools`` filtering plans a
call it never invokes, to decide whether to show the tool to a model at all.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Final, NoReturn, TypeVar, cast, get_type_hints
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, ValidationError, create_model

from sentrykit.audit import AuditOutcome, AuditTrail, build_facts
from sentrykit.cedar import CedarDecision, CedarRequest, Entity, EntityRef, PolicyEngine
from sentrykit.config import Settings, apply_overrides, get_settings
from sentrykit.constraints import ConstraintSet, RejectedArgument
from sentrykit.context import Invocation, Principal, current_environment
from sentrykit.envelope import AuthzEnvelope, attach_envelope, build_envelope, set_last_envelope
from sentrykit.errors import (
    ArgumentRejected,
    AuditUnavailable,
    AuthzDenied,
    ConfigurationError,
    DefaultUnavailable,
    NoValidArguments,
    SentrykitError,
    ValidationFailed,
)
from sentrykit.masking import Masker, MaskStrategyName, sensitive_fields
from sentrykit.registry import (
    Configured,
    build_audit_sink,
    build_context_provider,
    build_grant_store,
    build_policy_source,
)
from sentrykit.stores.base import (
    AuditSink,
    ContextProvider,
    GrantStore,
    PolicyBundle,
    PolicySource,
)

__all__ = [
    "ArgumentSpec",
    "Governor",
    "Plan",
    "current_governor",
    "get_governor",
    "install",
    "set_governor",
    "use_governor",
]

T = TypeVar("T")
_B = TypeVar("_B")

_LOGGER: Final = logging.getLogger("sentrykit.engine")

DEFAULT_RESOURCE_TYPE: str = "Resource"
"""Entity type used for the synthetic resource when a protected callable declares none."""

_GOVERNOR: Governor | None = None
"""The process-default governor. A plain global, not a ``ContextVar``: wiring is a
process-lifetime concern, and :func:`use_governor` covers the scoped case."""


_REFUSAL_OUTCOMES: Final[dict[type[BaseException], AuditOutcome]] = {
    AuthzDenied: "denied",
    ArgumentRejected: "arguments-rejected",
    NoValidArguments: "no-valid-arguments",
    DefaultUnavailable: "default-unavailable",
    ValidationFailed: "validation-failed",
}
"""How each typed refusal is classified in the audit trail.

Deliberately finer-grained than allow/deny: "Cedar permitted the call and then every argument
the caller proposed was refused" is a different event to an auditor than "no policy permits
this at all", even though the caller experiences both as a denial.
"""


def _qualified_name(fn: Callable[..., object]) -> str:
    """Render ``<module>.<qualname>`` for a callable, tolerating exotic ones.

    Args:
        fn: Any callable, including one that carries no ``__qualname__`` (a
            ``functools.partial``, a callable instance).

    Returns:
        The qualified name used as the derived action id and in diagnostics.
    """
    module = getattr(fn, "__module__", None) or "<unknown>"
    qualname = getattr(fn, "__qualname__", None) or getattr(fn, "__name__", None) or repr(fn)
    return f"{module}.{qualname}"


@dataclass(frozen=True, slots=True)
class ArgumentSpec:
    """Everything the engine needs to know about a protected callable's arguments.

    Derived once per callable and cached on the decorator's wrapper, because building a
    pydantic model from a signature is far more expensive than the authorization decision
    it supports.

    Attributes:
        name: Qualified name, used as the derived action id and in diagnostics.
        signature: The callable's signature, used to bind proposed positional arguments to
            parameter names.
        parameters: Every parameter name the callable accepts, in declaration order.
        positional_only: The subset that must be passed positionally.
        required: Parameters with no Python-level default, which the call cannot omit.
        model: A pydantic model over the parameters, for validating the final argument set.
        is_async: Whether the callable is a coroutine function.
        accepts_var_keyword: Whether the callable declares ``**kwargs``, in which case a
            policy default for an unlisted name is still deliverable.
    """

    name: str
    signature: inspect.Signature
    parameters: tuple[str, ...]
    positional_only: tuple[str, ...]
    required: frozenset[str]
    model: type[BaseModel]
    is_async: bool
    accepts_var_keyword: bool

    @classmethod
    def from_callable(cls, fn: Callable[..., object]) -> ArgumentSpec:
        """Derive a spec by introspecting ``fn``.

        Unannotated parameters are typed as ``object`` so that an untyped callable is still
        protectable — sentrykit's job is authorization, not enforcing that its users annotate
        their code. ``*args`` and ``**kwargs`` are not modelled as fields.

        Args:
            fn: The callable being protected.

        Returns:
            The derived spec.

        Raises:
            ConfigurationError: If the signature cannot be introspected or its annotations
                cannot be resolved into a model.
        """
        name = _qualified_name(fn)
        try:
            signature = inspect.signature(fn)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"Cannot introspect the signature of {name}: {exc}") from exc
        try:
            hints = get_type_hints(fn, include_extras=True)
        except (NameError, TypeError, AttributeError) as exc:
            # An unresolvable forward reference is a wiring mistake, not a runtime condition:
            # surface it at decoration time rather than on the first protected call.
            raise ConfigurationError(f"Cannot resolve the annotations of {name}: {exc}") from exc

        parameters: list[str] = []
        positional_only: list[str] = []
        required: set[str] = set()
        # ``Any`` because ``create_model`` types its field definitions that way; the values
        # here are always ``(annotation, default_or_Ellipsis)`` pairs.
        fields: dict[str, Any] = {}
        accepts_var_keyword = False

        for parameter_name, parameter in signature.parameters.items():
            if parameter.kind is inspect.Parameter.VAR_KEYWORD:
                accepts_var_keyword = True
                continue
            if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
                continue
            parameters.append(parameter_name)
            if parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
                positional_only.append(parameter_name)
            annotation = hints.get(parameter_name, object)
            if parameter.default is inspect.Parameter.empty:
                required.add(parameter_name)
                fields[parameter_name] = (annotation, ...)
            else:
                fields[parameter_name] = (annotation, parameter.default)

        try:
            model = create_model(
                f"{getattr(fn, '__name__', 'Protected')}Arguments",
                # ``extra="allow"`` rather than ``"forbid"``: the engine has already narrowed
                # the mapping to this callable's own parameters, and forbidding extras would
                # turn a policy default for a ``**kwargs`` callable into a hard failure.
                __config__=ConfigDict(arbitrary_types_allowed=True, extra="allow"),
                **fields,
            )
        except Exception as exc:  # re-raised with context below, never swallowed
            raise ConfigurationError(f"Cannot build an argument model for {name}: {exc}") from exc

        return cls(
            name=name,
            signature=signature,
            parameters=tuple(parameters),
            positional_only=tuple(positional_only),
            required=frozenset(required),
            model=model,
            is_async=inspect.iscoroutinefunction(fn),
            accepts_var_keyword=accepts_var_keyword,
        )

    def bind(self, args: Sequence[object], kwargs: Mapping[str, object]) -> dict[str, object]:
        """Map a call's positional and keyword arguments onto parameter names.

        Uses ``bind_partial``, so a call that omits arguments the policy will default is not
        an error here.

        Args:
            args: Positional arguments as passed.
            kwargs: Keyword arguments as passed.

        Returns:
            Parameter name to proposed value.

        Raises:
            ConfigurationError: If the arguments cannot be bound to the signature at all.
        """
        try:
            bound = self.signature.bind_partial(*args, **kwargs)
        except TypeError as exc:
            raise ConfigurationError(f"Cannot bind arguments for {self.name}: {exc}") from exc

        proposed: dict[str, object] = {}
        for parameter_name, value in bound.arguments.items():
            kind = self.signature.parameters[parameter_name].kind
            if kind is inspect.Parameter.VAR_KEYWORD and isinstance(value, Mapping):
                # ``bind_partial`` nests **kwargs under the parameter's own name. Flatten it,
                # so policy sees the names the caller actually used and :meth:`split` can
                # reconstruct the call.
                proposed.update(value)
                continue
            proposed[parameter_name] = value
        return proposed

    def split(self, arguments: Mapping[str, object]) -> tuple[list[object], dict[str, object]]:
        """Split a final argument mapping back into positional and keyword form.

        Necessary because positional-only parameters cannot be passed by name; calling
        ``fn(**arguments)`` would fail on them.

        Args:
            arguments: The processed arguments.

        Returns:
            Positional arguments in declaration order, and the keyword remainder.
        """
        positional: list[object] = []
        keyword: dict[str, object] = {}
        # Values bound to ``*args`` force every preceding parameter to be passed
        # positionally too, otherwise Python cannot reach the variadic slot.
        variadic: tuple[object, ...] = ()
        for parameter_name, parameter in self.signature.parameters.items():
            if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
                value = arguments.get(parameter_name, ())
                variadic = tuple(value) if isinstance(value, list | tuple) else (value,)
                break
        force_positional = bool(variadic)

        # Positional slots the caller omitted are held back until a later slot turns out to
        # be present; only then must their Python default be emitted to keep the order.
        pending: list[object] = []
        for parameter_name, parameter in self.signature.parameters.items():
            if parameter.kind is inspect.Parameter.VAR_KEYWORD:
                continue
            if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
                positional.extend(variadic)
                pending.clear()
                continue
            takes_slot = parameter.kind is inspect.Parameter.POSITIONAL_ONLY or (
                force_positional and parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
            )
            if not takes_slot:
                if parameter_name in arguments:
                    keyword[parameter_name] = arguments[parameter_name]
                continue
            if parameter_name in arguments:
                positional.extend(pending)
                pending.clear()
                positional.append(arguments[parameter_name])
            elif parameter.default is not inspect.Parameter.empty:
                pending.append(parameter.default)

        # Names the signature does not declare reach here only for a ``**kwargs`` callable.
        known = set(self.signature.parameters)
        for parameter_name, value in arguments.items():
            if parameter_name not in known:
                keyword[parameter_name] = value
        return positional, keyword

    def validate(self, arguments: Mapping[str, object]) -> dict[str, object]:
        """Validate the final argument set against the callable's model.

        Args:
            arguments: The processed arguments.

        Returns:
            The validated arguments, coerced by pydantic where the annotations call for it.

        Raises:
            ValidationFailed: Carrying pydantic's structured field errors.
        """
        try:
            validated = self.model(**arguments)
        except ValidationError as exc:
            raise ValidationFailed(
                [dict(error) for error in exc.errors(include_url=False)]
            ) from exc

        # Only the keys that were actually passed come back. Letting the model's own
        # parameter defaults through would make the envelope report values Python would have
        # supplied anyway, blurring the line between "policy defaulted this" and "the
        # signature did".
        fields = type(validated).model_fields
        return {
            key: (getattr(validated, key) if key in fields else value)
            for key, value in arguments.items()
        }


@dataclass(frozen=True, slots=True)
class Plan:
    """A decided-but-not-yet-performed invocation.

    Holding the decision separately from the side effect is what lets the same pipeline
    answer "may this run?" for a tool manifest and "run this" for a real call.

    Attributes:
        invocation: The normalized invocation the decision was made about.
        decision: What Cedar said.
        settings: The effective settings for this action.
        spec: The target callable's argument spec.
        processed: The final arguments, filtered, defaulted and validated.
        rejected: Arguments the policy refused.
        defaults_applied: Arguments filled in from the principal's defaults.
        obligations: Obligations the policy attached.
        trace: Debug detail, populated only at ``debug`` verbosity.
    """

    invocation: Invocation
    decision: CedarDecision
    settings: Settings
    spec: ArgumentSpec
    processed: dict[str, object] = field(default_factory=dict)
    rejected: tuple[RejectedArgument, ...] = ()
    defaults_applied: dict[str, object] = field(default_factory=dict)
    obligations: tuple[str, ...] = ()
    trace: dict[str, object] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        """Whether the call may proceed.

        True for a clean Cedar allow, and for an engine failure that ``fail_mode="open"``
        waved through. A clean policy deny never reaches here — :meth:`Governor.plan` raises
        instead of returning a refused plan.
        """
        if self.decision.allowed:
            return True
        return self.decision.failed and self.settings.fail_mode == "open"

    def envelope(self) -> AuthzEnvelope | None:
        """Build the caller-facing envelope for this plan, honoring its verbosity."""
        return build_envelope(
            decision="allow" if self.allowed else "deny",
            action=str(self.invocation.action),
            resource=str(self.invocation.resource),
            principal=str(self.invocation.principal.uid),
            processed=self.processed,
            rejected=self.rejected,
            defaults_applied=self.defaults_applied,
            obligations=self.obligations,
            determining_policies=self.decision.determining_policies,
            trace=self.trace or None,
            verbosity=self.settings.verbosity,
        )


class Governor:
    """Runs the authorization pipeline against one policy engine.

    Args:
        policy: The Cedar policy set and entity graph to decide against.
        settings: Base settings. Defaults to the process-wide configuration, resolved per
            action at decision time so a per-action override still applies.
        audit: Where decisions are recorded. ``None`` — the default — means no records are
            built at all, so a governor wired without a sink costs exactly what it did before
            the audit trail existed.
        bundle: The loaded policy bundle, when the governor was built from a
            :class:`~sentrykit.stores.base.PolicySource`. Supplies the per-policy annotation
            index obligations are read from, and the provenance the audit record carries.
            Without one, obligations stay empty and provenance is unavailable, which is
            exactly how a governor wired from raw policy text behaves.
        grants: The grant store principals were materialized from, when there is one. The
            decision path never consults it — a principal arrives already materialized, by
            way of :func:`~sentrykit.context.establish` — but the admin surface needs to
            reach the store it is governing, and holding the wiring in one object beats a
            second process-global.
    """

    __slots__ = ("_audit", "_bundle", "_grants", "_policy", "_provider", "_settings")

    def __init__(
        self,
        policy: PolicyEngine,
        settings: Settings | None = None,
        *,
        audit: AuditTrail | None = None,
        bundle: PolicyBundle | None = None,
        grants: GrantStore | None = None,
        context_provider: ContextProvider | None = None,
    ) -> None:
        self._policy = policy
        self._settings = settings
        self._audit = audit
        self._bundle = bundle
        self._grants = grants
        self._provider = context_provider

    @property
    def policy(self) -> PolicyEngine:
        """The policy engine this governor decides against."""
        return self._policy

    @property
    def audit(self) -> AuditTrail | None:
        """The audit trail this governor records to, if any."""
        return self._audit

    @property
    def bundle(self) -> PolicyBundle | None:
        """The policy bundle this governor's policies came from, if any."""
        return self._bundle

    @property
    def grants(self) -> GrantStore | None:
        """The grant store backing this governor's principals, if one was wired."""
        return self._grants

    @property
    def context_provider(self) -> ContextProvider | None:
        """The framework provider wired for this process, if one was.

        Held here for the same reason :attr:`grants` is: the decision path never touches
        it -- a principal reaches the governor already established -- but the boundary
        adapter has to find the wiring somewhere, and one object beats a second
        process-global. It is what lets ``SentrykitMiddleware(app)`` be spelled with no
        arguments once ``install(context_provider=...)`` has run.
        """
        return self._provider

    def plan(
        self,
        spec: ArgumentSpec,
        *,
        principal: Principal,
        action: EntityRef,
        resource: EntityRef | None = None,
        proposed: Mapping[str, object] | None = None,
        environment: Mapping[str, object] | None = None,
        invocation_id: str | None = None,
    ) -> Plan:
        """Decide an invocation without performing it.

        Runs the gate, the argument filter, default injection and validation, in that order.

        Args:
            spec: The target callable's argument spec.
            principal: Who is acting. Resolving the ambient principal — and refusing when
                there is none — happens in the decorator, before this point.
            action: What they propose to do.
            resource: What they propose to do it to. Defaults to
                ``Resource::"<action id>"`` so that a callable which declares no resource is
                still expressible in Cedar's three-part model.
            proposed: The arguments as supplied.
            environment: Request environment. Merged over the ambient environment, with
                ``now`` and ``channel`` filled in when absent.
            invocation_id: Correlation id. Generated when omitted; pass one to keep an audit
                trail deterministic in tests.

        Returns:
            The decided plan.

        Raises:
            AuthzDenied: If the gate denied, or if the engine failed under
                ``fail_mode="closed"``.
            ArgumentRejected: If an argument violated its constraint under
                ``arg_handling="strict"``.
            NoValidArguments: If the caller supplied arguments, every one was rejected, and
                defaults cannot complete the call.
            DefaultUnavailable: If a required argument has neither a supplied value nor a
                default.
            ValidationFailed: If the final argument set does not satisfy the callable's
                model.
        """
        settings = apply_overrides(self._settings or get_settings(), action.id)
        resource = resource or EntityRef(DEFAULT_RESOURCE_TYPE, action.id)
        invocation_id = invocation_id or uuid4().hex
        proposed_arguments = dict(proposed or {})
        env = merge_environment(current_environment(), environment, proposed=proposed_arguments)

        context = {
            "invocation_id": invocation_id,
            "action": str(action),
            "resource": str(resource),
            "principal": str(principal.uid),
        }

        # Built before the gate rather than alongside the returned plan, because a refusal has
        # to be as auditable as an allow and the record describes an *attempted* invocation
        # either way.
        invocation = Invocation(
            id=invocation_id,
            principal=principal,
            action=action,
            resource=resource,
            proposed=proposed_arguments,
            environment=env,
            callable_name=spec.name,
        )

        decision = self._policy.evaluate(
            CedarRequest(
                principal=principal.uid,
                action=action,
                resource=resource,
                context=env,
                # The principal snapshot is a per-request delta so a concurrent decision for
                # a different principal never sees it.
                entities=(Entity(principal.uid, principal.attributes, principal.all_parents()),),
                correlation_id=invocation_id,
            )
        )

        rejected: tuple[RejectedArgument, ...] = ()
        try:
            self._gate(decision, settings, action, resource, principal, context, env)

            obligations = self._obligations(decision, allowed=True)
            constraints = principal.constraints_for(action)
            kept, rejected = constraints.filter(proposed_arguments)
            if rejected:
                self._report_rejections(rejected, settings, context)

            if proposed_arguments and not kept:
                # Every argument the caller asked for was refused. Completing the call from
                # defaults would answer a question they did not ask, so refuse instead.
                _LOGGER.info(
                    "Every proposed argument was rejected",
                    extra={**context, "arguments": sorted(proposed_arguments)},
                )
                raise NoValidArguments(
                    allowed=constraints.describe(),
                    rejected=[item.as_detail() for item in rejected],
                )

            arguments, defaults_applied = constraints.inject_defaults(kept, spec.parameters)

            missing = self._missing_arguments(spec, constraints, arguments)
            if missing:
                _LOGGER.info(
                    "Required argument has no value and no default",
                    extra={**context, "arguments": list(missing)},
                )
                raise DefaultUnavailable(missing[0])

            processed = spec.validate(arguments)
        except SentrykitError as exc:
            self._audit_refusal(invocation, decision, spec, exc, rejected=rejected)
            raise

        trace: dict[str, object] = {}
        if settings.verbosity == "debug":
            trace = {
                **decision.as_trace(),
                "invocation_id": invocation_id,
                "channel": env.get("channel", "internal"),
                "settings": settings.model_dump(),
            }

        _LOGGER.debug(
            "Authorized invocation",
            extra={
                **context,
                "decision": decision.decision,
                "arguments": sorted(processed),
                "defaulted": sorted(defaults_applied),
                "rejected": [item.name for item in rejected],
            },
        )

        plan = Plan(
            invocation=invocation,
            decision=decision,
            settings=settings,
            spec=spec,
            processed=processed,
            rejected=rejected,
            defaults_applied=defaults_applied,
            obligations=obligations,
            trace=trace,
        )
        self._audit_decision(plan)
        return plan

    def _gate(
        self,
        decision: CedarDecision,
        settings: Settings,
        action: EntityRef,
        resource: EntityRef,
        principal: Principal,
        context: Mapping[str, str],
        environment: Mapping[str, object],
    ) -> None:
        """Apply the coarse Cedar gate, refusing unless the call may proceed.

        Separates the two ways a call fails to be authorized. An *engine failure* — a Cedar
        error, or ``no-decision`` — is a bug in the policy set and is logged at ``ERROR``;
        ``fail_mode`` decides whether it also refuses. A plain *policy denial* is normal
        operation, logged at ``INFO``, and refuses under either fail mode.

        Args:
            decision: What Cedar returned.
            settings: The effective settings for this action.
            action: The action being authorized.
            resource: The resource it was authorized against.
            principal: Who is acting.
            context: Pre-built log context.
            environment: The merged Cedar request context, for the debug trace.

        Raises:
            AuthzDenied: If the gate denied, or the engine failed under ``fail_mode="closed"``.
        """
        if decision.failed:
            _LOGGER.error(
                "Cedar evaluation failed",
                extra={
                    **context,
                    "decision": decision.decision,
                    "engine_errors": list(decision.errors),
                    "fail_mode": settings.fail_mode,
                },
            )
            if settings.fail_mode == "closed":
                self._refuse(
                    decision,
                    settings,
                    action,
                    resource,
                    principal,
                    environment,
                    invocation_id=context["invocation_id"],
                    reason="Authorization engine failed; refused under fail_mode=closed",
                    engine_errors=list(decision.errors),
                )
            # fail_mode="open": proceed, with the errors preserved in the debug trace.
            return

        if decision.allowed:
            return

        _LOGGER.info(
            "Authorization denied",
            extra={
                **context,
                "decision": decision.decision,
                "determining_policies": list(decision.determining_policies),
            },
        )
        self._refuse(
            decision,
            settings,
            action,
            resource,
            principal,
            environment,
            invocation_id=context["invocation_id"],
            reason=(
                "Denied by an explicit forbid policy"
                if decision.determining_policies
                else "No policy permits this action"
            ),
            engine_errors=None,
        )

    @staticmethod
    def _refuse(
        decision: CedarDecision,
        settings: Settings,
        action: EntityRef,
        resource: EntityRef,
        principal: Principal,
        environment: Mapping[str, object],
        *,
        invocation_id: str,
        reason: str,
        engine_errors: list[str] | None,
    ) -> NoReturn:
        """Record the deny envelope and raise.

        The envelope is recorded even though nothing is returned to the caller: a framework
        provider rendering the 403 reads it from :func:`~sentrykit.envelope.last_envelope`,
        so a denial is as reportable as an allow.

        Args:
            decision: What Cedar returned.
            settings: The effective settings for this action.
            action: The action that was refused.
            resource: The resource it was refused against.
            principal: Who was acting.
            environment: The merged Cedar request context, for the debug trace.
            invocation_id: Correlation id, so the deny trace joins the operational logs.
            reason: One-sentence explanation for the envelope.
            engine_errors: Cedar errors when this refusal came from an engine failure, and
                ``None`` when it is an ordinary policy denial.

        Raises:
            AuthzDenied: Always.
        """
        trace: dict[str, object] | None = None
        if settings.verbosity == "debug":
            trace = {
                **decision.as_trace(),
                "invocation_id": invocation_id,
                "channel": environment.get("channel", "internal"),
                "settings": settings.model_dump(),
            }
        set_last_envelope(
            build_envelope(
                decision="deny",
                action=str(action),
                resource=str(resource),
                principal=str(principal.uid),
                processed={},
                rejected=(),
                defaults_applied={},
                reason=reason,
                determining_policies=decision.determining_policies,
                trace=trace,
                verbosity=settings.verbosity,
            )
        )
        raise AuthzDenied(
            str(action),
            str(resource),
            list(decision.determining_policies),
            engine_errors=engine_errors,
        )

    @staticmethod
    def _report_rejections(
        rejected: tuple[RejectedArgument, ...],
        settings: Settings,
        context: Mapping[str, str],
    ) -> None:
        """Log, and under ``strict`` handling raise on, the arguments policy refused.

        Only names, rules and reasons are logged. The offending *value* is exactly the kind
        of caller-supplied data the logging standards keep out of the operational channel.

        Args:
            rejected: The rejections the constraint set produced. Never empty.
            settings: The effective settings for this action.
            context: Pre-built log context.

        Raises:
            ArgumentRejected: If ``arg_handling`` is ``strict``.
        """
        if settings.arg_handling == "strict":
            first = rejected[0]
            _LOGGER.info(
                "Argument rejected under strict handling",
                extra={**context, "argument": first.name, "rule": first.rule},
            )
            raise ArgumentRejected(first.name, first.reason, first.policy)
        for item in rejected:
            _LOGGER.warning(
                "Argument dropped by policy",
                extra={
                    **context,
                    "argument": item.name,
                    "rule": item.rule,
                    "reason": item.reason,
                    "policy": item.policy,
                },
            )

    @staticmethod
    def _missing_arguments(
        spec: ArgumentSpec,
        constraints: ConstraintSet,
        arguments: Mapping[str, object],
    ) -> tuple[str, ...]:
        """Name the arguments that still have no value once defaults have been injected.

        Two sources, because they mean different things: ``spec.required`` is what *Python*
        cannot call without, and ``ConstraintSet.missing_required`` is what *policy* insists
        on. Either one unsatisfied is a :class:`~sentrykit.errors.DefaultUnavailable`.

        Args:
            spec: The target callable's argument spec.
            constraints: The principal's constraints for this action.
            arguments: The completed argument mapping.

        Returns:
            The missing names, ordered by the callable's declaration order so the error
            names the first hole a reader would notice.
        """
        missing = {name for name in spec.required if name not in arguments}
        missing.update(constraints.missing_required(arguments))
        if not missing:
            return ()
        ordered = [name for name in spec.parameters if name in missing]
        ordered.extend(sorted(name for name in missing if name not in spec.parameters))
        return tuple(ordered)

    # --- audit ---------------------------------------------------------------------------
    #
    # The whole reach of the audit trail into the decision pipeline is these three methods
    # plus the two calls that reach them. They are no-ops unless a trail was wired, so a bare
    # ``Governor(policy_engine)`` takes exactly the path it would without auditing at all,
    # allocating nothing and touching no masking code.

    def _obligations(self, decision: CedarDecision, *, allowed: bool) -> tuple[str, ...]:
        """Read the obligations the determining policies attached to this decision.

        Obligations live in an ``@obligations`` annotation, which Cedar exposes only through
        the policy *text*. The bundle owns that index, so a governor wired from raw policy
        text — with no bundle — reports no obligations.

        Args:
            decision: What Cedar returned.
            allowed: Whether the call is proceeding, which selects the determining permit
                policies rather than the determining forbids.

        Returns:
            The obligations, or empty when no bundle is wired.
        """
        if self._bundle is None:
            return ()
        return self._bundle.obligations_for(decision.determining_policies, allowed=allowed)

    def _declared_sensitive(self, spec: ArgumentSpec) -> dict[str, MaskStrategyName | None]:
        """Read the ``Sensitive`` markers off the protected callable's signature.

        Computed only when a trail is wired: introspecting the argument model costs more than
        the decision does, and an unaudited governor has no use for the answer.
        """
        return sensitive_fields(spec.model)

    def _audit_decision(self, plan: Plan) -> None:
        """Record a decision that permitted the call.

        A sink failure propagates here. That is the point: under ``fail_mode="closed"`` an
        action whose authorization cannot be proven must not happen, so the
        :class:`~sentrykit.errors.AuditUnavailable` refuses the call before the side effect
        rather than after it.
        """
        trail = self._audit
        if trail is None or not trail.enabled:
            return
        trail.record(
            build_facts(
                invocation=plan.invocation,
                decision=plan.decision,
                outcome="allowed",
                allowed=True,
                processed=plan.processed,
                rejected=plan.rejected,
                defaults_applied=plan.defaults_applied,
                obligations=plan.obligations,
                declared_sensitive=self._declared_sensitive(plan.spec),
            )
        )

    def _audit_refusal(
        self,
        invocation: Invocation,
        decision: CedarDecision,
        spec: ArgumentSpec,
        error: SentrykitError,
        *,
        rejected: tuple[RejectedArgument, ...] = (),
    ) -> None:
        """Record a decision that refused the call.

        Unlike :meth:`_audit_decision`, a sink failure here is logged and swallowed. The call
        is already being refused, so raising
        :class:`~sentrykit.errors.AuditUnavailable` would replace a precise
        :class:`~sentrykit.errors.AuthzDenied` — the answer the caller actually needs — with
        an operational error. Failing closed is already the outcome; the only thing left to
        protect is the diagnosis.
        """
        trail = self._audit
        if trail is None or not trail.enabled:
            return
        outcome: AuditOutcome = _REFUSAL_OUTCOMES.get(type(error), "denied")
        try:
            trail.record(
                build_facts(
                    invocation=invocation,
                    decision=decision,
                    outcome=outcome,
                    allowed=False,
                    reason=str(error),
                    rejected=rejected,
                    obligations=self._obligations(decision, allowed=False),
                    declared_sensitive=self._declared_sensitive(spec),
                )
            )
        except AuditUnavailable:
            _LOGGER.error(
                "Audit sink rejected a refusal record; the refusal itself still stands",
                extra={
                    "invocation_id": invocation.id,
                    "action": str(invocation.action),
                    "outcome": outcome,
                },
            )

    def invoke(self, fn: Callable[..., T], plan: Plan) -> T:
        """Perform a planned call and attach its envelope.

        Args:
            fn: The protected callable.
            plan: The :class:`Plan` produced by :meth:`plan` for this call.

        Returns:
            Whatever ``fn`` returned, with the ``_authz`` envelope attached when the result
            is a mapping and ``envelope_on_success`` is set.
        """
        positional, keyword = plan.spec.split(plan.processed)
        result = fn(*positional, **keyword)
        return attach_envelope(result, self._success_envelope(plan))

    async def ainvoke(self, fn: Callable[..., Awaitable[T]], plan: Plan) -> T:
        """Await a planned call and attach its envelope.

        The decision itself is synchronous — Cedar evaluation is in-process and cheap — so
        this differs from :meth:`invoke` only in awaiting the callable. Hosts that need the
        decision off the event loop wrap it with
        :func:`~sentrykit.context.bind_context`.

        Args:
            fn: The protected coroutine function.
            plan: The :class:`Plan` produced by :meth:`plan` for this call.

        Returns:
            Whatever ``fn`` resolved to, with the envelope attached where applicable.
        """
        positional, keyword = plan.spec.split(plan.processed)
        result = await fn(*positional, **keyword)
        return attach_envelope(result, self._success_envelope(plan))

    @staticmethod
    def _success_envelope(plan: Plan) -> AuthzEnvelope | None:
        """Build and record the envelope for a call that ran.

        Recorded here rather than only inside
        :func:`~sentrykit.envelope.attach_envelope` so that a non-mapping return value —
        which cannot carry the envelope itself — still leaves it on the context for a
        framework provider to render.

        Args:
            plan: The :class:`Plan` that was invoked.

        Returns:
            The envelope, or ``None`` when ``envelope_on_success`` is off or verbosity is
            ``off``.
        """
        envelope = plan.envelope() if plan.settings.envelope_on_success else None
        set_last_envelope(envelope)
        return envelope


def install(
    policies: str | None = None,
    *,
    entities: Sequence[Entity] = (),
    schema: str | None = None,
    settings: Settings | None = None,
    policy_source: str | PolicySource | Sequence[str | PolicySource] | None = None,
    grant_store: str | GrantStore | Sequence[str | GrantStore] | None = None,
    audit_sink: str | AuditSink | Sequence[str | AuditSink] | None = None,
    context_provider: str | ContextProvider | None = None,
    masker: Masker | None = None,
) -> Governor:
    """Wire a governor and make it the process default.

    One call covers both ends of the range. Hand it a policy string and it wires an in-memory
    governor — the shape for tests and for a service whose policy fits in a literal.
    Hand it DSNs instead and the same call assembles the pluggable substrate: policy sources
    unioned, grant stores merged, audit sinks fanned out, each resolved through the registry
    so a third-party backend is reachable by name alone.

    Either way the result is one :class:`Governor`, because multiplicity is a composite that
    satisfies the same Protocol — the decision path never learns how many sources were
    configured.

    Args:
        policies: Cedar policy text. Mutually exclusive with ``policy_source``.
        entities: Extra stable entities — roles, teams, resources — merged on top of whatever
            the sources and the grant store contribute.
        schema: Optional Cedar schema text, for inline policies.
        settings: Base settings, defaulting to the process configuration.
        policy_source: One DSN (``"file://./policies"``), several, an already-built source,
            or a sequence mixing the two — ``["pack://", LinkedPolicySource(links)]`` unions
            the shipped pack with something the host constructed itself.
        grant_store: One DSN (``"memory://"``), several, or an already-built store. Its stable
            entities join the graph; its principals do not, since those are per-request.
        audit_sink: One DSN (``"jsonl://./audit.jsonl"``), several, or an already-built sink.
            Defaults to ``SENTRYKIT_AUDIT_SINK``. Nothing configured means no audit trail —
            a library must not begin writing files merely because it was imported.
        context_provider: One DSN (``"fastapi://"``) or an already-built provider, wired so a
            framework adapter can find it with no second configuration step. Exactly one, and
            never a sequence: a process serves one boundary, and there is no composite that
            could guess which framework an incoming request belongs to.
        masker: How sensitive values are masked before an audit write. Defaults to one built
            from the settings.

    Returns:
        The installed governor.

    Raises:
        ConfigurationError: If neither or both of ``policies``/``policy_source`` were given,
            if a DSN names an unknown backend, or if the policies, entities or schema fail to
            parse.
    """
    if (policies is None) == (policy_source is None):
        raise ConfigurationError(
            "install() needs exactly one of policies= (inline Cedar text) or "
            "policy_source= (a DSN or a built PolicySource)"
        )

    effective = settings or get_settings()
    source = _as_backend(policy_source, build_policy_source, PolicySource, "policy source")
    store = _as_backend(grant_store, build_grant_store, GrantStore, "grant store")

    if source is not None:
        bundle = source.load()
    else:
        # Inline policies get a bundle too, rather than a bare engine. It costs one extra
        # parse at wiring time and buys the annotation index, which is what makes obligations
        # work for a policy literal exactly as they do for a policy directory.
        bundle = PolicyBundle.from_text(policies or "", schema=schema, source="inline")

    graph: list[Entity] = list(bundle.entities)
    if store is not None:
        graph.extend(store.entities())
    graph.extend(entities)
    bundle = replace(bundle, entities=tuple(graph))

    sink = _as_backend(audit_sink, build_audit_sink, AuditSink, "audit sink")
    if sink is None and effective.audit_sink:
        sink = build_audit_sink(effective.audit_sink)
    trail = AuditTrail(
        sink,
        masker=masker or Masker.from_settings(effective),
        bundle=bundle,
        strict=effective.fail_mode == "closed",
    )

    provider = _as_backend(
        context_provider, build_context_provider, ContextProvider, "context provider"
    )
    governor = Governor(
        bundle.engine(),
        settings,
        audit=trail,
        bundle=bundle,
        grants=store,
        context_provider=provider,
    )
    set_governor(governor)
    _LOGGER.debug(
        "Installed the process-default governor",
        extra={
            "entities": len(bundle.entities),
            "policies": len(bundle.provenance),
            "policy_set_hash": bundle.bundle_hash,
            "audited": trail.enabled,
            "context_provider": provider.name if provider is not None else None,
        },
    )
    return governor


def _as_backend(
    configured: Configured | _B | None,
    build: Callable[[Configured | None], _B | None],
    protocol: type,
    label: str,
) -> _B | None:
    """Accept DSNs, already-built backends, or a mix of the two, and return one backend.

    Letting a caller pass an instance matters more than it looks: a test wants an
    :class:`~sentrykit.stores.memory.InMemoryAuditSink` it still holds a reference to, and a
    host with its own credentials wants to construct its backend itself. A DSN is the
    convenience, not the only door — and that has to hold *inside* a sequence too, or a
    union is closed to any backend that cannot be spelled as a DSN.

    Args:
        configured: A DSN, a built backend, a sequence mixing the two, or ``None``.
        build: The registry factory for this kind.
        protocol: The Protocol an instance must satisfy.
        label: Human name for the error message.

    Returns:
        The backend, or ``None`` when nothing was configured.

    Raises:
        ConfigurationError: If an instance was given that does not satisfy ``protocol``.
    """
    if configured is None:
        return None
    if isinstance(configured, str):
        return build(configured)
    if isinstance(configured, Sequence):
        return build(list(configured))
    if not isinstance(configured, protocol):
        raise ConfigurationError(
            f"the {label} passed to install() does not satisfy the {protocol.__name__} protocol"
        )
    # ``Configured`` widens to ``object`` so that one normalization path serves all four
    # extension points; the isinstance above is the check the cast stands on.
    return cast("_B", configured)


def set_governor(governor: Governor | None) -> None:
    """Install ``governor`` as the process default, or clear it with ``None``."""
    global _GOVERNOR
    _GOVERNOR = governor


def current_governor() -> Governor | None:
    """Return the process-default governor, or ``None`` if none is installed."""
    return _GOVERNOR


def get_governor() -> Governor:
    """Return the process-default governor.

    Returns:
        The installed governor.

    Raises:
        ConfigurationError: If none is installed. Protecting a callable without wiring a
            policy is a configuration mistake, and it fails loudly at call time rather than
            quietly allowing.
    """
    if _GOVERNOR is None:
        raise ConfigurationError(
            "No governor is installed; call sentrykit.install(...) or set_governor(...) "
            "before invoking a protected callable"
        )
    return _GOVERNOR


@contextmanager
def use_governor(governor: Governor) -> Iterator[Governor]:
    """Install ``governor`` for the duration of a block, then restore the previous one.

    Args:
        governor: The governor to use.

    Yields:
        The governor, for convenience.
    """
    previous = current_governor()
    set_governor(governor)
    try:
        yield governor
    finally:
        set_governor(previous)


def derive_action(fn: Callable[..., object]) -> EntityRef:
    """Derive an action id for a callable that declares none.

    Uses ``<module>.<qualname>``, which is stable across refactors that do not move the
    function and unique within a process — so a policy written against it keeps meaning what
    it meant.

    Args:
        fn: The protected callable.

    Returns:
        ``Action::"<module>.<qualname>"``.
    """
    return EntityRef("Action", _qualified_name(fn))


def merge_environment(
    ambient: Mapping[str, object],
    explicit: Mapping[str, object] | None,
    *,
    proposed: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build the Cedar request context for one decision.

    Layers the explicit environment over the ambient one, fills in ``now`` and ``channel``
    when neither supplied them, and exposes the proposed arguments under ``args`` so a Cedar
    ``forbid`` can inspect them directly. That last part is the defense in depth: the
    Python-side filter is the enforcement, and an argument-aware ``forbid`` is the backstop
    that catches a filter that was never configured.

    Args:
        ambient: The environment established at the boundary.
        explicit: Per-call overrides.
        proposed: The proposed arguments, exposed to policy under ``args``.

    Returns:
        The merged environment, ready for coercion into a Cedar context.
    """
    environment = dict(ambient)
    if explicit:
        environment.update(explicit)
    environment.setdefault("channel", "internal")
    environment.setdefault("now", datetime.now(UTC))
    # Always the *current* proposal: an ``args`` key left over from an enclosing scope would
    # let a policy decide about the wrong call.
    environment["args"] = dict(proposed or {})
    return environment
