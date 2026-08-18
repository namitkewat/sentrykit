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
can be made without performing the side effect. Phase 4's ``list_tools`` filtering plans a
call it never invokes, to decide whether to show the tool to a model at all.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Collection, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TypeVar

from pydantic import BaseModel

from sentrykit.cedar import CedarDecision, Entity, EntityRef, PolicyEngine
from sentrykit.config import Settings
from sentrykit.constraints import RejectedArgument
from sentrykit.context import Invocation, Principal
from sentrykit.envelope import AuthzEnvelope

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

DEFAULT_RESOURCE_TYPE: str = "Resource"
"""Entity type used for the synthetic resource when a protected callable declares none."""


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
        raise NotImplementedError

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
        raise NotImplementedError

    def split(self, arguments: Mapping[str, object]) -> tuple[list[object], dict[str, object]]:
        """Split a final argument mapping back into positional and keyword form.

        Necessary because positional-only parameters cannot be passed by name; calling
        ``fn(**arguments)`` would fail on them.

        Args:
            arguments: The processed arguments.

        Returns:
            Positional arguments in declaration order, and the keyword remainder.
        """
        raise NotImplementedError

    def validate(self, arguments: Mapping[str, object]) -> dict[str, object]:
        """Validate the final argument set against the callable's model.

        Args:
            arguments: The processed arguments.

        Returns:
            The validated arguments, coerced by pydantic where the annotations call for it.

        Raises:
            ValidationFailed: Carrying pydantic's structured field errors.
        """
        raise NotImplementedError


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
        """Whether the call may proceed."""
        raise NotImplementedError

    def envelope(self) -> AuthzEnvelope | None:
        """Build the caller-facing envelope for this plan, honoring its verbosity."""
        raise NotImplementedError


class Governor:
    """Runs the authorization pipeline against one policy engine.

    Args:
        policy: The Cedar policy set and entity graph to decide against.
        settings: Base settings. Defaults to the process-wide configuration, resolved per
            action at decision time so a per-action override still applies.
    """

    def __init__(self, policy: PolicyEngine, settings: Settings | None = None) -> None:
        raise NotImplementedError

    @property
    def policy(self) -> PolicyEngine:
        """The policy engine this governor decides against."""
        raise NotImplementedError

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
        raise NotImplementedError

    def invoke(self, fn: Callable[..., T], plan: Plan) -> T:
        """Perform a planned call and attach its envelope.

        Args:
            fn: The protected callable.
            plan: The plan produced by :meth:`plan` for this call.

        Returns:
            Whatever ``fn`` returned, with the ``_authz`` envelope attached when the result
            is a mapping and ``envelope_on_success`` is set.
        """
        raise NotImplementedError

    async def ainvoke(self, fn: Callable[..., Awaitable[T]], plan: Plan) -> T:
        """Await a planned call and attach its envelope.

        The decision itself is synchronous — Cedar evaluation is in-process and cheap — so
        this differs from :meth:`invoke` only in awaiting the callable. Hosts that need the
        decision off the event loop wrap it with
        :func:`~sentrykit.context.bind_context`.

        Args:
            fn: The protected coroutine function.
            plan: The plan produced by :meth:`plan` for this call.

        Returns:
            Whatever ``fn`` resolved to, with the envelope attached where applicable.
        """
        raise NotImplementedError


def install(
    policies: str,
    *,
    entities: Sequence[Entity] = (),
    schema: str | None = None,
    settings: Settings | None = None,
) -> Governor:
    """Build a governor over an in-memory policy set and make it the process default.

    The one-call wiring for Phase 1, for tests, and for small services whose policy fits in a
    string literal. Phase 2 replaces the in-memory source with the pluggable
    ``PolicySource`` / ``GrantStore`` pair without changing anything downstream.

    Args:
        policies: Cedar policy text.
        entities: The stable entity graph — roles, teams, resources.
        schema: Optional Cedar schema text.
        settings: Base settings, defaulting to the process configuration.

    Returns:
        The installed governor.

    Raises:
        ConfigurationError: If the policies, entities or schema fail to parse.
    """
    raise NotImplementedError


def set_governor(governor: Governor | None) -> None:
    """Install ``governor`` as the process default, or clear it with ``None``."""
    raise NotImplementedError


def current_governor() -> Governor | None:
    """Return the process-default governor, or ``None`` if none is installed."""
    raise NotImplementedError


def get_governor() -> Governor:
    """Return the process-default governor.

    Returns:
        The installed governor.

    Raises:
        ConfigurationError: If none is installed. Protecting a callable without wiring a
            policy is a configuration mistake, and it fails loudly at call time rather than
            quietly allowing.
    """
    raise NotImplementedError


@contextmanager
def use_governor(governor: Governor) -> Iterator[Governor]:
    """Install ``governor`` for the duration of a block, then restore the previous one.

    Args:
        governor: The governor to use.

    Yields:
        The governor, for convenience.
    """
    raise NotImplementedError


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
    raise NotImplementedError


def merge_environment(
    ambient: Mapping[str, object],
    explicit: Mapping[str, object] | None,
    *,
    proposed: Mapping[str, object] | None = None,
    parameters: Collection[str] = (),
) -> dict[str, object]:
    """Build the Cedar request context for one decision.

    Layers the explicit environment over the ambient one, fills in ``now`` and ``channel``
    when neither supplied them, and exposes the proposed arguments under ``args`` so a Cedar
    ``forbid`` can inspect them directly. That last part is ADR-002's defense in depth: the
    Python-side filter is the enforcement, and an argument-aware ``forbid`` is the backstop
    that catches a filter that was never configured.

    Args:
        ambient: The environment established at the boundary.
        explicit: Per-call overrides.
        proposed: The proposed arguments, exposed to policy under ``args``.
        parameters: Parameter names of the target callable, used to label the argument
            context.

    Returns:
        The merged environment, ready for coercion into a Cedar context.
    """
    raise NotImplementedError
