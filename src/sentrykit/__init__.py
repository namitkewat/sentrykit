"""sentrykit — lightweight, framework-agnostic authorization built on AWS Cedar.

Clip :func:`~sentrykit.decorator.protect` onto any callable and sentrykit decides, per call,
whether the principal may invoke it, which arguments they may pass, and which defaults to
inject when they pass none.

```python
from sentrykit import Entity, EntityRef, Principal, establish, install, protect

install(
    '''
    @id("support-may-search")
    permit(
      principal in Role::"support",
      action == Action::"tool.search_orders",
      resource == Tool::"orders"
    );
    ''',
    entities=[Entity(EntityRef("Tool", "orders")), Entity(EntityRef("Role", "support"))],
)


@protect(action='Action::"tool.search_orders"', resource='Tool::"orders"')
def search_orders(customer_id: str, limit: int = 10) -> dict[str, object]:
    return {"customer_id": customer_id, "limit": limit}


with establish(Principal(id="alice", roles=("support",)), channel="agent"):
    search_orders(customer_id="c-1")
```

The caller proposes; the policy decides. See ``dev-docs/architecture.md`` for how the pieces
fit and ``dev-docs/design-decisions.md`` for why.
"""

from __future__ import annotations

from sentrykit.cedar import CedarDecision, CedarRequest, Entity, EntityRef, PolicyEngine
from sentrykit.config import (
    Settings,
    clear_action_overrides,
    configure,
    get_settings,
    override_action,
    reset_settings,
    settings_for,
)
from sentrykit.constraints import (
    ArgumentConstraint,
    ConstraintSet,
    FilterResult,
    RejectedArgument,
)
from sentrykit.context import (
    ContextScope,
    Invocation,
    Principal,
    bind_context,
    clear_context,
    current_environment,
    current_principal,
    establish,
    principal_context,
    require_principal,
)
from sentrykit.decorator import ProtectedMeta, is_protected, protect, protected_meta
from sentrykit.engine import (
    ArgumentSpec,
    Governor,
    Plan,
    current_governor,
    get_governor,
    install,
    set_governor,
    use_governor,
)
from sentrykit.envelope import AuthzEnvelope, last_envelope
from sentrykit.errors import (
    ArgumentRejected,
    AuthzDenied,
    ConfigurationError,
    DefaultUnavailable,
    NoContext,
    NoValidArguments,
    SentrykitError,
    ValidationFailed,
)

__all__ = [
    "ArgumentConstraint",
    "ArgumentRejected",
    "ArgumentSpec",
    "AuthzDenied",
    "AuthzEnvelope",
    "CedarDecision",
    "CedarRequest",
    "ConfigurationError",
    "ConstraintSet",
    "ContextScope",
    "DefaultUnavailable",
    "Entity",
    "EntityRef",
    "FilterResult",
    "Governor",
    "Invocation",
    "NoContext",
    "NoValidArguments",
    "Plan",
    "PolicyEngine",
    "Principal",
    "ProtectedMeta",
    "RejectedArgument",
    "SentrykitError",
    "Settings",
    "ValidationFailed",
    "__version__",
    "bind_context",
    "clear_action_overrides",
    "clear_context",
    "configure",
    "current_environment",
    "current_governor",
    "current_principal",
    "establish",
    "get_governor",
    "get_settings",
    "install",
    "is_protected",
    "last_envelope",
    "override_action",
    "principal_context",
    "protect",
    "protected_meta",
    "require_principal",
    "reset_settings",
    "set_governor",
    "settings_for",
    "use_governor",
]

__version__ = "0.1.0.dev0"
