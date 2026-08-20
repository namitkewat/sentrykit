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

The caller proposes; the policy decides.
"""

from __future__ import annotations

from sentrykit.audit import AuditTrail, AuthzAuditRecord, ChainVerdict, verify_chain
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
from sentrykit.masking import Masker, Sensitive
from sentrykit.policy.loader import (
    LinkedPolicySource,
    PackPolicySource,
    TemplateLink,
    link_template,
    load_pack,
)
from sentrykit.registry import (
    available,
    build_audit_sink,
    build_grant_store,
    build_policy_source,
    register_audit_sink,
    register_context_provider,
    register_grant_store,
    register_policy_source,
)
from sentrykit.stores.base import (
    AuditSink,
    AuditWindow,
    GrantRecord,
    GrantSpec,
    GrantStore,
    PolicyBundle,
    PolicySource,
)

__all__ = [
    "ArgumentConstraint",
    "ArgumentRejected",
    "ArgumentSpec",
    "AuditSink",
    "AuditTrail",
    "AuditUnavailable",
    "AuditWindow",
    "AuthzAuditRecord",
    "AuthzDenied",
    "AuthzEnvelope",
    "CedarDecision",
    "CedarRequest",
    "ChainVerdict",
    "ConfigurationError",
    "ConstraintSet",
    "ContextScope",
    "DefaultUnavailable",
    "Entity",
    "EntityRef",
    "FilterResult",
    "Governor",
    "GrantRecord",
    "GrantSpec",
    "GrantStore",
    "Invocation",
    "LinkedPolicySource",
    "Masker",
    "NoContext",
    "NoValidArguments",
    "PackPolicySource",
    "Plan",
    "PolicyBundle",
    "PolicyEngine",
    "PolicySource",
    "Principal",
    "ProtectedMeta",
    "RejectedArgument",
    "ReservedKey",
    "Sensitive",
    "SentrykitError",
    "Settings",
    "TemplateLink",
    "ValidationFailed",
    "__version__",
    "available",
    "bind_context",
    "build_audit_sink",
    "build_grant_store",
    "build_policy_source",
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
    "link_template",
    "load_pack",
    "override_action",
    "principal_context",
    "protect",
    "protected_meta",
    "register_audit_sink",
    "register_context_provider",
    "register_grant_store",
    "register_policy_source",
    "require_principal",
    "reset_settings",
    "set_governor",
    "settings_for",
    "use_governor",
    "verify_chain",
]

__version__ = "0.1.0"
