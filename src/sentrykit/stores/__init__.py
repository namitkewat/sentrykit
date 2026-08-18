"""The three store contracts, and lazy access to the backends that ship with sentrykit.

The contracts are imported eagerly; the **backends are not**. Two reasons, and the second is
the one that matters:

1. A backend module reaches back into :mod:`sentrykit.audit` for the record type, and
   :mod:`sentrykit.audit` reaches into :mod:`sentrykit.stores.base` for the sink contract.
   Importing the backends from this package's body would close that loop.
2. Entry-point discovery, not a package import, is what makes a backend reachable. The
   registry resolves ``jsonl://`` by exactly the path it resolves a third-party
   ``sentrykit-<x>`` sink — through ``importlib.metadata`` — and if the built-ins needed a
   privileged import to be found, ADR-004's claim that built-in and third-party backends are
   indistinguishable to the core would simply be false.

``from sentrykit.stores import JsonlAuditSink`` still works: PEP 562 resolves it on first
access, importing the one module it needs. See ``dev-docs/architecture.md`` §4 for why there
are three stores rather than one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from sentrykit.stores.base import (
    AuditSink,
    AuditWindow,
    ContextProvider,
    GrantKind,
    GrantRecord,
    GrantSpec,
    GrantStore,
    NullAuditSink,
    PolicyBundle,
    PolicyProvenance,
    PolicySource,
    SupportsClose,
)

if TYPE_CHECKING:  # pragma: no cover - the type checker resolves what __getattr__ defers
    from sentrykit.stores.composite import (
        CompositeAuditSink,
        CompositeGrantStore,
        CompositePolicySource,
    )
    from sentrykit.stores.filesystem import FilesystemPolicySource
    from sentrykit.stores.jsonl import JsonlAuditSink
    from sentrykit.stores.memory import (
        InMemoryAuditSink,
        InMemoryGrantStore,
        InMemoryTokenVault,
    )

__all__ = [
    "AuditSink",
    "AuditWindow",
    "CompositeAuditSink",
    "CompositeGrantStore",
    "CompositePolicySource",
    "ContextProvider",
    "FilesystemPolicySource",
    "GrantKind",
    "GrantRecord",
    "GrantSpec",
    "GrantStore",
    "InMemoryAuditSink",
    "InMemoryGrantStore",
    "InMemoryTokenVault",
    "JsonlAuditSink",
    "NullAuditSink",
    "PolicyBundle",
    "PolicyProvenance",
    "PolicySource",
    "SupportsClose",
]

_LAZY: Final[dict[str, str]] = {
    "CompositeAuditSink": "sentrykit.stores.composite",
    "CompositeGrantStore": "sentrykit.stores.composite",
    "CompositePolicySource": "sentrykit.stores.composite",
    "FilesystemPolicySource": "sentrykit.stores.filesystem",
    "InMemoryAuditSink": "sentrykit.stores.memory",
    "InMemoryGrantStore": "sentrykit.stores.memory",
    "InMemoryTokenVault": "sentrykit.stores.memory",
    "JsonlAuditSink": "sentrykit.stores.jsonl",
}
"""Backend name to the module that defines it, imported on first access."""


def __getattr__(name: str) -> object:
    """Resolve a backend name by importing only the module that defines it.

    Args:
        name: The attribute being read.

    Returns:
        The backend class.

    Raises:
        AttributeError: For anything that is not a known backend, so a typo still fails the
            way a missing attribute normally does.
    """
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    return getattr(import_module(module_name), name)


def __dir__() -> list[str]:
    """List the eager and lazy names together, so tab-completion sees the backends."""
    return sorted(__all__)
