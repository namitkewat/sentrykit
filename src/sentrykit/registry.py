"""One plugin mechanism, used by everything pluggable.

ADR-004 in practice: a `Protocol` contract, a name-keyed registry, an in-process
``register_*`` decorator, and ``importlib.metadata`` entry-point discovery — the same four
pieces for policy sources, grant stores, audit sinks and framework context providers. Adding
a sink and adding a framework are the same shape of task, and the core imports neither.

**Built-ins register through the decorator a third party would use.** They are not special-
cased anywhere; ``jsonl`` reaches the registry by exactly the path ``sentrykit-splunk`` would.
That is the property the plugin tests assert, because it is the only way to know an external
backend is a first-class citizen rather than a documented aspiration.

Backends are addressed by **DSN**: ``jsonl://./audit.jsonl?fsync=true``,
``file://./policies``, ``memory://``. The scheme selects the backend; everything after it is
the backend's business.

Discovery is **lazy**. ``EntryPoint.load()`` imports the plugin's module, so resolving every
installed backend at ``import sentrykit`` time would drag optional dependencies into every
process. The registry looks at entry points only when an in-process lookup misses, then
caches the result.

Phase 2 research pinned the `importlib.metadata` details that matter here: always call
``entry_points(group=...)`` (the bare call returns a different type on 3.11), treat the
result as an iterable and nothing more (it is a `list` subclass on 3.11 and a `tuple`
subclass on 3.12+), and expect an unknown group to be empty rather than to raise.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Literal, TypeVar

from sentrykit.stores.base import (
    AuditSink,
    ContextProvider,
    GrantStore,
    PolicySource,
)

__all__ = [
    "DSN",
    "ENTRY_POINT_GROUPS",
    "PluginKind",
    "RegisteredPlugin",
    "available",
    "build_audit_sink",
    "build_context_provider",
    "build_grant_store",
    "build_policy_source",
    "clear_registry",
    "parse_dsn",
    "register_audit_sink",
    "register_context_provider",
    "register_grant_store",
    "register_policy_source",
    "resolve",
]

PluginKind = Literal["policy_source", "grant_store", "audit_sink", "context_provider"]
"""The four extension points."""

ENTRY_POINT_GROUPS: Final[Mapping[PluginKind, str]] = {
    "policy_source": "sentrykit.policy_sources",
    "grant_store": "sentrykit.grant_stores",
    "audit_sink": "sentrykit.audit_sinks",
    "context_provider": "sentrykit.context_providers",
}
"""Entry-point group per kind. A third-party package publishes into one of these."""

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class DSN:
    """A parsed backend address.

    Parsed by hand rather than with :func:`urllib.parse.urlsplit`, because the targets are
    often filesystem paths and this library ships for ``win-64``: a URL parser reads the
    ``D:`` of ``file://D:/policies`` as a scheme-relative host and mangles it. Splitting on
    the first ``://`` and the first ``?`` keeps a Windows path intact, which matters more here
    than RFC conformance for addresses only sentrykit ever reads.

    Attributes:
        scheme: The registered backend name — ``jsonl``, ``file``, ``memory``.
        target: Everything between the scheme and the query. Usually a path; may be empty
            (``memory://``).
        options: Query parameters, as strings.
        raw: The DSN exactly as given, for error messages and provenance.
    """

    scheme: str
    target: str = ""
    options: Mapping[str, str] = field(default_factory=dict)
    raw: str = ""

    def option(self, name: str, default: str | None = None) -> str | None:
        """Return one option, or ``default`` when it is absent."""
        raise NotImplementedError

    def flag(self, name: str, default: bool = False) -> bool:
        """Read an option as a boolean.

        ``true``/``1``/``yes``/``on`` are true, ``false``/``0``/``no``/``off`` are false, in
        any case.

        Raises:
            ConfigurationError: If the value is present but is neither.
        """
        raise NotImplementedError

    def integer(self, name: str, default: int | None = None) -> int | None:
        """Read an option as an integer.

        Raises:
            ConfigurationError: If the value is present and not an integer.
        """
        raise NotImplementedError


def parse_dsn(dsn: str) -> DSN:
    """Parse a backend address.

    Args:
        dsn: ``scheme://target?key=value&key2=value2``. A bare name (``memory``) is accepted
            and read as ``memory://``, since a schemeless backend with no target is common
            enough that requiring the punctuation is just friction.

    Returns:
        The parsed address.

    Raises:
        ConfigurationError: If the string carries no usable scheme.
    """
    raise NotImplementedError


@dataclass(frozen=True, slots=True)
class RegisteredPlugin:
    """One registered backend, however it got here.

    Attributes:
        kind: Which extension point it plugs into.
        name: The DSN scheme it answers to.
        factory: Callable taking a :class:`DSN` and returning an instance. For a class
            registered directly this is its ``from_dsn`` classmethod.
        distribution: The distribution that supplied it (``sentrykit``, ``sentrykit-splunk``),
            when discovery knows — ``EntryPoint.dist`` may be absent.
        version: That distribution's version, when known.
        source: ``builtin`` for an in-process registration, ``entry-point`` for a discovered
            one. Recorded for diagnostics only: the core treats the two identically, which is
            the point of ADR-004.
    """

    kind: PluginKind
    name: str
    factory: Callable[[DSN], object]
    distribution: str | None = None
    version: str | None = None
    source: Literal["builtin", "entry-point"] = "builtin"


def register_policy_source(name: str) -> Callable[[type[T]], type[T]]:
    """Register a :class:`~sentrykit.stores.base.PolicySource` under a DSN scheme.

    The decorated class must expose ``from_dsn(cls, dsn: DSN) -> Self``.

    Args:
        name: The DSN scheme, e.g. ``file``.

    Returns:
        The decorator, which returns the class unchanged.

    Raises:
        ConfigurationError: If ``name`` is already registered for this kind by a *different*
            class. Re-registering the same class is a no-op, so module reimport is harmless.
    """
    raise NotImplementedError


def register_grant_store(name: str) -> Callable[[type[T]], type[T]]:
    """Register a :class:`~sentrykit.stores.base.GrantStore` under a DSN scheme.

    See :func:`register_policy_source` for the contract.
    """
    raise NotImplementedError


def register_audit_sink(name: str) -> Callable[[type[T]], type[T]]:
    """Register an :class:`~sentrykit.stores.base.AuditSink` under a DSN scheme.

    See :func:`register_policy_source` for the contract.
    """
    raise NotImplementedError


def register_context_provider(name: str) -> Callable[[type[T]], type[T]]:
    """Register a :class:`~sentrykit.stores.base.ContextProvider` under a DSN scheme.

    See :func:`register_policy_source` for the contract.
    """
    raise NotImplementedError


def resolve(kind: PluginKind, name: str) -> RegisteredPlugin:
    """Find the backend registered as ``name``, discovering entry points if needed.

    In-process registrations win over entry points, so a host can override a shipped backend
    without uninstalling the package that provides it.

    Args:
        kind: Which extension point.
        name: The DSN scheme.

    Returns:
        The registration.

    Raises:
        ConfigurationError: If nothing answers to that name. The message lists what *is*
            available, because "unknown sink 'jsonl1'" with no list is a bad afternoon.
    """
    raise NotImplementedError


def available(kind: PluginKind) -> tuple[str, ...]:
    """List every backend name available for ``kind``, discovering entry points.

    Args:
        kind: Which extension point.

    Returns:
        The names, sorted.
    """
    raise NotImplementedError


def clear_registry(kind: PluginKind | None = None) -> None:
    """Drop registrations and the discovery cache.

    For tests, and for a host that installs a plugin at runtime. Built-ins re-register on
    their module's next import, so this is not a way to permanently remove one.

    Args:
        kind: Which extension point to clear, or ``None`` for all of them.
    """
    raise NotImplementedError


def build_policy_source(dsn: str | Sequence[str] | None) -> PolicySource | None:
    """Build a policy source from one DSN, or a composite from several.

    Multiplicity is a composite that satisfies the same Protocol (ADR-004), so the core
    always holds exactly one source and never learns how many were configured.

    Args:
        dsn: One DSN, several, or ``None``.

    Returns:
        The single source when one DSN was given, a
        :class:`~sentrykit.stores.composite.CompositePolicySource` when several were, and
        ``None`` when none were.

    Raises:
        ConfigurationError: If a scheme is unknown or a backend rejects its DSN.
    """
    raise NotImplementedError


def build_grant_store(dsn: str | Sequence[str] | None) -> GrantStore | None:
    """Build a grant store from one DSN, or a composite from several.

    Several stores merge by precedence — earlier DSNs win — unless every one of them declares
    a namespace, in which case the composite routes by namespace instead. See
    :class:`~sentrykit.stores.composite.CompositeGrantStore`.

    Args:
        dsn: One DSN, several, or ``None``.

    Returns:
        The store, the composite, or ``None``.

    Raises:
        ConfigurationError: If a scheme is unknown or a backend rejects its DSN.
    """
    raise NotImplementedError


def build_audit_sink(dsn: str | Sequence[str] | None) -> AuditSink | None:
    """Build an audit sink from one DSN, or a fan-out composite from several.

    Args:
        dsn: One DSN, several, or ``None``. The error policy for a fan-out is a DSN option on
            the *first* sink (``?on_error=primary-durable`` or ``?on_error=all-or-nothing``).

    Returns:
        The sink, the composite, or ``None`` when none were configured — which leaves
        auditing off rather than silently discarding records into a null sink.

    Raises:
        ConfigurationError: If a scheme is unknown or a backend rejects its DSN.
    """
    raise NotImplementedError


def build_context_provider(dsn: str | Sequence[str] | None) -> ContextProvider | None:
    """Build a framework context provider. Phases 3 and 4 supply the implementations.

    Args:
        dsn: One DSN, several, or ``None``.

    Returns:
        The provider, or ``None``.

    Raises:
        ConfigurationError: If a scheme is unknown.
    """
    raise NotImplementedError


def discovered(kind: PluginKind) -> Iterable[RegisteredPlugin]:
    """Enumerate the entry-point registrations for ``kind``, loading each one.

    Exposed so a host can inspect what is installed — and so the plugin test can assert that
    a third-party distribution reaches the registry with no change to sentrykit.

    Args:
        kind: Which extension point.

    Returns:
        The discovered registrations. A plugin whose module fails to import is skipped with
        an ``ERROR`` log rather than breaking every other backend.
    """
    raise NotImplementedError
