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

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib import metadata
from typing import Final, Literal, TypeVar
from urllib.parse import unquote

from sentrykit.errors import ConfigurationError
from sentrykit.stores.base import (
    AuditSink,
    ContextProvider,
    GrantStore,
    PolicySource,
)

_LOGGER: Final = logging.getLogger("sentrykit.registry")

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
    "registrations",
    "remember",
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

_TRUTHY: Final[frozenset[str]] = frozenset({"true", "1", "yes", "on"})
_FALSEY: Final[frozenset[str]] = frozenset({"false", "0", "no", "off"})

_REGISTRY: Final[dict[PluginKind, dict[str, RegisteredPlugin]]] = {
    kind: {} for kind in ENTRY_POINT_GROUPS
}
"""In-process registrations, by kind and name. Populated by the ``register_*`` decorators."""

_DISCOVERED: Final[set[PluginKind]] = set()
"""Kinds whose entry points have already been swept, so discovery runs at most once each."""


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
        return self.options.get(name, default)

    def flag(self, name: str, default: bool = False) -> bool:
        """Read an option as a boolean.

        ``true``/``1``/``yes``/``on`` are true, ``false``/``0``/``no``/``off`` are false, in
        any case.

        Raises:
            ConfigurationError: If the value is present but is neither. A typo in
                ``?fsync=ture`` silently meaning "no" is exactly the kind of durability
                setting that must not fail quietly.
        """
        raw = self.options.get(name)
        if raw is None:
            return default
        lowered = raw.strip().lower()
        if lowered in _TRUTHY:
            return True
        if lowered in _FALSEY:
            return False
        raise ConfigurationError(
            f"option {name!r} in {self.raw!r} is {raw!r}, which is not a boolean"
        )

    def integer(self, name: str, default: int | None = None) -> int | None:
        """Read an option as an integer.

        Raises:
            ConfigurationError: If the value is present and not an integer.
        """
        raw = self.options.get(name)
        if raw is None:
            return default
        try:
            return int(raw.strip())
        except ValueError as exc:
            raise ConfigurationError(
                f"option {name!r} in {self.raw!r} is {raw!r}, which is not an integer"
            ) from exc


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
    text = dsn.strip()
    if not text:
        raise ConfigurationError("a backend DSN cannot be empty")

    scheme, separator, remainder = text.partition("://")
    if not separator:
        # A bare name. Only meaningful when it *is* just a name -- anything carrying a path
        # or a query without a scheme is a typo, and guessing at it would wire the host to a
        # backend it did not ask for.
        if "/" in text or "?" in text or ":" in text:
            raise ConfigurationError(f"cannot parse backend DSN {dsn!r}; expected scheme://target")
        scheme, remainder = text, ""

    scheme = scheme.strip().lower()
    if not scheme:
        raise ConfigurationError(f"cannot parse backend DSN {dsn!r}; it names no scheme")

    target, _, query = remainder.partition("?")
    options: dict[str, str] = {}
    for pair in query.split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        options[unquote(key.strip())] = unquote(value.strip())
    return DSN(scheme=scheme, target=unquote(target), options=options, raw=text)


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
    return _register("policy_source", name)


def register_grant_store(name: str) -> Callable[[type[T]], type[T]]:
    """Register a :class:`~sentrykit.stores.base.GrantStore` under a DSN scheme.

    See :func:`register_policy_source` for the contract.
    """
    return _register("grant_store", name)


def register_audit_sink(name: str) -> Callable[[type[T]], type[T]]:
    """Register an :class:`~sentrykit.stores.base.AuditSink` under a DSN scheme.

    See :func:`register_policy_source` for the contract.
    """
    return _register("audit_sink", name)


def register_context_provider(name: str) -> Callable[[type[T]], type[T]]:
    """Register a :class:`~sentrykit.stores.base.ContextProvider` under a DSN scheme.

    See :func:`register_policy_source` for the contract.
    """
    return _register("context_provider", name)


def _register(kind: PluginKind, name: str) -> Callable[[type[T]], type[T]]:
    """Build the decorator the four public ``register_*`` functions return.

    One implementation for all four kinds, because ADR-004's claim is that adding a sink and
    adding a framework are the same task -- if the registration paths diverged, they would
    not be.

    Args:
        kind: Which extension point.
        name: The DSN scheme.

    Returns:
        A decorator returning its class unchanged, so a registered class is still an ordinary
        class its own tests can construct directly.
    """
    scheme = name.strip().lower()
    if not scheme:
        raise ConfigurationError(f"a {kind} must be registered under a non-empty name")

    def decorate(cls: type[T]) -> type[T]:
        """Record ``cls`` as the backend answering to ``scheme``."""
        factory = getattr(cls, "from_dsn", None)
        if not callable(factory):
            raise ConfigurationError(
                f"{cls.__qualname__} cannot be registered as a {kind} named {scheme!r}: "
                "it has no from_dsn(dsn) classmethod"
            )
        existing = _REGISTRY[kind].get(scheme)
        if existing is not None and getattr(existing.factory, "__self__", None) is not cls:
            raise ConfigurationError(
                f"a {kind} named {scheme!r} is already registered "
                f"({existing.name} from {existing.source})"
            )
        _REGISTRY[kind][scheme] = RegisteredPlugin(kind=kind, name=scheme, factory=factory)
        _LOGGER.debug("Registered %s %r from %s", kind, scheme, cls.__qualname__)
        return cls

    return decorate


def registrations(kind: PluginKind) -> Mapping[str, RegisteredPlugin]:
    """Return the in-process registrations for ``kind``, without triggering discovery.

    Exposed for :func:`resolve` and for tests that need to see the registry as it stands.
    """
    return _REGISTRY[kind]


def remember(plugin: RegisteredPlugin) -> None:
    """Cache a discovered registration so the entry-point sweep runs once per kind.

    An in-process registration always wins: a host that has explicitly registered a backend
    has said which one it wants, and an installed package must not quietly replace it.
    """
    _REGISTRY[plugin.kind].setdefault(plugin.name, plugin)


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
    scheme = name.strip().lower()
    registered = _REGISTRY[kind]
    plugin = registered.get(scheme)
    if plugin is None and kind not in _DISCOVERED:
        # Only sweep on a miss, and only once: ``EntryPoint.load()`` imports the plugin's
        # module, so an eager sweep would pull every installed backend into every process.
        discovered(kind)
        plugin = registered.get(scheme)
    if plugin is None:
        known = ", ".join(sorted(registered)) or "none registered"
        raise ConfigurationError(f"no {kind} is registered as {scheme!r}; available: {known}")
    return plugin


def available(kind: PluginKind) -> tuple[str, ...]:
    """List every backend name available for ``kind``, discovering entry points.

    Args:
        kind: Which extension point.

    Returns:
        The names, sorted.
    """
    if kind not in _DISCOVERED:
        discovered(kind)
    return tuple(sorted(_REGISTRY[kind]))


def clear_registry(kind: PluginKind | None = None) -> None:
    """Drop registrations and the discovery cache.

    For tests, and for a host that installs a plugin at runtime. Built-ins re-register on
    their module's next import, so this is not a way to permanently remove one.

    Args:
        kind: Which extension point to clear, or ``None`` for all of them.
    """
    kinds: tuple[PluginKind, ...] = tuple(ENTRY_POINT_GROUPS) if kind is None else (kind,)
    for one in kinds:
        _REGISTRY[one].clear()
        # Drop the sweep marker too, or the next ``resolve`` would trust an empty registry.
        _DISCOVERED.discard(one)


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
    addresses = _addresses(dsn)
    if not addresses:
        return None
    sources: list[PolicySource] = []
    for address in addresses:
        built = _instantiate("policy_source", address)
        if not isinstance(built, PolicySource):
            raise _unsatisfied("policy_source", address, "PolicySource")
        sources.append(built)
    if len(sources) == 1:
        return sources[0]
    from sentrykit.stores.composite import CompositePolicySource

    return CompositePolicySource(sources)


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
    addresses = _addresses(dsn)
    if not addresses:
        return None
    stores: list[GrantStore] = []
    for address in addresses:
        built = _instantiate("grant_store", address)
        if not isinstance(built, GrantStore):
            raise _unsatisfied("grant_store", address, "GrantStore")
        stores.append(built)
    if len(stores) == 1:
        return stores[0]
    from sentrykit.stores.composite import CompositeGrantStore

    return CompositeGrantStore(stores)


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
    addresses = _addresses(dsn)
    if not addresses:
        return None
    # Read the fan-out policy before building anything: a typo in ``?on_error=`` should be a
    # wiring error, not a surprise the first time a replica goes down.
    from sentrykit.stores.composite import AUDIT_ERROR_POLICIES, CompositeAuditSink

    requested = parse_dsn(addresses[0]).option("on_error", "primary-durable") or ""
    on_error = AUDIT_ERROR_POLICIES.get(requested)
    if on_error is None:
        known = ", ".join(sorted(AUDIT_ERROR_POLICIES))
        raise ConfigurationError(
            f"audit sink option 'on_error' in {addresses[0]!r} is {requested!r}; expected {known}"
        )
    sinks: list[AuditSink] = []
    for address in addresses:
        built = _instantiate("audit_sink", address)
        if not isinstance(built, AuditSink):
            raise _unsatisfied("audit_sink", address, "AuditSink")
        sinks.append(built)
    if len(sinks) == 1:
        return sinks[0]
    return CompositeAuditSink(sinks, on_error=on_error)


def build_context_provider(dsn: str | Sequence[str] | None) -> ContextProvider | None:
    """Build a framework context provider. Phases 3 and 4 supply the implementations.

    Args:
        dsn: One DSN, several, or ``None``.

    Returns:
        The provider, or ``None``.

    Raises:
        ConfigurationError: If a scheme is unknown.
    """
    addresses = _addresses(dsn)
    if not addresses:
        return None
    if len(addresses) > 1:
        # There is no composite provider, and inventing one would have to guess which
        # framework owns an incoming request. A process wires the provider for the boundary
        # it actually serves.
        raise ConfigurationError(
            f"only one context provider can be configured, but {len(addresses)} were given: "
            f"{', '.join(addresses)}"
        )
    built = _instantiate("context_provider", addresses[0])
    if not isinstance(built, ContextProvider):
        raise _unsatisfied("context_provider", addresses[0], "ContextProvider")
    return built


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
    found: list[RegisteredPlugin] = []
    # Always ``group=``: the bare call is the one spelling whose return type differs across
    # 3.11--3.13. The result is only ever iterated -- it is a ``list`` subclass on 3.11 and a
    # ``tuple`` subclass on 3.12+ -- and an unknown group comes back empty rather than raising.
    for entry_point in metadata.entry_points(group=ENTRY_POINT_GROUPS[kind]):
        try:
            loaded = entry_point.load()
        except Exception:
            # One broken plugin must not take out every other backend: an unimportable sink
            # is that distribution's problem, not a reason to leave the host with no audit.
            _LOGGER.exception(
                "Could not load %s plugin %r from %r; skipping it",
                kind,
                entry_point.name,
                entry_point.value,
            )
            continue
        factory = getattr(loaded, "from_dsn", None)
        if not callable(factory):
            _LOGGER.error(
                "The %s plugin %r (%r) has no from_dsn(dsn) classmethod; skipping it",
                kind,
                entry_point.name,
                entry_point.value,
            )
            continue
        distribution = entry_point.dist
        plugin = RegisteredPlugin(
            kind=kind,
            name=entry_point.name.strip().lower(),
            factory=factory,
            # ``EntryPoint.dist`` is typed ``Distribution | None``, so both hops are guarded.
            distribution=getattr(distribution, "name", None) if distribution is not None else None,
            version=getattr(distribution, "version", None) if distribution is not None else None,
            source="entry-point",
        )
        remember(plugin)
        found.append(plugin)
    _DISCOVERED.add(kind)
    return tuple(found)


def _addresses(dsn: str | Sequence[str] | None) -> tuple[str, ...]:
    """Normalize the three ways a backend can be configured into a tuple of DSNs.

    A lone string is one DSN rather than a sequence of characters, which is the whole reason
    this is a function and not an inline ``tuple(dsn)``.
    """
    if dsn is None:
        return ()
    if isinstance(dsn, str):
        return (dsn,)
    return tuple(dsn)


def _instantiate(kind: PluginKind, dsn: str) -> object:
    """Parse one DSN, resolve its backend, and build it.

    Args:
        kind: Which extension point.
        dsn: The address.

    Returns:
        Whatever the backend's ``from_dsn`` returned, unchecked — the caller validates it
        against the Protocol it is supposed to satisfy.

    Raises:
        ConfigurationError: If the DSN is unparseable, the scheme is unknown, or the factory
            rejected the address.
    """
    parsed = parse_dsn(dsn)
    plugin = resolve(kind, parsed.scheme)
    try:
        return plugin.factory(parsed)
    except ConfigurationError:
        raise
    except Exception as exc:
        # A third-party factory can raise anything at all. The host asked to be *configured*,
        # so a stranger's ``KeyError`` is reported as the configuration failure it is.
        raise ConfigurationError(
            f"the {kind} {parsed.scheme!r} could not be built from {parsed.raw!r}: {exc}"
        ) from exc


def _unsatisfied(kind: PluginKind, dsn: str, protocol: str) -> ConfigurationError:
    """Build the error for a backend that constructed but does not implement its contract.

    Checked at wiring time on purpose: a sink missing ``query`` should fail when the process
    starts, not when an auditor runs the yearly report.
    """
    return ConfigurationError(
        f"the {kind} built from {dsn!r} does not satisfy the {protocol} protocol"
    )
