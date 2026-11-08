# Plugins & extensions

Everything sentrykit talks to on the outside is a plugin: where policies come from, where
grants live, where audit records go, and how a framework establishes context. All four use
the same four pieces, so *add a sink* and *add a framework* are the same shape of task.

1. A `Protocol` contract in `sentrykit.stores.base`.
2. A name, which doubles as a DSN scheme.
3. An in-process `register_*` decorator.
4. An `importlib.metadata` entry point, so an installed package self-registers.

The built-in backends use exactly this path. There is no privileged import for them — if
there were, "built-in and third-party are indistinguishable to the core" would be a slogan
rather than a property.

## The four extension points

| Kind | Protocol | Entry-point group | Ships with |
| --- | --- | --- | --- |
| Policy source | `PolicySource` | `sentrykit.policy_sources` | `file`, `pack` |
| Grant store | `GrantStore` | `sentrykit.grant_stores` | `jsonfile`, `memory` |
| Audit sink | `AuditSink` | `sentrykit.audit_sinks` | `jsonl`, `memory` |
| Context provider | `ContextProvider` | `sentrykit.context_providers` | `fastapi`, `flask`, `mcp`, `pydantic-ai` |

## Addressing a backend: the DSN

```
scheme://target?option=value&other=value
```

The scheme selects the backend; everything after it is that backend's business.

```python
"file://./policies"                      # a directory of .cedar files
"pack://"                                # the shipped policy pack
"pack://rbac,ownership"                  # ... just those two patterns
"file://./policies?validate=false"       # skip schema type-checking at load
"jsonl://./var/audit.jsonl?fsync=true"   # durable append-only log
"jsonfile://./var/grants.json"           # durable grant store, shared across processes
"memory://"                              # in-process grant store
"memory://tenant-a"                      # ... with a namespace, for routed composites
```

DSNs are parsed by hand rather than with `urllib.parse`, because targets are usually
filesystem paths and a URL parser reads the `D:` of `file://D:/policies` as a host and
mangles it. Splitting on the first `://` and the first `?` keeps a Windows path intact.

## Wiring them up

`install()` takes a DSN, a list of DSNs, or an already-built instance for each kind:

```python
from sentrykit import install

install(
    policy_source="file://./policies",
    grant_store="memory://",
    audit_sink="jsonl://./var/audit.jsonl",
)
```

Pass a list and you get a composite — which satisfies the same `Protocol`, so the decision
path never learns how many were configured:

```python
install(
    policy_source=["file://./policies/base", "file://./policies/tenant-a"],
    audit_sink=["jsonl://./var/audit.jsonl", "memory://"],
)
```

Or build the object yourself when a DSN cannot carry what you need — credentials, a client
you already own, a handle a test wants to keep:

```python
from sentrykit.stores import InMemoryAuditSink

sink = InMemoryAuditSink()
install(POLICIES, audit_sink=sink)
assert sink.records          # the test still holds the reference
```

### Composite semantics

| Kind | How several combine |
| --- | --- |
| `PolicySource` | **Union.** Policies are concatenated in a fixed order and declared ids are namespaced `<source>/<id>`. There is deliberately **no source precedence** — an override is a Cedar `forbid`, and forbid always wins, so ordering cannot change a decision. |
| `GrantStore` | **Merge by precedence** (earlier stores win per field; roles and parents union) *or* **route by namespace** when every member declares one. |
| `AuditSink` | **Fan out.** `?on_error=primary-durable` (default) requires the first sink to succeed and logs the rest's failures; `?on_error=all-or-nothing` reports any failure. |

## Writing a third-party backend

A backend needs a `from_dsn` classmethod and the Protocol's methods. It imports nothing from
sentrykit at runtime if you would rather it did not — the Protocols are structural.

```python
# sentrykit_splunk/sink.py
from __future__ import annotations

from collections.abc import Iterator


class SplunkAuditSink:
    """Ship audit records to a Splunk HTTP Event Collector."""

    def __init__(self, url: str, *, token: str, name: str = "splunk") -> None:
        self._url, self._token, self._name = url, token, name

    @classmethod
    def from_dsn(cls, dsn) -> SplunkAuditSink:          # dsn: sentrykit.registry.DSN
        return cls(dsn.target, token=dsn.option("token", "") or "")

    @property
    def name(self) -> str:
        return self._name

    def write(self, record) -> None:
        ...        # record is already masked and already chained — just persist it

    def query(self, window) -> Iterator:
        ...
```

Publish it:

```toml
# pyproject.toml of sentrykit-splunk
[project.entry-points."sentrykit.audit_sinks"]
splunk = "sentrykit_splunk.sink:SplunkAuditSink"
```

After `pip install sentrykit-splunk`, `audit_sink="splunk://hec.example.com?token=..."`
works with **no change to sentrykit**. Discovery is lazy: entry points are swept the first
time a name misses the in-process registry, so an installed backend costs nothing until it is
asked for.

To register without publishing a package — a backend that lives in your own application:

```python
from sentrykit import register_audit_sink


@register_audit_sink("ourdb")
class OurDatabaseSink:
    ...
```

In-process registrations win over entry points, so this also overrides a shipped backend
without uninstalling the package that provides it.

Every kind registers the same way. A policy source is the one hosts add most often — a bundle
in object storage, a config service — and it needs three members: a `name` to namespace policy
ids with, a `load()` returning a `PolicyBundle`, and a `current_hash()` cheap enough to poll:

```python
from sentrykit import register_policy_source
from sentrykit.stores.base import PolicyBundle


@register_policy_source("ourbundle")
class OurBundleSource:
    def __init__(self, dsn):
        self.dsn = dsn

    @property
    def name(self) -> str:
        return "ourbundle"

    @classmethod
    def from_dsn(cls, dsn):
        return cls(dsn)

    def load(self) -> PolicyBundle:
        text = fetch(self.dsn.target)  # your storage
        return PolicyBundle.from_text(text, source=self.name)

    def current_hash(self) -> str:
        return self.load().bundle_hash
```

`install(policy_source="ourbundle://prod")` now resolves it, and
`install(policy_source=["pack://", "ourbundle://prod"])` unions it with the shipped pack.
Source order cannot change a decision — an override is a Cedar `forbid`, and forbid always
wins — so the names exist to namespace policy ids, not to establish precedence.

## Inspecting what is installed

```python
from sentrykit import available

available("audit_sink")     # ('jsonl', 'memory')
available("grant_store")    # ('jsonfile', 'memory')
available("policy_source")  # ('file', 'pack')
```

An unknown scheme raises `ConfigurationError` naming what *is* available, and every built
object is checked against its Protocol at wiring time — a plugin missing `query` fails when
you start the process, not when an auditor runs a report.

## What a backend can rely on

- **Audit sinks receive masked, chained records.** Masking happens upstream of the write, in
  `AuditTrail`, and a sink must never mask, mutate, or reorder. See
  [Audit & compliance](audit.md).
- **A sink may raise.** Signal a failed append with `AuditUnavailable`; under
  `fail_mode="closed"` sentrykit refuses the governed call rather than let an unprovable
  action through.
- **Policy sources own their provenance.** `PolicyBundle.from_text` builds the annotation
  index; set each entry's `origin` to something an auditor can resolve — a file path, an S3
  version id, a git commit. It also parses any
  [argument ceiling](policies.md#argument-ceilings) a policy declares and raises
  `ConfigurationError` on a malformed one, so a source that builds its bundle that way fails at
  load rather than serving a bound that silently enforces nothing.
- **A grant store returns materialized principals.** Expired and revoked grants are excluded
  by the store, so the decision path never reasons about grant lifecycles.
- **A grant store refuses what it could not honour.** `grant()` raises `ConfigurationError` on
  an argument constraint no value could satisfy — inverted bounds, an uncompilable pattern, a
  default the constraint's own rules reject. `ArgumentConstraint.inconsistencies()` is the check
  the built-in stores run, and a third-party store should run it at the write too: left to the
  call path, an unsatisfiable constraint is a refusal of everything, found by whoever calls
  next.
