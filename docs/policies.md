# Policies & patterns

Cedar separates *policy logic* from *entity data*, and sentrykit leans on that split hard
(ADR-005):

- **Policy logic lives in files** under version control. It changes by review, and git
  history is the change-control evidence an auditor asks for.
- **Grants are data** in a mutable store. A role is a parent edge, a per-argument limit is an
  attribute, a time-boxed grant is a timestamp. "Add role" is CRUD — reviewed policy logic
  never changes at runtime.

The shipped policy pack (RBAC, ownership, delegation, expiry, break-the-glass,
separation-of-duties, JIT elevation) lands in Phase 5. This page covers loading policy and
managing grants.

## Loading policy from a directory

```
policies/
  00-base.cedar
  10-support.cedar
  app.cedarschema
  entities.json
```

```python
from sentrykit import install

install(policy_source="file://./policies")
```

Files matching `*.cedar` are read in **sorted order** and concatenated. The order matters:
Cedar numbers policies positionally in the text it parses, and the annotation index that
carries obligations and provenance is keyed by those numbers. Prefixing filenames
(`00-`, `10-`) keeps that order explicit rather than incidental.

`entities.json` holds the **stable** graph — roles, teams, tools — in Cedar entity JSON:

```json
[
  {"uid": {"type": "Role", "id": "support"}, "attrs": {}, "parents": []},
  {"uid": {"type": "Tool", "id": "accounts"}, "attrs": {}, "parents": []}
]
```

Principals never belong here. They arrive per request, materialized from a grant store, so
one principal's snapshot can never leak into another's decision.

### Validation at load, not at runtime

When a `*.cedarschema` is present, the source type-checks the policies against it and raises
`ConfigurationError` naming the offending policy. Cedar's validator never raises on its own —
a policy parse error, a schema parse error and a genuine type error all come back as data —
so a source that did not branch on the result would wire up a policy set that cannot possibly
permit anything and deny every request for the life of the process.

Turn it off per source with `file://./policies?validate=false`.

Note that `.cedarschema` is Cedar's schema *surface syntax*; the JSON schema form is not
accepted.

## Always give a policy an `@id`

```
@id("support-may-look-up-accounts")
permit (
  principal in Role::"support",
  action == Action::"tool.lookup",
  resource == Tool::"accounts"
);
```

Without it Cedar reports determining policies as `policy0`, `policy1`, … — positional ids
that shift the moment someone inserts a policy above, which would quietly make your audit
trail wrong.

Cedar does **not** enforce `@id` uniqueness. When several sources are unioned, sentrykit
namespaces declared ids as `<source>/<id>` so two sources declaring the same name stay
distinguishable.

## Obligations

An obligation says what must *also* happen when a call is permitted. It is declared on the
policy, because "you may do this, provided X" is reviewed logic rather than mutable grant
data (ADR-012).

```
@id("support-may-look-up-accounts")
@obligations("hmac:account, notify:secops")
permit (
  principal in Role::"support",
  action == Action::"tool.lookup",
  resource == Tool::"accounts"
);
```

One comma-separated `@obligations` annotation, not several — Cedar rejects a repeated
annotation key outright. Each entry is `verb:target`:

- **Masking verbs** — `mask`, `redact`, `partial`, `hmac`, `tokenize` — are consumed by
  sentrykit before the audit write. See [Audit & compliance](audit.md).
- **Everything else** — `notify:secops`, `justify` — is carried on the `_authz` envelope and
  the audit record for your application to discharge.

Obligations come from the determining **permit** policies of a call that proceeds. A
determining `forbid`'s obligations belong to the denial record instead: they describe what
must happen about a refusal, not about a call.

```python
result["_authz"]["obligations"]   # ['hmac:account', 'notify:secops']
```

## Composing several sources

```python
install(policy_source=["file://./policies/base", "file://./policies/tenant-a"])
```

Sources compose by **union**. There is deliberately no source precedence, and adding one
would be a mistake: Cedar's `forbid` always beats any `permit`, so an override is expressed
as a `forbid` and the result is the same whichever order the sources are read in. That
order-independence is what makes merging policy from several places safe at all.

```
# policies/tenant-a/20-restrictions.cedar
@id("no-lookups-outside-business-hours")
forbid (principal, action == Action::"tool.lookup", resource)
unless { context.now_hour >= 9 && context.now_hour < 18 };
```

Two sources declaring the *same* entity identically is fine — several policy directories may
each need `Role::"admin"` to exist. Declaring it **differently** is a `ConfigurationError`: an
ambiguous graph is a wiring fault, and which of the two definitions won would decide requests.

Source names namespace policy ids, so members of a union must have distinct names. A
`file://` source is named after its directory, which usually makes that automatic; set
`?name=` when two directories share a basename.

## Grants are data

```python
from datetime import UTC, datetime, timedelta

from sentrykit import Entity, EntityRef, install
from sentrykit.stores import InMemoryGrantStore
from sentrykit.stores.base import GrantSpec

store = InMemoryGrantStore()
store.add_entity(Entity(EntityRef("Role", "support")))

record = store.grant(
    GrantSpec(
        principal=EntityRef("User", "bob"),
        kind="role",
        subject="support",
        granted_by="ops",
        reason="ticket-4412",
        expires_at=datetime.now(UTC) + timedelta(hours=2),
    )
)

store.get_principal("bob").roles      # ('support',)
```

Four kinds of grant:

| `kind` | `subject` | Confers |
| --- | --- | --- |
| `role` | role name | Parent edge `Role::"<subject>"` |
| `parent` | a uid | Any other parent edge — team, project, delegation target |
| `attribute` | attribute name | A Cedar attribute (`value`) on the principal |
| `constraint` | argument name | An `ArgumentConstraint` for one argument of one action |

`role` and `parent` are the interesting ones: Cedar computes the transitive closure, so
*user → team → project → resource* is resolved by policy rather than by a chain of `if`
statements. That is the offload this library exists for.

### Expiry and revocation

```python
store.revoke(record.id, revoked_by="ops", reason="rotation")
store.get_principal("bob").roles      # ()
```

`get_principal` returns a principal with expired and revoked grants already excluded, so the
decision path never reasons about grant lifecycles. Revocation *marks* the record rather than
deleting it — "who had what, when" has to survive the withdrawal or the audit trail has a
hole in it. Pass `include_inactive=True` to `grants_for` to see the history.

Pass an explicit `now=` to make a test deterministic:

```python
store.get_principal("bob", now=datetime(2026, 6, 1, tzinfo=UTC))
```

### Per-argument grants

Constraints decide *which arguments* a principal may pass and *which defaults* to inject when
they pass none:

```python
from sentrykit.constraints import ArgumentConstraint

store.grant(
    GrantSpec(
        principal=EntityRef("User", "bob"),
        kind="constraint",
        subject="region",
        action='Action::"tool.lookup"',
        constraint=ArgumentConstraint(allow=("eu-west",), default="eu-west",
                                      policy="grant-region"),
    )
)
```

Use `action="*"` for a constraint that applies to every action; an action-specific entry
refines it. See [Concepts](concepts.md) for how the filter and default injection behave.

## Composing several grant stores

```python
install(policy_source="file://./policies", grant_store=["memory://tenant-a", "memory://tenant-b"])
```

When **every** store declares a namespace the composite routes by it. Otherwise it merges by
precedence: earlier stores win per field, and roles and parents are unioned.
