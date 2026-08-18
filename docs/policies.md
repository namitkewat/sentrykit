# Policies & patterns

Cedar separates *policy logic* from *entity data*, and sentrykit leans on that split hard
(ADR-005):

- **Policy logic lives in files** under version control. It changes by review, and git
  history is the change-control evidence an auditor asks for.
- **Grants are data** in a mutable store. A role is a parent edge, a per-argument limit is an
  attribute, a time-boxed grant is a timestamp. "Add role" is CRUD — reviewed policy logic
  never changes at runtime.

A [policy pack](#the-shipped-policy-pack) ships with the library — RBAC, groups,
ownership, delegation, expiry, break-the-glass, separation-of-duties and JIT elevation — as
*data*, reachable through the same union as your own directory.

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

## The shipped policy pack

Eight patterns ship with sentrykit. They reach a governor as an ordinary policy source, so
there is nothing special about them:

```python
install(policy_source=["pack://", "file://./policies"])
```

The union namespaces their ids as `pack/<id>`, so an audit record says which artifact decided
a call. Note *where* that spelling appears: Cedar reports the raw `@id` it parsed, so a
decision's `determining_policies` reads `rbac-required-role`, while the record's `provenance`
carries `{"policy_id": "pack/rbac-required-role", "source": "pack", ...}`. The namespace is
sentrykit's hygiene applied to the index, not a rewrite of the policy text.

Drop the DSN and the pack is not there.

Take a subset when you want one:

```python
install(policy_source=["pack://rbac,ownership", "file://./policies"])
```

### Every pattern is attribute-driven

A shipped pack cannot know your role names, your resource types or your actions, so **none of
its policies name any**. Each one reads the shape of the request instead: the *resource*
declares what it requires, the *grant store* supplies the principal's edges and attributes,
and the *context* supplies `now`, `break_glass`, `on_behalf_of` and `justification`.

Adopting a pattern is therefore a matter of putting an attribute on an entity — which is
data, which is ADR-005 restated for the pack.

| Pattern | What it decides | Data it reads |
| --- | --- | --- |
| `rbac` | A principal holding the role the resource requires may act on it. | `resource.required_role` |
| `groups` | A member of the group the resource belongs to may act on it, at any depth. | `resource.group` |
| `ownership` | The owner of a resource may act on it; ownership is not inherited. | `resource.owner` |
| `delegation` | A principal may act on behalf of its delegator, but only within the delegated scope and only until the delegation lapses. | `principal.delegated_by`, `principal.delegated_actions`, `principal.delegation_expires`, `resource.required_role`, `context.on_behalf_of`, `context.now` |
| `expiry` | An entitlement window that refuses the call outside its bounds. | `principal.entitlement_starts`, `principal.entitlement_expires`, `context.now` |
| `break-glass` | An emergency-only resource is refused outright unless the caller raises the flag, and is then reachable only by a principal entitled to the emergency, carrying a justification. | `resource.emergency_only`, `resource.emergency_role`, `context.break_glass`, `context.justification` |
| `separation-of-duties` | A conflicting role is refused the resource outright, and nobody approves what they prepared themselves. | `resource.conflicting_role`, `resource.prepared_by` |
| `jit-elevation` | A principal holds an elevated role for a window, and is refused once the window closes. | `principal.elevation_role`, `principal.elevation_until`, `resource.required_role`, `context.now` |

Every timestamp is **epoch seconds**. `coerce_value` renders each `datetime` that way and the
engine injects `now` into the environment on every decision, so a TTL condition is a Cedar
integer comparison. Cedar has no ordering on strings, so an ISO timestamp could not be
compared at all.

```python
from sentrykit.policy import PATTERNS

PATTERNS["break-glass"].policy_ids
# ('emergency-resource-forbidden-without-flag', 'break-the-glass')
PATTERNS["break-glass"].requires
# ('resource.emergency_only', 'resource.emergency_role', 'context.break_glass',
#  'context.justification')
```

### Half the pack forbids

Five of the patterns contribute a `forbid`, and that is the half that does the containing:

- `delegation-outside-scope-forbidden` — without it, a delegated principal could reach the
  plain RBAC permit and ignore the scope it was delegated. The forbid is what makes a
  delegation *bound* an agent rather than merely add to it.
- `emergency-resource-forbidden-without-flag` — this is what makes an emergency-only resource
  emergency-only. It fires whenever the flag is absent, and forbid beats every permit.
- `entitlement-expired-forbidden`, `jit-elevation-expired-forbidden`,
  `sod-conflicting-role` — the same shape.

### Break-the-glass takes three things, not one

```python
with establish(ana, channel="web", break_glass=True, justification="incident 4471"):
    open_vault(item="master-key")
```

The principal must be in the resource's `emergency_role`, the caller must raise
`break_glass`, and the justification must be non-empty. A permit conditioned on the flag
alone would authorize **anyone**: the flag is caller-supplied and a Cedar `permit` needs no
base entitlement to fire. The permit carries `notify:secops` and `record:justification` as
mandatory obligations, so a call that proceeds this way cannot proceed quietly.

### The schema is opt-in

`pack.cedarschema` ships with the pack, but the loaded bundle does not carry it unless you
ask:

```python
install(policy_source=["pack://?schema=true", "file://./policies"])
```

A composite concatenates its members' schemas, and an engine built *with* a schema validates
every request against it — so a pack that contributed one by default would make every request
naming an action it had never heard of fail to parse, in an application that was working a
moment earlier. The pack's decisions are identical either way.

When you do opt in, your schema must declare only what the pack does not. Redeclaring `User`,
`Role`, `Group` or `Resource` is a Cedar schema parse error (`` `User` is declared twice ``).
Adding actions is safe — an action whose context is `{}` still type-checks against the pack's
`context has now` conditions.

### Time-boxed grants from a template

Cedar has policy templates, but `cedarpy` exposes no API for linking one, and an unlinked
template in a policy set is inert. `link_template` links on sentrykit's side and hands back
*both* halves of the fact: reviewable logic, and revocable data.

```python
from datetime import UTC, datetime
from sentrykit.policy import LinkedPolicySource, link_template, pack_template

link = link_template(
    pack_template("time-boxed-grant"),
    link_id="oncall-ana",
    principal='User::"ana"',
    resource='Resource::"paging"',
    expires_at=datetime(2026, 9, 1, tzinfo=UTC),
    granted_by="ops",
    reason="on-call rotation",
)

install(policy_source=["pack://", LinkedPolicySource([link])])
```

The generated policy carries the expiry as a condition, guarded so it validates cleanly:

```
@id("oncall-ana")
permit (
  principal == User::"ana",
  action,
  resource == Resource::"paging"
)
when { context has now && context.now <= 1788220800 };
```

`link.grant` is the matching `GrantSpec`, carrying the same expiry, so the grant is listed,
audited and revoked like any other.

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

## Administering grants

The admin surface is governed CRUD over the grant store — and because `Action::"admin.grant"`
is an ordinary Cedar action, it is **governed by the same engine it administers** and logged
into the same sink.

```bash
sentrykit grant 'User::"ana"' --role oncall --expires 2026-09-01     --reason "on-call rotation"     --store jsonfile://./var/grants.json --as 'User::"root"'

sentrykit grants 'User::"ana"' --store jsonfile://./var/grants.json
sentrykit revoke <grant-id> --reason "shift ended"     --store jsonfile://./var/grants.json --as 'User::"root"'
```

`--as` names the operator (or set `SENTRYKIT_ACTOR`). They are resolved through the grant
store like anyone else, so **an operator the store has never heard of is refused** — there is
no back door, and forgetting to configure the store surfaces immediately rather than as a
silent hole.

Write the policy that permits it, the same way you would for any other action:

```
@id("root-may-administer-grants")
permit (
  principal in Role::"admin",
  action in [Action::"admin.grant", Action::"admin.revoke"],
  resource == Resource::"admin.grants"
);
```

### The proposed grant is argument-filtered, not just gated

The command builds its `GrantSpec` from the **policy-processed** arguments, not from what you
typed. So a constraint on the operator decides *which* grants they may make:

```python
store.grant(GrantSpec(
    principal=EntityRef("User", "root"),
    kind="constraint",
    subject="subject",
    action='Action::"admin.grant"',
    constraint=ArgumentConstraint(allow=("oncall",), default="oncall",
                                  policy="grant-admin-scope"),
))
```

An operator who asks for `--role admin` now stores a grant of `oncall`, and the audit record
says so. That is the same proposes/decides split as everywhere else in the library, applied
to the surface that hands out authority.

### Two records, or one

An allowed mutation writes **two** audit records — the decision that permitted it, then the
mutation itself — and a refused one writes **one**, the refusal, leaving the store untouched.
`sentrykit grants` mutates nothing, is ungoverned, and writes none.

### Bootstrapping the first operator

There is a chicken and egg here, and it is deliberate: you cannot `sentrykit grant` yourself
into `Role::"admin"`, because the grant that would let you is itself governed. Seed the first
operator in provisioning code, where the store is an ordinary object:

```python
from sentrykit.stores import JsonFileGrantStore
from sentrykit.stores.base import GrantSpec

store = JsonFileGrantStore("./var/grants.json")
store.grant(GrantSpec(principal=EntityRef("User", "root"), kind="role", subject="admin",
                      granted_by="bootstrap", reason="initial operator"))
```

A CLI flag that skipped the gate for the first grant would be a back door that never closes.

## Composing several grant stores

```python
install(policy_source="file://./policies", grant_store=["memory://tenant-a", "memory://tenant-b"])
```

When **every** store declares a namespace the composite routes by it. Otherwise it merges by
precedence: earlier stores win per field, and roles and parents are unioned.
