# Audit & compliance

sentrykit emits one hash-chained record per authorization decision — allow *and* refusal —
and per admin grant mutation. The yearly audit report is meant to be a query over that
stream, not an afternoon of reading logs.

The audit log is **not** the operational log. `logging` output is ephemeral, may be verbose,
and never contains sensitive values. The audit stream is a data product: masked before it is
written, hash-chained, and pinned to the exact policy logic that produced it.

## Turning it on

Nothing is written unless a sink is configured — a library must not start writing files
merely because it was imported.

```python
from sentrykit import install

install(policy_source="file://./policies", audit_sink="jsonl://./var/audit.jsonl")
```

or by environment:

```bash
SENTRYKIT_AUDIT_SINK=jsonl://./var/audit.jsonl
SENTRYKIT_HMAC_KEY=...             # required before anything asks for hmac masking
SENTRYKIT_MASK_DEFAULT=hmac        # redact | partial | hmac | tokenize
```

## What a record contains

```python
from sentrykit.stores import InMemoryAuditSink

sink = InMemoryAuditSink()
install(POLICIES, entities=[...], audit_sink=sink)

with establish(Principal(id="alice", roles=("support",)), channel="agent"):
    look_up(account="ACCT-4417-9930")

record = sink.records[-1]
```

| Group | Fields | Why it is there |
| --- | --- | --- |
| Identity | `record_id`, `sequence`, `timestamp`, `invocation_id`, `kind` | `invocation_id` is shared with the Cedar result, the `_authz` envelope and the operational logs, so the three cross-reference by id and never by copying payloads. |
| Principal | `principal` (a `PrincipalSnapshot`: uid, roles, parents, attributes, constraints) | A **snapshot**, not a reference. Roles get revoked and attributes get corrected; a record that merely pointed at a principal would silently start describing a different one. |
| Request | `action`, `resource`, `callable_name`, `channel`, `environment` | |
| Outcome | `decision`, `outcome`, `reason` | `outcome` is finer than allow/deny: `denied`, `no-valid-arguments`, `default-unavailable`, `validation-failed`, `arguments-rejected`, `engine-error`. All are denials to the caller and completely different events to an auditor. |
| Arguments | `proposed`, `processed`, `rejected`, `defaults_applied`, `signature_defaults` | What was asked for, what the policy decided and passed, what it refused and why. A narrowed call is recorded as completely as a refused one, because "it ran, with these arguments rather than those" is a different fact from "it ran". `signature_defaults` names the governed parameters the *callable's* own default filled — policy checked that value and accepted it, and `processed` does not carry it, so the two sources stay distinguishable. |
| Policy | `obligations`, `determining_policies`, `provenance`, `policy_set_hash`, `engine_errors` | `policy_set_hash` pins the logic so a decision replays; `provenance` says which source and which artifact each determining policy came from. |
| Integrity | `masked`, `prev_hash`, `record_hash`, `dropped_since_last_write` | The first three are what `verify_chain` reads. The last is what the chain cannot tell you: how many records were built and then refused by the sink before this one landed. |

For the call above:

```python
record.determining_policies   # ('support-may-look-up',)
record.obligations            # ('hmac:account', 'notify:secops')
record.masked                 # {'account': 'hmac'}
record.proposed               # {'account': 'hmac:9aceb229b6349cc0807f99047180c19e'}
record.provenance             # ({'cedar_id': 'policy0', 'policy_id': 'support-may-look-up',
                              #   'effect': 'permit', 'source': 'inline', ...},)
```

The callable received `ACCT-4417-9930`. The sink never did.

Masking reaches the principal's own constraints too, and this is easy to miss: an allow-set
*enumerates* values, so a record that named one in the clear would be publishing every
identifier that principal may reach — including peers they never asked for — on every decision.
So for each argument the plan covers, the `allow` members, the `deny` members and the `pattern`
inside `record.principal.constraints` are masked with the same strategy and the same key as the
argument itself:

```python
record.principal.constraints['Action::"tool.lookup"']['account']
# {'allow': ['hmac:9aceb229b6349cc0807f99047180c19e'], 'required': False, 'has_default': True}
```

Because the key is the argument name rather than the rule name, the digests still line up, and
*"was what the caller proposed one of the values they were permitted to pass"* is still a
question you can answer from the record alone:

```python
record.proposed["account"] in record.principal.constraints[action]["account"]["allow"]
```

`minimum` and `maximum` are **not** masked. A bound is a rule rather than a value — it
identifies nobody, and it is usually the thing you came to read.

One gap worth knowing about: a **mutation** record is not masked. A grant write has no
determining policies and no protected callable, so nothing declares which of its fields are
sensitive, and an `attribute` grant's value and the constraint it carries reach the sink as
written. Keep that in mind when choosing who can read the audit store.

`rejected` is where a narrowed call becomes reconstructable. It carries one entry per argument
that did not survive, whatever refused it: a value the caller proposed that violated a rule, a
value bounded by an [argument ceiling](policies.md#argument-ceilings) declared in reviewed
policy text, and a default that was *withheld* because it did not satisfy the constraint it
belongs to. Each entry names the rule it broke and, where the constraint records one, the id
of the policy or grant that carried it — a ceiling always records one — so "why did this call
run with `limit=100` when the caller asked for 500" is answered out of the record rather than
by reconstructing the policy set as it stood that day.

A withheld default reads differently from the other two. The value policy would have supplied
was itself refused by its own constraint, so the argument was left with no value at all: the
callable's own default applied, or the call was refused for a missing required argument.

## Masking runs before the write

This is the invariant the rest of this page rests on: anything written to an
append-only store is permanent, so a raw sensitive value there cannot be withdrawn, and
masking at read or report time is too late by definition.

`AuditTrail` is the only thing in sentrykit that calls `sink.write()`, and it masks on the
way in. That is a structural property, not a convention — a unit test scans the source tree
and fails if any other module writes to a sink.

The `redaction` setting does **not** disable it. `redaction` governs the
caller-facing `_authz` envelope and the operational logs; the immutable write is the one
place masking must not be configurable away.

### Four strategies

| Strategy | Result | Use it when |
| --- | --- | --- |
| `redact` | `[redacted]` | The value has no analytical use at all. |
| `partial` | `**********9930` | A human needs to recognize a record. A value at or below `keep` characters is masked *completely* — short values are exactly where a partial mask leaks the whole thing. |
| `hmac` | `hmac:9aceb229...` | **The default.** The only strategy that lets an auditor say "the same account appears in these fourteen decisions" without the store ever holding the account number. The field name is bound into the digest, so the same value under two argument names does not collide. |
| `tokenize` | `token:...` | Reversible, via a vault that is *not* the audit store — so a subject-erasure request can drop the mapping and leave the chain intact but no longer resolvable. |

Plain hashing is not offered. A customer id has too little entropy to survive an unkeyed
digest, so `hmac` refuses to run without `SENTRYKIT_HMAC_KEY` rather than degrade quietly.

### Choosing a strategy per field

Three ways, most specific first.

**A policy obligation** — reviewed logic, so it wins:

```
@id("support-may-look-up")
@obligations("hmac:account, notify:secops")
permit (principal in Role::"support", action == Action::"tool.lookup", resource == Tool::"accounts");
```

**A signature annotation** — the developer's declared default:

```python
from typing import Annotated
from sentrykit import Sensitive, protect


@protect(action='Action::"tool.lookup"', resource='Tool::"accounts"')
def look_up(account: Annotated[str, Sensitive()], note: str = "") -> dict[str, object]:
    return {"account": account, "note": note}
```

`Sensitive()` means "sensitive, use the configured default"; `Sensitive("redact")` names one.

**The configured default**, for anything an obligation named with the bare `mask:` verb.

Masking is applied by field name across `proposed`, `processed`, `defaults_applied`, every
rejected argument's `value`, the principal snapshot's `attributes`, and the environment. The
rejected-argument case matters more than it looks: the argument was refused, but the value
the caller proposed is still attached to explain why.

Obligations whose verb is not a masking verb — `notify:secops`, `justify` — are carried
through on the record and the envelope for your application to discharge.

## The hash chain

Each record's hash covers its content **and** its predecessor's hash, so editing any record
invalidates every record after it.

```python
from sentrykit.audit import verify_chain

verify_chain(sink.records)      # ChainVerdict(ok=True, broken_at=None, reason=None)
```

`verify_chain` checks two things, because they catch different attacks:

- **re-hashing** each record catches one that was *edited*;
- **link and sequence checking** catches one that was *deleted*, which would otherwise leave
  every surviving record individually valid.

A `JsonlAuditSink` can verify its own file:

```python
from sentrykit.stores import JsonlAuditSink

with JsonlAuditSink("./var/audit.jsonl") as sink:
    verdict = sink.verify()
    if not verdict.ok:
        raise SystemExit(f"audit log broken at record {verdict.broken_at}: {verdict.reason}")
```

### An intact chain is not a complete log

These are different claims, and the chain can only make the first one. The chain advances only
on a write that *landed*, so if the sink refuses a record — a full disk, a network partition —
the records written either side of that gap link to each other perfectly and `verify_chain`
returns `ok=True` across it.

So a refused record is admitted by the next one that lands:

```python
record.dropped_since_last_write   # 3
```

Three records were built, masked, and never stored. The decisions they described still
happened. The count is inside `record_hash`, so it cannot be stripped without breaking the
record it sits on, and `audit-report` sums it over the window:

```text
## Tamper evidence

- Records whose own hash recomputes: 412 of 412.
- Chain: intact across the records that were written — but this window is **incomplete**, and
  the chain cannot show that.
- Records lost: 3. The sink refused that many records, which were built and masked and never
  stored. The decisions they described still happened, and nothing here says what they were.
```

A record with nothing to admit omits the field from the data it hashes, so logs written before
this existed verify unchanged. The reverse is not true: a record carrying a count cannot be read
by an older install, so upgrade readers before writers.

One limit worth knowing: the count lives in memory until a record lands, so a process that dies
while its sink is down takes its unreported count with it. This narrows the window in which a
loss is invisible rather than closing it.

A refusal that could not be recorded also carries the failure on the exception, so the boundary
answering the caller can say so:

```python
except AuthzDenied as denied:
    if denied.audit_failure is not None:
        ...  # correct refusal, and nothing in the trail will show it happened
```

That reaches the error under `fail_mode="closed"`. Under `fail_mode="open"` the trail absorbs
the failure and the call proceeds, which is what the count on the next record is for.

This is **detection, not prevention**. Preventing a rewrite is the storage layer's job — S3
Object Lock, WORM media — and no such backend ships today. Write one against the `AuditSink`
Protocol and the core will not be able to tell it from the built-ins; see
[plugins](plugins.md). The chain is what tells you the prevention failed.

### The JSONL sink is single-writer, by design

One file has exactly one writing process. That is not a limitation being papered over:
`record_hash` depends on `prev_hash`, so a writer must know the file's tail, and that state
cannot be shared across processes without a distributed lock.

**Threads inside that one process are fine.** The chain's own state lives on the trail, not on
the sink, so that is where it is protected: a decision takes a lock, links its record, writes
it, and advances the chain before releasing. Concurrent requests — Flask with `threaded=True`,
gunicorn's threaded workers, waitress, or FastAPI's threadpool for a sync endpoint — produce a
chain that links and sequence numbers that neither repeat nor skip.

The cost is that audit writes are serialized per trail. That is free for the in-memory sink and
for a plain `jsonl://`, which serialized its own writes anyway; with
`jsonl://path?fsync=true` it means every decision in the process queues behind that durability
call. If you need both per-record `fsync` and concurrency, give each writer its own sink.

The sink holds one handle open, serializes writes behind a lock, and opens with
`newline="\n"`. All three are forced by measurement rather than taste — on Windows,
`open(path, "a")` per write is not atomic (8 threads × 200 records produced 1346 of 1600
lines, three of them malformed), and default text mode writes CRLF, which would make the same
record hash differently per platform.

`fsync` costs about 3.7 ms per record against 0.007 ms for a flush, so it is opt-in
(`jsonl://path?fsync=true`). A flush already survives process death; only a machine crash
loses it.

## The yearly report is a query

The point of a structured, queryable decision log is that the audit report is not an
afternoon of reading it. `sentrykit audit-report` windows the sink and writes markdown:

```bash
sentrykit audit-report --from 2026-01-01 --to 2026-12-31     --out audit.md --sink jsonl://./var/audit.jsonl
```

With `--sink` omitted it uses `SENTRYKIT_AUDIT_SINK`; with `--out` omitted it writes to
stdout. `--principal`, `--action` and `--top` narrow it further.

Markdown rather than PDF, deliberately: it is diffable, it renders in every forge and doc
site, and it costs no dependency. Run it through whatever converter you already have if a PDF
is what your auditor wants.

### `--to` includes the day you named

`AuditWindow` bounds are **half-open** — `start` inclusive, `end` exclusive — so adjacent
windows tile a log without counting a record twice. But an operator writing `--to 2026-12-31`
means "including that day", so a **bare date** is nudged one day forward. A value carrying a
time is used exactly, because someone who wrote one meant it. The report heading echoes what
you typed; the header line under it states the bound that was actually queried, marked
exclusive.

### It aggregates by outcome, not by allow/deny

```markdown
## Outcomes

| Outcome | Count |
| --- | ---: |
| allowed | 4 |
| denied | 3 |
```

`allow`/`deny` is the wrong axis for a report. It folds six materially different refusals —
`denied`, `no-valid-arguments`, `default-unavailable`, `validation-failed`,
`arguments-rejected`, `engine-error` — into one bucket, and both admin mutations (`granted`,
`revoked`) into the other. An auditor asking "how often did a call fail validation" could
never get that back out. Mutations get their own section for the same reason.

The report also counts **determining policies**, which is the column that answers *which rule
is actually doing the work*, and **obligations raised**, which is how you check that
`notify:secops` was discharged as often as it was demanded.

### Tamper evidence in the report

```markdown
## Tamper evidence

- Records whose own hash recomputes: 7 of 7.
- Chain: intact across the window.
```

Two different claims, because a filter changes what is provable. Re-hashing each record
individually is always meaningful. The **chain** is only checked when the window applies no
identity filter: with `--principal` set, the matched records are a non-contiguous slice of the
chain, and a break there would mean "filtered", not "tampered". In that case the report says
the chain was not checked rather than reporting a break it cannot interpret.

### Building a report in-process

`build_report` is pure — no sink, no clock — so a report over a known set of records is
exactly assertable:

```python
from datetime import UTC, datetime

from sentrykit import AuditWindow
from sentrykit.cli import build_report, render_markdown

window = AuditWindow(start=datetime(2026, 1, 1, tzinfo=UTC),
                     end=datetime(2027, 1, 1, tzinfo=UTC))
report = build_report(sink.query(window), window=window, sink=sink.name)

report.by_outcome        # {'allowed': 4, 'denied': 3}
report.by_policy         # {'rbac-required-role': 3, 'break-the-glass': 1, ...}
document = render_markdown(report)
```

## Admin mutations are audited too

A grant is as auditable as the call it later permits, so `AuditTrail.record_mutation` writes
one record per change, with `kind="mutation"` and `outcome` of `granted` or `revoked`. The
`sentrykit grant` and `sentrykit revoke` commands go through the governed path, so an allowed
mutation leaves **two** records — the decision that permitted it, then the mutation itself —
and a refused one leaves the refusal alone. See [policies](policies.md#administering-grants).

## When the sink is down

`fail_mode` arbitrates. Under `closed` — the default — a sink that cannot accept a record
raises `AuditUnavailable` and the governed call is refused: an action nobody can prove
happened is an action that should not have happened. Under `open` the failure is logged at
`ERROR` and the call proceeds.

One asymmetry worth knowing: a sink failure while recording a *refusal* is logged and
swallowed. The call is already being refused, and replacing a precise `AuthzDenied` with an
operational error would take away the answer the caller actually needs.

## Reading records back

```python
from datetime import UTC, datetime
from sentrykit import AuditWindow

window = AuditWindow(
    start=datetime(2026, 1, 1, tzinfo=UTC),
    end=datetime(2027, 1, 1, tzinfo=UTC),
    decision="deny",
    limit=500,
)
for record in sink.query(window):
    ...
```

An empty window matches everything. Filtering lives on the window rather than in each sink,
so a third-party backend can push down what it can and lean on `AuditWindow.matches` for the
rest without the semantics drifting per backend.

A fan-out composite queries its **first** sink only. De-duplicating across sinks would
silently hide a divergence between them, which is exactly what an auditor needs to see.

## Fanning out to several sinks

```python
install(
    policy_source="file://./policies",
    audit_sink=["jsonl://./var/audit.jsonl?on_error=primary-durable", "memory://"],
)
```

- `primary-durable` (default) — the first sink must succeed; failures in the others are
  logged and swallowed, so a replica being down does not refuse production traffic.
- `all-or-nothing` — every sink is attempted and any failure is reported. Note that this is
  not a transaction: sinks that already accepted the record keep it. The guarantee is "you
  will be told", not "nothing was written".
