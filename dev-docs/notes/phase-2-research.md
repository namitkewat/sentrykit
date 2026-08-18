# Phase 2 — research notes

Findings verified against the **actually installed** `default` pixi environment (Python
3.13.15, cedarpy 4.8.7) on 2026-08-18, plus throwaway `pixi exec` environments for Python
3.11.15 and 3.12.13. Everything below was confirmed by running code, not read from
documentation. Phase 1's findings are in `phase-1-research.md` and are not repeated.

---

## 1. `importlib.metadata.entry_points()` across 3.11 – 3.13

Probed the same script on all three interpreters. The selectable call is uniform; the
*container type* is not.

| | 3.11.15 | 3.12.13 | 3.13.15 |
| --- | --- | --- | --- |
| `entry_points` return annotation | `EntryPoints \| SelectableGroups` | `EntryPoints` | `EntryPoints` |
| `entry_points(group=...)` returns | `EntryPoints` | `EntryPoints` | `EntryPoints` |
| `EntryPoints` MRO | `EntryPoints → DeprecatedList → list` | `EntryPoints → tuple` | `EntryPoints → tuple` |
| `repr` of an empty result | `[]` | `()` | `EntryPoints(())` |
| `.select(...)`, `.names`, `len()`, iteration | yes | yes | yes |
| unknown group | empty, never raises | empty | empty |
| `entry_points()["group"]` | `KeyError` + `DeprecationWarning` | `KeyError` | `KeyError` |
| `EntryPoint` fields | `name value group module attr extras dist load() matches()` | same | same |
| `ep.dist` populated | yes | yes | yes (`ep.dist.name`, `ep.dist.version`) |

### Consequences for `registry.py`

1. **Always pass `group=`.** The bare `entry_points()` call is the only shape that differs
   across versions (3.11 hands back `SelectableGroups`), and the mapping interface is dead
   on every supported version. `entry_points(group=...)` is the one spelling that behaves
   identically on 3.11, 3.12 and 3.13.
2. **Treat the result as an iterable, nothing more.** It is a `list` subclass on 3.11 and a
   `tuple` subclass on 3.12+; anything that concatenates it, hashes it, or relies on its
   `repr` is a version bug waiting to happen. Iterate and build our own container.
3. **An unknown group is empty, not an error.** No `try/except KeyError` is needed around
   discovery, and a process with no plugins installed is not a special case.
4. `ep.dist.name` / `ep.dist.version` give free provenance for a discovered plugin — worth
   recording on the registry entry so an audit can say *which distribution* supplied a sink.
   `EntryPoint.dist` is typed `Distribution | None`, so read it defensively.
5. Discovery must stay **lazy**. `ep.load()` imports the plugin module; doing that at
   `import sentrykit` time would drag every installed backend into every process. Resolve on
   first miss in the in-process registry, then cache.

---

## 2. cedarpy 4.8.7 — `validate_policies`

```python
validate_policies(policies: str, schema: str | dict | Schema) -> ValidationResult
```

`ValidationResult` exposes exactly three members:

| Member | Type | Notes |
| --- | --- | --- |
| `validation_passed` | `bool` | |
| `errors` | `list[ValidationError]` | each has `.policy_id` and `.error` |
| `id_annotations_by_policy_id` | `dict[str, str]` | generated id → that policy's `@id` |

Behaviour confirmed:

- **It never raises.** Unparseable policy text comes back as
  `ValidationError(policy_id='', error='Policy parse error: ...')`; an unparseable *schema*
  comes back as `ValidationError(policy_id='', error='Schema parse error: ...')`. So
  `FilesystemPolicySource` must inspect `validation_passed`, not rely on an exception, and
  translate a failure into `ConfigurationError` itself.
- An unknown action produces two errors for one policy (`unrecognized action` plus `unable to
  find an applicable action given the policy scope constraints`) — error count is not policy
  count; group by `policy_id` before reporting.
- `schema=` accepts a pre-parsed `cedarpy.Schema` handle, so validation and evaluation can
  share one parse.
- `Schema.from_str` accepts **Cedar schema syntax only** — handing it the JSON schema form
  raises `ValueError: error parsing schema: unexpected token '{'`. The filesystem source
  therefore reads `*.cedarschema` text.

This closes the Phase 5 question: `sentrykit policy validate` needs no Cedar CLI.

---

## 3. cedarpy exposes **all** policy annotations — via JSON, not the handle

This is the finding that decides how obligations are represented.

`cedarpy.PolicySet` is opaque: its only members are `from_str`, `from_json_str`,
`with_added_str`, `with_linked`, `with_linked_batch`, `without_linked`, `templates`. There is
no way to walk its policies.

But `policies_to_json_str(text)` — note it takes **`str`, not a `PolicySet` handle** — emits
every annotation:

```json
{"templates": {}, "templateLinks": [],
 "staticPolicies": {
   "policy0": {"effect": "permit", "principal": {...}, "action": {...}, "resource": {...},
               "conditions": [],
               "annotations": {"id": "btg-read", "obligation": "notify:secops,justify",
                               "risk": "high"}}}}
```

Meanwhile a decision's `diagnostics.reasons` carries the **same generated ids**
(`["policy0"]`), and `diagnostics.id_annotations_by_reason` carries only the `@id`.

So the join is: *parse the policy text once at load time into an annotation index keyed by
generated id; at decision time, look up each determining policy in that index.* Confirmed
end to end in the probe.

### Generated-id stability — confirmed, with the rule that makes it safe

`policyN` ids are **positional in the text**. Concatenating three fragments A+B+C yields
`policy0`, `policy1`, `policy2` in that order, and `PolicySet.with_added_str` continues the
same numbering (A then +B → the forbid from B is reported as `policy1`). Therefore:

> The annotation index must be built from **exactly the text the `PolicySet` was built
> from**, in the same order. `CompositePolicySource` fixes a deterministic source order and
> concatenates once; the index and the engine are derived from that one string.

`PolicyEngine` already retains that text on `.policies`, so no change to `cedar.py` is
needed.

### Annotation syntax limits (probed)

| Form | Result |
| --- | --- |
| `@obligations("a,b")` | fine — value is a plain string |
| the same key twice on one policy | `ValueError: duplicate annotation: @obligation` |
| `@sentrykit.obligation(...)` (dotted key) | `ValueError: unexpected token '.'` |
| `@sentrykit_obligations(...)` (underscored) | fine |
| `@obligations("")` | fine, value `""` |
| `@obligations` (no value) | fine, value **`None`** |
| policy with no annotations at all | `"annotations"` is **`None`**, not `{}` |

The last two are parser traps: the index builder must treat a missing annotation block and a
valueless annotation as absent rather than assume `dict`/`str`.

Because a key cannot repeat, obligations are carried as **one comma-separated
`@obligations(...)` annotation**, not as repeated annotations.

### Forbid-override across a union — confirmed

Union of a permit (A) and a conditional forbid (B): with the condition true, the decision is
`Deny` naming `b-forbid`; with it false, `Allow` naming `a-permit`. Cedar's forbid-wins
semantics survive the union unchanged, which is why `CompositePolicySource` needs **no**
source precedence: an override is expressed as a `forbid`, and ordering sources cannot
change a decision.

Duplicate `@id` values across two sources parse without complaint — Cedar does not enforce
uniqueness. That makes `determining_policies` ambiguous, so **namespacing declared ids is
sentrykit's hygiene requirement**, enforced by the composite, not by Cedar.

---

## 4. Append-only JSONL on Windows — the naive design is broken

Probed on `win32` / `os.name == "nt"`. `fcntl` is absent (`msvcrt` is present).

### 4.1 Text-mode append rewrites the bytes

```python
open(path, "a", encoding="utf-8").write('{"n":1}\n')   # → b'{"n":1}\r\n'
open(path, "a", encoding="utf-8", newline="\n").write(...)  # → b'{"n":1}\n'
```

A hash chain is over *bytes*. Left at the default, the same record hashes differently on
Windows and Linux and an external verifier disagrees with the writer. **`newline="\n"` is
mandatory**, not a style preference.

### 4.2 `open(..., "a")` per write is **not** atomic on Windows — measured data loss

8 threads × 200 records, each opening the file in append mode for its own write:

```
expected 1600 lines, got 1346, 3 malformed lines, json.loads() fails
```

Windows' CRT emulates append as seek-to-end + write, and the pair races. This is not a
theoretical caveat; a quarter of the records vanished. The same loop with **one shared handle
guarded by a `threading.Lock`** produced 1600/1600 lines in 0.01 s.

### 4.3 The chain already forces a single writer

`record_hash` depends on `prev_hash`, so a writer must know the tail of the file before it
can build the next record. That state cannot be shared between processes without a
distributed lock, so **single-writer-per-file is an invariant of the design**, not a
limitation being papered over. `JsonlAuditSink` therefore:

- holds one file handle open for the sink's lifetime, opened `"a"` with
  `encoding="utf-8", newline="\n"`;
- serializes `write()` with a `threading.Lock`;
- recovers `prev_hash` by reading the last line when it opens an existing file;
- documents that concurrent writers must use separate files (a `CompositeAuditSink` fan-out
  or a per-process path), and that multi-process durability is a job for the Phase 5 S3 /
  Iceberg backends.

### 4.4 `fsync` is a real cost — make it opt-in

| Mode | 200 records | per record |
| --- | --- | --- |
| `flush()` + `os.fsync()` | 0.743 s | **3.71 ms** |
| `flush()` only | 0.001 s | 0.007 ms |

3.7 ms on every authorization decision is not acceptable as a default for a pre-action gate.
`flush()` alone survives process death (the bytes are in the OS page cache); only a machine
crash loses them. `JsonlAuditSink` flushes always and fsyncs only when asked
(`jsonl://path?fsync=true`).

### 4.5 Two more Windows behaviours confirmed

- A file held open for append **can** be read concurrently — no sharing violation — so
  `query()` may read the file the sink is still writing.
- `os.replace()` over an existing file works, so rotation/compaction has a safe primitive if
  a later phase needs one.

---

## 5. Decisions taken for Phase 2 as a consequence

1. **Obligations are annotations on the determining policies.** `PolicySource.load()`
   returns a bundle that carries a per-policy provenance record — generated id, declared
   `@id`, effect, source, origin, annotations, parsed obligations — built from the exact
   policy text the `PolicyEngine` is constructed from. The Governor joins
   `CedarDecision.determining_policies` against that index and surfaces obligations from the
   determining **permit** policies only (a forbid's obligations belong to a denial record,
   not to a call that is proceeding). Recorded as ADR-012.
2. **The registry always calls `entry_points(group=...)`, lazily, and caches by name.**
   Built-ins register through the same decorator third parties use, so the two are
   indistinguishable.
3. **`CompositePolicySource` concatenates in a fixed source order and namespaces declared
   ids** (`<source>/<id>`). No source precedence — an override is a `forbid`.
4. **`JsonlAuditSink` is single-writer, one open handle, lock-guarded, `newline="\n"`,
   flush-always / fsync-on-request.** Recorded as ADR-013.
5. **The audit write always masks**, regardless of the `redaction` setting; `redaction`
   governs the caller-facing envelope and the operational logs. ADR-007 makes an unmaskable
   WORM write the thing that must not be configurable away.
