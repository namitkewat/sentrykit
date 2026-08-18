# Quickstart

Everything below runs against the core: a policy set held in memory, one decorator, and no
framework. Guarding an HTTP route adds one line and changes none of it — see
[web frameworks](web-frameworks.md).

## Install

```bash
pip install sentrykit
```

## 1. Write the policy

Cedar policy logic lives in files under version control (ADR-005). For a first run a string
literal is fine.

```python
POLICIES = """
@id("support-may-search-orders")
permit (
  principal in Role::"support",
  action == Action::"tool.search_orders",
  resource == Tool::"orders"
);

@id("suspended-principals-are-forbidden")
forbid (principal, action, resource)
when { principal has suspended && principal.suspended };
"""
```

Always give a policy an `@id("...")` annotation. Cedar reports determining policies by
parser-generated ids (`policy0`, `policy1`, …) otherwise, and those shift the moment someone
inserts a policy above — which would quietly make your audit trail wrong.

## 2. Wire the engine

```python
from sentrykit import Entity, EntityRef, install

install(
    POLICIES,
    entities=[
        Entity(EntityRef("Role", "support")),
        Entity(EntityRef("Tool", "orders")),
    ],
)
```

`install` parses eagerly, so a malformed policy raises
[`ConfigurationError`](concepts.md#errors) here at startup rather than silently denying every
request for the rest of the process's life.

## 3. Protect a callable

```python
from sentrykit import protect


@protect(action='Action::"tool.search_orders"', resource='Tool::"orders"')
def search_orders(customer_id: str, region: str = "eu", limit: int = 100) -> dict[str, object]:
    return {"customer_id": customer_id, "region": region, "limit": limit}
```

`@protect` works on any callable — an HTTP handler, a background job, an agent tool — and
preserves the wrapped signature, so type checkers and framework introspection still see the
original function. It supplies the *action* and the *proposed arguments*. Who is acting comes
from somewhere else.

## 4. Say who is acting

```python
from sentrykit import ArgumentConstraint, ConstraintSet, Principal, establish

alice = Principal(
    id="alice",
    roles=("support",),
    constraints={
        'Action::"tool.search_orders"': ConstraintSet(
            arguments={
                "region": ArgumentConstraint(allow=("eu",), default="eu", policy="grant-eu-only"),
                "limit": ArgumentConstraint(minimum=1, maximum=50, default=10, policy="grant-page-size"),
            }
        )
    },
)

with establish(alice, channel="agent", request_id="req-1"):
    result = search_orders(customer_id="c-1", region="us", limit=500)
```

In a real application a *context provider* calls `establish` once at the framework boundary
and every protected callable below it — however deeply nested — is governed. Nothing has to
thread a principal through its signature.

## 5. Read what happened

Alice asked for `region="us"` and `limit=500`. Policy permits neither, so both were dropped
and replaced with her defaults. The call still ran, narrowed to what she is entitled to, and
says so:

```json
{
  "customer_id": "c-1",
  "region": "eu",
  "limit": 10,
  "_authz": {
    "decision": "allow",
    "action": "Action::\"tool.search_orders\"",
    "resource": "Tool::\"orders\"",
    "rejected": [
      {
        "name": "region",
        "rule": "allow-set",
        "reason": "Value is not one of the permitted values",
        "policy": "grant-eu-only"
      },
      {
        "name": "limit",
        "rule": "maximum",
        "reason": "Value is above the maximum of 50",
        "policy": "grant-page-size"
      }
    ],
    "defaults_applied": { "region": null, "limit": null }
  }
}
```

That is `summary` verbosity, the default: it names what happened without disclosing values.
At `verbose` the envelope also carries the principal, the processed arguments, the offending
values (`"us"`, `500`) and the real defaults. See [verbosity](concepts.md#verbosity).

The envelope is attached under `_authz` when the result is a mapping. For any other return
type the result is handed back untouched — rewrapping it would change your function's type —
and the envelope is available from `last_envelope()`, which is how the framework providers
attach it to an HTTP response.

## 6. Denials

```python
from sentrykit import AuthzDenied

mallory = Principal(id="mallory", roles=("guest",))

with establish(mallory):
    try:
        search_orders(customer_id="c-1")
    except AuthzDenied as exc:
        print(exc.determining_policies)  # [] -- nothing permitted it
```

A `forbid` names itself:

```python
sam = Principal(id="sam", roles=("support",), attributes={"suspended": True})

with establish(sam):
    try:
        search_orders(customer_id="c-1")
    except AuthzDenied as exc:
        print(exc.determining_policies)  # ['suspended-principals-are-forbidden']
```

And with no principal at all, the call is refused rather than run unguarded:

```python
search_orders(customer_id="c-1")  # NoContext
```

That last one is the rule worth internalizing: **forgetting to establish context fails
closed.** A missing provider surfaces immediately instead of leaving a silent hole.

## 7. Async, and threads

Async callables work identically:

```python
@protect(action='Action::"tool.search_orders"', resource='Tool::"orders"')
async def search_orders_async(customer_id: str) -> dict[str, object]: ...
```

The ambient principal follows `await` and `asyncio.to_thread` on its own. It does **not**
follow a bare `ThreadPoolExecutor.submit` — the worker thread starts from an empty context,
so every protected call inside it denies. Use `bind_context` there:

```python
from sentrykit import bind_context

executor.submit(bind_context(reconcile_orders, batch_id))
```

## Configuration

Settings come from `SENTRYKIT_`-prefixed environment variables or from `configure(...)`:

```bash
export SENTRYKIT_VERBOSITY=verbose
export SENTRYKIT_ARG_HANDLING=strict
```

```python
from sentrykit import configure, override_action

configure(verbosity="verbose")
override_action("tool.search_orders", arg_handling="strict")
```

| Setting | Values | Meaning |
| --- | --- | --- |
| `verbosity` | `off` / `summary` / `verbose` / `debug` | How much the `_authz` envelope discloses |
| `arg_handling` | `lenient` / `strict` | Drop a rejected argument, or refuse the call |
| `fail_mode` | `closed` / `open` | What an *engine failure* does — see [fail modes](concepts.md#fail-modes) |
| `redaction` | bool | Mask sensitive values before they leave the engine |
| `envelope_on_success` | bool | Attach an envelope to successful calls |

## Next

- [Concepts](concepts.md) — the pipeline, the two failure kinds, and why the caller proposes
  but the policy decides.
