# Web frameworks

sentrykit guards HTTP handlers with the same `@protect` decorator it guards everything else
with. The framework contributes one small object — a **context provider** — and nothing else
changes.

A provider does exactly two things:

1. **Establishes** ambient context at the request boundary: it turns the framework's request
   into a principal (via your auth) and an environment (`channel`, `request_id`), and releases
   both when the request ends.
2. **Renders** a refusal as an HTTP response carrying the `_authz` envelope.

Everything between those two points — the gate, argument filtering, default injection,
validation, the audit record — is the framework-agnostic core, unchanged.

```bash
pip install "sentrykit[fastapi]"
pip install "sentrykit[flask]"
```

## FastAPI

```python
from fastapi import FastAPI
from starlette.requests import Request

from sentrykit import install, protect
from sentrykit.integrations.fastapi import FastAPIProvider, protect_app
from sentrykit.stores.memory import InMemoryGrantStore

store = InMemoryGrantStore()          # seed roles and constraints into this
provider = FastAPIProvider(
    identify=lambda request: request.headers.get("x-user"),
    grants=store,
)
install(POLICY_TEXT, grant_store=store, context_provider=provider)

app = FastAPI()
protect_app(app, provider=provider)


@protect(action='Action::"orders.search"', resource='Tool::"orders"')
def search_orders(region: str, limit: int) -> dict[str, object]:
    return {"region": region, "limit": limit}


@app.get("/orders")
def list_orders(region: str | None = None) -> dict[str, object]:
    proposed = {"region": region} if region is not None else {}
    return search_orders(**proposed)
```

The route declares `region: str | None = None` and forwards only what the caller actually sent.
That is deliberate: an argument the caller omitted is the one policy fills in from their
defaults, so a route that substituted its own value first would leave nothing to inject — an
absent argument has to stay expressible at the boundary. The bounds those defaults sit inside
come from the principal's grants, and a reviewed policy may declare an
[argument ceiling](policies.md#argument-ceilings) that intersects with them.

`protect_app` does two things, and each is available on its own:

| Call | What it adds |
| --- | --- |
| `protect_app(app, provider=...)` | Both of the below. |
| `app.add_middleware(SentrykitMiddleware, provider=...)` | Establishment for every request. |
| `install_error_handlers(app, provider)` | One handler per sentrykit error. |

### Establish in middleware, or in an `async` dependency — never in a sync one

`SentrykitMiddleware` is pure ASGI. It establishes before calling the rest of the stack and
releases in a `finally`, so the principal reaches **both** `async def` and `def` routes: a
sync route runs in an AnyIO worker thread, and `anyio.to_thread.run_sync` copies the context
into it.

For an app that governs only part of its surface, `context_dependency()` is the route-scoped
form:

```python
from fastapi import Depends
from sentrykit.integrations.fastapi import context_dependency

@app.get("/orders", dependencies=[Depends(context_dependency())])
def list_orders() -> dict[str, object]: ...
```

!!! warning "A synchronous dependency cannot establish context"
    A `def` dependency runs in its own AnyIO worker thread with a *copy* of the context. Its
    `establish()` is discarded the moment it returns, and every protected call downstream then
    fails closed. sentrykit ships no sync-dependency form, so there is nothing to reach for by
    mistake — but if you write your own establishment hook, it must be `async`.

One further difference: the dependency's teardown unwinds *below* Starlette's
`ExceptionMiddleware`, so ambient context is already released by the time a refusal is
rendered. That costs nothing, because refusals are rendered from the exception rather than from
ambient state.

!!! note "Do not declare a `response_model` on a governed route"
    The engine attaches the `_authz` envelope to the returned mapping. A `response_model`
    validates the return value against a schema that does not mention `_authz` and strips it.

## Flask

```python
from flask import Blueprint, Flask, request

from sentrykit import install
from sentrykit.integrations.flask import FlaskProvider, protect_app

provider = FlaskProvider(
    identify=lambda request: request.headers.get("x-user"),
    grants=store,
)
install(POLICY_TEXT, grant_store=store, context_provider=provider)

app = Flask(__name__)
protect_app(app, provider=provider)


@app.get("/orders")
def list_orders() -> dict[str, object]:
    proposed = {}
    region = request.args.get("region")
    if region is not None:
        proposed["region"] = region
    return search_orders(**proposed)
```

`protect_app` registers three things: a `before_request` hook that establishes, a
`teardown_request` hook that releases, and the error handlers. Flask runs them in the order
`before_request → view → errorhandler → teardown_request`, so a refusal is rendered while the
principal is still ambient and released immediately afterwards.

### Governing one blueprint

`protect_blueprint` scopes all three to a single blueprint, so an ungoverned surface can live
beside a governed one under the same app:

```python
from sentrykit.integrations.flask import protect_blueprint

api = Blueprint("api", __name__, url_prefix="/api")
protect_blueprint(api, provider=provider)
app.register_blueprint(api)
```

Routes outside `api` never see the hooks.

## Identity: you supply the id, the grant store supplies the authority

The `identify` callback receives the framework's request and returns one of:

| Return value | Meaning |
| --- | --- |
| `str` | A principal id, read as `User::"<id>"` and resolved through `GrantStore.get_principal`. |
| `EntityRef` | The same, with the entity type named explicitly. |
| `Principal` | Used as-is. The escape hatch for an app with no grant store. |
| `None` | Unauthenticated. Nothing is established, and every protected call in the request fails closed. |

That split is the point. Your web layer answers *who is this*; the grant store answers *what
may they do* — roles, group edges, per-argument constraints and expiries, all resolved before
the principal reaches the decision path. Neither half needs to know about the other.

An id the store has never heard of behaves exactly like no id at all: the request proceeds
unauthenticated and is refused at the first protected call, which is a refusal the caller can
be shown rather than a stack trace at the boundary.

A provider built from a DSN (`fastapi://`, `flask://`) has no application auth to call into, so
it reads a header instead — `x-sentrykit-principal` by default, or `?header=x-user`. That suits
an example app or a service behind a gateway that has already authenticated the caller, and
nothing else.

## What the provider establishes

| Key | Value |
| --- | --- |
| `channel` | `"http"`. Policies read it as `context.channel`, so a rule can say *not over HTTP*. |
| `request_id` | The caller's `X-Request-ID` when they send one, otherwise a fresh UUID4. Shared by the decision, the operational logs and the audit record. |

Anything else your policies need — auth strength, tenant, a break-the-glass flag — comes from
the `environment` callback, which is merged on top:

```python
FastAPIProvider(
    identify=...,
    environment=lambda request: {"auth_strength": request.headers.get("x-auth-strength", "weak")},
)
```

## Refusals

Most rejected arguments never reach a status code. Under the default `arg_handling="lenient"`
an over-broad value is rejected, the principal's own default fills the gap, and the route
returns its ordinary response with the rejections named in the `_authz` envelope; the statuses
below are for a call that cannot proceed at all.

Every sentrykit error maps to one status, identically on both frameworks:

| Error | Status |
| --- | --- |
| `AuthzDenied`, `NoContext` | **403** |
| `ArgumentRejected` (only under `arg_handling="strict"`), `NoValidArguments`, `DefaultUnavailable` | **400** |
| `ValidationFailed` | **422** |
| `ConfigurationError`, `AuditUnavailable`, any other `SentrykitError` | **500** |

A missing principal is a 403 rather than a 401 on purpose: sentrykit is not the authenticator
and has no `WWW-Authenticate` challenge to offer, so claiming otherwise would send callers to a
scheme it knows nothing about.

The body is:

```json
{
  "detail": "The policy denied action Action::\"orders.search\".",
  "error": "AuthzDenied",
  "_authz": {
    "decision": "deny",
    "reason": "The policy denied action Action::\"orders.search\".",
    "action": "Action::\"orders.search\"",
    "resource": "Tool::\"orders\""
  }
}
```

`verbosity` trims `_authz` exactly as it trims the success envelope:

| Verbosity | Refusal body |
| --- | --- |
| `off` | `{"detail": "Forbidden"}` — the status phrase and nothing else. No `error`, no `_authz`. |
| `summary` | The decision, the reason, the action and resource, and the *names* and reasons of rejected arguments. No values. |
| `verbose` | Adds the offending values, the `allowed` set a caller needs in order to retry, and the input pydantic rejected. |
| `debug` | Adds `determining_policies` and the Cedar engine errors behind a refusal. |

Refusal bodies are built **from the exception**, never from ambient state. A sync route runs in
a worker thread whose context copy is discarded on return, so `last_envelope()` is simply empty
by the time a handler runs — and every sentrykit error already carries the structured detail
the envelope needs.

## Protected callables that are not routes

This is the part that makes the decorator worth having. The gate is on the **callable**, not on
the URL:

```python
@protect(action='Action::"orders.summarize"', resource='Tool::"orders"')
def summarize_orders() -> dict[str, object]:
    return {"summary": "3 open orders"}


@app.get("/orders/summary")          # this route is NOT protected
def summary() -> dict[str, object]:
    return summarize_orders()        # this call is
```

The handler mentions no authorization at all. `summarize_orders` is authorized against the same
ambient principal the provider established, whether it is called from a route, from a service
layer three frames deeper, or from a background job.

!!! warning "Thread-pool offload needs `bind_context`"
    Ambient context follows `await` and `asyncio.to_thread`, and the frameworks' own sync-route
    offload. It does **not** follow a bare `ThreadPoolExecutor.submit`. Wrap those calls with
    `sentrykit.bind_context(fn, *args)`, or the principal is lost and the call fails closed.

## The lifecycle rule: establish at the boundary, release at teardown

Both providers release the context they established — `SentrykitMiddleware` in a `finally`,
`FlaskProvider` in `teardown_request`. This is correctness, not tidiness.

Flask serves a request on a pooled worker thread, and its test client serves one in the
caller's own context. Without the release, the `ContextVar` established for request *N* is
still ambient after it ends — and anything running on that thread outside a request, a
background task or a scheduled job, would then act as request *N*'s principal.

`release()` is total: it resets the scope when there is one, clears the context outright when
there is not, and drops the last envelope either way. If you drive the hooks by hand, always
pair them:

```python
scope = provider.establish(request)
try:
    ...
finally:
    provider.release(scope)          # always, including on the error path
```

## Wiring by DSN

Both providers are registered under the `sentrykit.context_providers` entry-point group, so a
process can be configured entirely from strings:

```python
install(policy_source="file://./policies", grant_store="memory://", context_provider="fastapi://")
```

`Governor.context_provider` then holds the result, which is where `SentrykitMiddleware(app)`,
`context_dependency()` and `protect_app(app)` look when you give them no provider of their own.
A third-party framework adapter publishes into the same group and is reachable the same way —
see [Plugins & extensions](plugins.md).

!!! note "Flask resolves its provider at wiring time"
    Flask hooks are registered as bound methods, so `protect_app` / `protect_blueprint` resolve
    the default provider when you call them: `install(context_provider=...)` must come first.
    The FastAPI middleware resolves per request and has no such ordering constraint.

## Runnable examples

`examples/fastapi_app/` and `examples/flask_app/` are one orders-and-refunds desk built twice.
Seven routes, seven protected callables, three principals, one `service.py` with no framework
import in it, one set of grant data, and one reviewed policy directory — shared verbatim
between the two apps, down to the URLs. Only the boundary wiring differs: `protect_app` over
the whole FastAPI app, `protect_blueprint` over a Flask blueprint. Diffing the two directories
is the shortest available account of how much of an application the framework choice touches.

Policy *logic* is loaded off disk rather than handed over as a string, which is what puts the
argument ceiling under review beside the `permit` it hangs on:

```python
install(
    policy_source=FilesystemPolicySource(POLICY_DIR),
    grant_store=store,
    context_provider=provider,
)
```

`policies=` and `policy_source=` are mutually exclusive, so moving to files moves *all* the
policy logic out of Python. Grants — roles, entity edges, per-argument constraints — stay in
the store, which is the half an admin surface may mutate.

```bash
pixi run -e web run-fastapi     # serves on http://127.0.0.1:8000
pixi run -e web run-flask       # serves on http://127.0.0.1:5000
```

Before either app starts serving it drives 22 requests through its own framework's test client
and prints one line each, so the whole decision surface is readable before you type a `curl`.
Both call `configure(verbosity="verbose")`, so the `_authz` envelope carries processed values,
applied defaults and rejection reasons; a service in production would leave that at `summary`.
sentrykit logs `Argument dropped by policy` once per rejected value, so seven of those land on
stderr ahead of the table.

```
#   who    request                                                            code  what the policy did
--  -----  -----------------------------------------------------------------  ----  --------------------
1   alice  GET  /orders/status                                                200   allowed
2   alice  GET  /orders/summary                                               200   allowed
3   alice  GET  /orders                                                       200   defaulted: region='eu' limit=10
4   alice  GET  /orders?region=cn&limit=5                                     200   narrowed: region='cn' rejected (allow-set, alice-region), refilled with 'eu'
5   alice  GET  /orders?limit=500&status=open                                 200   narrowed: limit=500 rejected (maximum, alice-limit), refilled with 10 | defaulted: region='eu'
6   dana   GET  /orders?limit=500&status=open                                 200   narrowed: limit=500 rejected (maximum, support-may-search), refilled with 25 | defaulted: region='eu'
7   alice  GET  /orders/o-1                                                   200   allowed
8   bob    GET  /orders/o-1                                                   403   denied: The policy denied action Action::"orders.read".
9   bob    POST /orders/export {"fmt":"csv"}                                  200   allowed
10  bob    POST /orders/export {"scope":"open"}                               200   defaulted: fmt='csv'
11  bob    POST /orders/export {"fmt":"xml","scope":"open"}                   200   narrowed: fmt='xml' rejected (deny-set, bob-fmt), refilled with 'csv'
12  bob    POST /orders/export {"fmt":"xml"}                                  400   NoValidArguments: Every supplied argument was rejected by policy.
13  bob    POST /orders/export {"fmt":"pdf"}                                  403   denied: The policy denied action Action::"orders.export".
14  bob    GET  /orders                                                       403   denied: The policy denied action Action::"orders.search".
15  alice  POST /refunds {"order_id":"ord-0007","amount":100,"region":"uk"}   200   allowed
16  alice  POST /refunds {"order_id":"ord-0007","amount":750,"region":"uk"}   403   denied: The policy denied action Action::"refunds.issue".
17  alice  POST /refunds {"order_id":"ord-0007","amount":900,"region":"eu"}   200   narrowed: amount=900 rejected (maximum, alice-amount), refilled with 50
18  alice  POST /refunds {"order_id":"ord-0007","amount":5000,"region":"eu"}  403   denied: The policy denied action Action::"refunds.issue".
19  dana   POST /refunds {"order_id":"ord-0007","amount":5000,"region":"eu"}  200   allowed
20  alice  POST /refunds {"order_id":"refund-me","amount":100,"region":"eu"}  400   DefaultUnavailable: Argument 'order_id' is required and no policy default is configured.
21  dana   POST /refunds/rf-1/approve                                         200   allowed
22  alice  POST /refunds/rf-1/approve                                         403   denied: The policy denied action Action::"refunds.approve".
```

Authentication is a stub — the `x-user` header names the principal — which is the seam a real
app replaces with its session, its bearer token or its gateway's assertion. Nothing below the
`identify` callback changes when it does.

### Who the three principals are

No policy file names a person. Roles, entity edges and per-argument constraints are all grant
data:

| Principal | Role | Place in the graph | Argument constraints |
| --- | --- | --- | --- |
| `alice` | `support` | `Team::"eu-support"` → `Division::"emea"` → `Project::"orders-eu"` | search: `region` ∈ {`eu`,`uk`} default `eu`; `limit` ≤ 50 default `10`. refunds: `order_id` matching `ord-[0-9]{4}` with **no default**; `amount` 1–750 default `50`; `region` ∈ {`eu`,`uk`} default `eu` |
| `bob` | `auditor` | `Team::"us-support"` → `Division::"amer"` → `Project::"orders-us"` | export: `fmt` ∉ {`xml`} default `csv` |
| `dana` | `admin`, which has `Role::"support"` as a parent | `Team::"eu-support"` → `Division::"emea"` → `Project::"orders-eu"` | search: `limit` default `25`, with **no bound of her own**; `region` default `eu` |

Between them the grant data uses the whole constraint vocabulary — allow-set, deny-set,
pattern, minimum, maximum, default — at least once each.

### The ceiling is reviewed text, and it can only narrow

Flows 5 and 6 are the identical request from two people, and they are the pair to read twice.
`policies/10-orders.cedar` declares an [argument ceiling](policies.md#argument-ceilings) on the
permit that lets support search:

```cedar
@id("support-may-search")
@constraints("{\"limit\": {\"maximum\": 100}}")
permit (
  principal in Role::"support",
  action == Action::"orders.search",
  resource == Tool::"orders"
);
```

`@constraints` is a **Cedar policy annotation, not a Python decorator**: text carried on the
policy, parsed when the directory loads. It grants nobody anything. It states the widest value
*anybody* reaching this permit may pass, and it **intersects** with whatever the grant store
holds for the caller — so a grant can tighten it and can never loosen it.

Alice's own grant caps `limit` at 50, which is tighter than the reviewed 100, so hers is the
bound that bites and the rejection names her grant:

```bash
curl -s 'localhost:8000/orders?limit=500&status=open' -H 'x-user: alice'
# {"region":"eu","limit":10,"status":"open", ...,
#  "_authz":{"decision":"allow","processed":{"status":"open","region":"eu","limit":10},
#            "rejected":[{"name":"limit","rule":"maximum",
#                         "reason":"Value is above the maximum of 50",
#                         "policy":"alice-limit","value":500}],
#            "defaults_applied":{"region":"eu","limit":10},
#            "narrowed":true,"narrowed_arguments":["limit"],
#            "guidance":"This result is valid and was served. ..."}}
```

Dana's grant sets no maximum at all — only a default — so the reviewed ceiling is her only
bound, and the rejection names the reviewed policy instead:

```bash
curl -s 'localhost:8000/orders?limit=500&status=open' -H 'x-user: dana'
# {"region":"eu","limit":25,"status":"open", ...,
#  "_authz":{"decision":"allow","processed":{"status":"open","limit":25,"region":"eu"},
#            "rejected":[{"name":"limit","rule":"maximum",
#                         "reason":"Value is above the maximum of 100",
#                         "policy":"support-may-search","value":500}],
#            "defaults_applied":{"limit":25,"region":"eu"},
#            "narrowed":true,"narrowed_arguments":["limit"],
#            "guidance":"This result is valid and was served. ..."}}
```

**She asked for 500, the ceiling is 100, and she ran with 25.** That is the whole of
reject-and-refill in one line: the value she may not pass was thrown away and her own default
was put in the gap. The result is her default and has no relationship to the bound that refused
it — nothing was trimmed to 100, and nothing ever is. Grants filter before ceilings, so
whichever of the two bounds is tighter is the one that reports.

### Several arguments decided in one call

Flow 5 above is also where the three parts of the argument layer are visible side by side, in
one envelope:

- `rejected` names `limit=500`, the rule that refused it and the policy that carried the rule;
- `defaults_applied` names both the refill for `limit` and the injection for `region`, which
  the caller never proposed at all;
- `processed` is what the function actually received — `status` passed through untouched,
  because no constraint governs it.

The contrast between those three arguments is the design rule worth copying, and it lives in
the signature: `search_orders(region: str, limit: int, status: str = "open")`. `region` and
`limit` are values policy decides, so they carry no Python default and stay omittable; a Python
default would fill the hole before a policy default could reach it. `status` is the caller's
own business, so Python answers for it and the policy layer never sees it.

### Two rules that read more than the principal

`policies/20-refunds.cedar` permits support to issue refunds unconditionally and then puts two
narrow `forbid` rules over it. Each decides on something no per-argument rule could express.

**One argument together with the principal.** `refunds-above-the-desk-limit-need-an-admin`
refuses anything over 1000 from a caller who is not an admin. Flows 18 and 19 are the same
request from two people:

```bash
curl -s -i -X POST localhost:8000/refunds -H 'x-user: alice' \
     -H 'content-type: application/json' \
     -d '{"order_id":"ord-0007","amount":5000,"region":"eu"}'
# 403  {"detail":"The policy denied action Action::\"refunds.issue\".","error":"AuthzDenied", ...}

curl -s -X POST localhost:8000/refunds -H 'x-user: dana' \
     -H 'content-type: application/json' \
     -d '{"order_id":"ord-0007","amount":5000,"region":"eu"}'
# {"refund_id":"rf-1","order_id":"ord-0007","amount":5000,"region":"eu", ...}
```

Dana is exempted by the rule's last clause because `Role::"admin"` has `Role::"support"` as a
parent, so one edge in the entity graph covers both populations.

**Two arguments against each other.** `no-large-cross-region-refunds` refuses anything over 200
booked outside `eu`. Flows 15 and 16 differ only in the amount, and each value is fine on its
own — 750 is inside alice's range of 1–750, and `uk` is one of her permitted regions — while
the pair is refused:

```bash
curl -s -X POST localhost:8000/refunds -H 'x-user: alice' \
     -H 'content-type: application/json' \
     -d '{"order_id":"ord-0007","amount":100,"region":"uk"}'    # 200

curl -s -i -X POST localhost:8000/refunds -H 'x-user: alice' \
     -H 'content-type: application/json' \
     -d '{"order_id":"ord-0007","amount":750,"region":"uk"}'    # 403
```

Nothing in either route compares `amount` to `region`, and nothing there asks who the caller
is. Cedar receives the whole proposal as `context.args` and answers about all of it at once, so
a cross-argument rule is policy text rather than a branch in a handler.

Flow 17 separates the two layers, which is easy to conflate: at `amount=900` the gate says yes,
because 900 is under the desk limit of 1000 — and alice's own grant then rejects the value and
refills it with 50.

Both refusals are **named** denies. A `forbid` that fires is determining, so at
`verbosity="debug"` alice's envelope carries
`"determining_policies":["refunds-above-the-desk-limit-need-an-admin"]`. The refusals in flows
8 and 14 read the other way: no permit reaches bob at all, so no policy was determining and
`determining_policies` is empty even at `debug`. When nothing permitted a call there is no rule
to point at, and reporting one would be inventing it.

### Reject-and-refill from a deny-set, and the call with nothing left

Bob's `fmt` constraint is a deny-set with a default, the mirror image of an allow-set:
everything passes except what is named. Flow 11 proposes `xml` alongside a `scope` that
survives, so the rejection is refilled and the export runs:

```bash
curl -s -X POST localhost:8000/orders/export -H 'x-user: bob' \
     -H 'content-type: application/json' -d '{"fmt":"xml","scope":"open"}'
# {"fmt":"csv","scope":"open","exported":42,
#  "_authz":{"decision":"allow","processed":{"scope":"open","fmt":"csv"},
#            "rejected":[{"name":"fmt","rule":"deny-set",
#                         "reason":"Value is explicitly denied","policy":"bob-fmt",
#                         "value":"xml"}],
#            "defaults_applied":{"fmt":"csv"},
#            "narrowed":true,"narrowed_arguments":["fmt"],
#            "guidance":"This result is valid and was served. ..."}}
```

Flow 12 proposes the same value **alone**, and is refused. Narrowing refines a proposal; it
does not rescue one, so a call in which nothing the caller sent survived is turned away rather
than rebuilt entirely from defaults:

```bash
curl -s -i -X POST localhost:8000/orders/export -H 'x-user: bob' \
     -H 'content-type: application/json' -d '{"fmt":"xml"}'
# 400  {"detail":"Every supplied argument was rejected by policy.",
#       "error":"NoValidArguments",
#       "_authz":{"decision":"deny",
#                 "reason":"Every supplied argument was rejected by policy.",
#                 "rejected":[{"name":"fmt","rule":"deny-set",
#                              "reason":"Value is explicitly denied","policy":"bob-fmt"}],
#                 "allowed":{"fmt":{"deny":["xml"],"policy":"bob-fmt",
#                                   "required":false,"has_default":true}}}}
```

That body is built from the exception rather than from a decision, which is why it names no
action and no resource — the gate had already said yes. The `allowed` block, which appears on
no permitted call's envelope, is what a caller needs in order to retry.

Flow 10 reaches the same `csv` by the other route: `fmt` is simply omitted, so it turns up in
`defaults_applied` and never in `rejected`. That distinction is worth preserving in anything
you build on the envelope — it is the difference between *the caller asked for something they
may not have* and *the caller asked for nothing*.

### The bare `@protect`, and a protected callable that is not a route

Flow 1 calls `desk_status`, which is decorated with a bare `@protect` — no `action=`, no
`resource=`. sentrykit derives both from the callable's import path, and the reviewed file
names the derived action verbatim:

```bash
curl -s localhost:8000/orders/status -H 'x-user: alice'
# {"desk":"orders","open":true,
#  "_authz":{"decision":"allow",
#            "action":"Action::\"examples.fastapi_app.service.desk_status\"",
#            "resource":"Resource::\"examples.fastapi_app.service.desk_status\"",
#            "principal":"User::\"alice\""}}
```

Convenient, and fragile in one specific way: renaming or moving the function changes the id the
policy has to match. Pass an explicit `action=` as soon as the policy is expected to outlive
the module layout.

Flow 2 is the one that shows what "action layer, not routing layer" buys. `/orders/summary` is
an ordinary route with no authorization on it; `summarize_orders()` inside it is protected, and
is decided against the same ambient principal the provider established:

```bash
curl -s localhost:8000/orders/summary -H 'x-user: alice'
# {"summary":"3 open orders",
#  "_authz":{"decision":"allow","action":"Action::\"orders.summarize\"",
#            "resource":"Tool::\"orders\"","principal":"User::\"alice\""}}
```

The same function is governed identically when a service layer three frames deeper calls it, or
a background job does.

Each example directory's README carries the remaining flows — the multi-hop relationship in
flows 7 and 8, the `forbid` that reads the raw proposal in flow 13, the pattern with no default
to refill from in flow 20, and the admin action in flows 21 and 22 — as one `curl` apiece.
