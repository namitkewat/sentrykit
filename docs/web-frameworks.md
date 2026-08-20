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

Most rejected arguments never reach a status code. Under the default `arg_handling="lenient"` an
over-broad request is narrowed to what the principal may have and the route returns its ordinary
response, with the rejections named in the `_authz` envelope; the statuses below are for a call
that cannot proceed at all.

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

`examples/fastapi_app/` and `examples/flask_app/` are the same three routes on both frameworks,
sharing an identical policy and an identical service layer:

```bash
pixi run -e web run-fastapi
pixi run -e web run-flask
```

```bash
curl -H 'x-user: alice' localhost:8000/orders
curl -H 'x-user: alice' 'localhost:8000/orders?region=cn&limit=5'
curl -H 'x-user: bob'   localhost:8000/orders
```

The first runs on injected defaults, the second is narrowed with `region` rejected and
defaulted, and the third is refused. See each directory's README for the full set.
