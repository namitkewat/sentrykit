# Phase 3 — research notes

Findings verified against the **actually installed** `web` pixi environment on 2026-08-18,
by running code rather than by reading documentation. Phase 1's and Phase 2's findings are in
`phase-1-research.md` / `phase-2-research.md` and are not repeated.

| Package | Version |
| --- | --- |
| Python | 3.13.15 (conda-forge) |
| fastapi | 0.141.1 |
| starlette | **1.6.0** |
| flask | 3.1.3 |
| werkzeug | 3.1.8 |
| httpx | 0.28.1 |
| anyio | 4.14.2 |
| uvicorn | 0.52.3 |
| pydantic | 2.13.4 |
| pytest / pytest-asyncio | 9.1.1 / 1.4.0 |

`asgiref` is **not** installed, so Flask `async def` views are unavailable in this
environment. The Flask example and its tests use sync views only.

---

## 1. Does ambient context reach a sync `def` route? — yes, and the mechanism is pinned

This is the question the whole provider design turns on, because `@protect` reads a
`ContextVar` and a Flask-style sync handler under FastAPI does **not** run on the event loop.

`starlette.concurrency.run_in_threadpool` is, verbatim in 1.6.0:

```python
async def run_in_threadpool(func, *args, **kwargs):
    func = functools.partial(func, *args, **kwargs)
    return await anyio.to_thread.run_sync(func)
```

and `anyio.to_thread.run_sync` runs the callable inside a **copy of the calling context**.
Confirmed by observation, not inference — a sync route reported
`thread='AnyIO worker thread'` and still saw the value a middleware had set:

| Established in | Seen by `async def` route | Seen by `def` route |
| --- | --- | --- |
| pure-ASGI middleware | yes | **yes** (AnyIO worker thread) |
| `BaseHTTPMiddleware` (`@app.middleware("http")`) | yes | **yes** |
| `async def` dependency | yes | **yes** |
| `async def` **yield** dependency | yes | **yes** |
| **`def` (sync) dependency** | **no** | **no** |

> **Consequence.** A context provider for FastAPI may establish from middleware or from an
> `async` dependency, but **never from a sync dependency** — that runs in its own worker
> thread with a *copy* of the context, so its `establish()` is discarded on return and every
> protected call downstream fails closed. `sentrykit.integrations.fastapi` therefore ships a
> pure-ASGI middleware plus an `async` yield-dependency, and no sync-dependency form exists
> to be reached for by mistake.

## 2. Context propagates *down* but not *up* out of a sync route — so the renderer reads the exception

The copy is one-way. A `ContextVar` set **inside** a route is visible afterwards only when
the route was `async`:

| Set inside | Visible to the enclosing middleware / exception handler afterwards |
| --- | --- |
| `async def` route | **yes** (same task, same context) |
| `def` route | **no** (worker-thread copy is discarded) |

`sentrykit.envelope.set_last_envelope` is a `ContextVar` write, and the engine performs it
*inside* the protected call. So:

> **Consequence.** `last_envelope()` is **not** a reliable source for a provider rendering an
> error response — it is empty for every sync route. The verbosity-aware renderer in
> `integrations/base.py` builds the envelope **from the exception object**, whose structured
> detail (`AuthzDenied.determining_policies`, `NoValidArguments.allowed/rejected`,
> `ValidationFailed.errors`, …) is complete and framework-independent. `last_envelope()` is
> used only as optional enrichment where it happens to be populated.

The success path is unaffected: `attach_envelope` mutates the returned mapping in place, and
the object crosses the thread boundary as an ordinary return value.

## 3. FastAPI/Starlette 1.6 middleware and exception-handler surface

```python
FastAPI.add_exception_handler(exc_class_or_status_code: int | type[Exception], handler) -> None
FastAPI.exception_handler(exc_class_or_status_code: int | type[Exception])       # decorator
FastAPI.add_middleware(middleware_class, *args, **kwargs)
BaseHTTPMiddleware.__init__(self, app: ASGIApp, dispatch: DispatchFunction | None = None)
```

`starlette.middleware.base` still exports `BaseHTTPMiddleware` in 1.6.0 (alongside a new
`create_collapsing_task_group`). We do not use it: a pure-ASGI class needs no task group,
adds no `call_next` buffering, and — see below — keeps the established context alive for the
exception handler.

**Built stack order**, read off `app.build_middleware_stack()`:

```
ServerErrorMiddleware
  <user middleware, e.g. SentrykitMiddleware>
    ExceptionMiddleware          <- registered exception handlers run here
      AsyncExitStackMiddleware   <- yield-dependency teardown runs here
        APIRouter
```

Two consequences follow directly from that order, both confirmed by probe:

- An exception handler registered for a **base** class catches its subclasses (Starlette
  walks `type(exc).__mro__`). Registering one handler for `SentrykitError` would work — but
  the mapping is per-type anyway, so each type is registered explicitly and the base class is
  registered last as the catch-all.
- Handlers run **inside** user middleware, so a middleware-established context is still
  ambient in the handler (`var_in_handler` was populated). Handlers run **outside** the
  AsyncExitStack, so a *yield-dependency*-established context is **already reset** by then
  (`var_in_handler` was `null`). Another reason the renderer must not depend on ambient
  context.

Exception handlers execute on the event-loop thread even when the raising route was sync.

Request auth is exposed three ways, all confirmed working: `request.headers[...]`,
`request.state.<attr>` (backed by `scope["state"]`, so a pure-ASGI middleware can seed it
via `scope.setdefault("state", {})`), and `Depends(HTTPBearer(...))` /
`Depends(APIKeyHeader(...))` from `fastapi.security`. sentrykit stays out of that choice: the
app supplies an **auth → principal-id** callback and the provider resolves the id through
`GrantStore.get_principal`.

## 4. Flask 3.1 hooks — `errorhandler` runs before `teardown_request`

```python
Flask.before_request(f)          Flask.teardown_request(f)     # f(exc: BaseException | None)
Flask.after_request(f)           Flask.errorhandler(code_or_exception)
Flask.register_error_handler(code_or_exception, f)
Blueprint(name, import_name, *, url_prefix=None, ...)
Blueprint.before_request / teardown_request / errorhandler          # blueprint-scoped
Blueprint.before_app_request / teardown_app_request                 # app-scoped from a blueprint
```

Observed ordering for a request whose view raises:

```
before_request  ->  view raises  ->  errorhandler renders  ->  teardown_request
```

so the handler still sees the ambient principal, and teardown is the correct place for the
reset. Other confirmed behaviours:

- `@app.errorhandler(Boom)` catches `SubBoom` — Flask walks the MRO like Starlette does.
- `before_request` and `teardown_request` fire even for a **404**, so a provider that
  establishes in `before_request` must tolerate there being no matched view.
- `teardown_request` receives the exception (or `None`) and runs even when `before_request`
  itself raised — so the token has to be stashed somewhere teardown can find it, and its
  absence has to be a no-op rather than a `KeyError`.
- Everything happens on **one thread per request** (`MainThread` under `test_client`,
  `Thread-N (process_request_thread)` under a threaded `werkzeug` server), so a
  `ContextVar` token captured in `before_request` is always resettable in `teardown_request`.

`flask.g` is the natural place for the token: request-scoped, cleared with the app context.

## 5. The cross-request leak is real, and the two frameworks prove it differently

Measured with a deliberately leaky provider that establishes and never resets:

- **Flask.** `test_client()` runs the request on the caller's thread and in the caller's
  context, so an un-reset `ContextVar` from request *N* is still ambient at the start of
  request *N+1*. Under a threaded `werkzeug` server the same hazard exists per pooled worker
  thread. With the `before_request` → `teardown_request` token reset in place, the sequence
  `alice → (no auth) → bob → (no auth)` reported `alice, None, bob, None` on four different
  pooled threads. **This is a genuine same-context leak test.**
- **FastAPI.** `TestClient` drives each request through its own portal task, which starts
  from a fresh context copy — so a leaky ASGI middleware still *appears* clean through the
  test client. A no-leak test written only against `TestClient` would therefore pass
  vacuously.

> **Consequence for the tests.** The FastAPI no-leak assertion is written twice: once
> behaviourally through `TestClient` (principal A, then an unauthenticated call ⇒ denied), and
> once by driving the ASGI callable **twice inside a single `contextvars` context** and
> asserting `current_principal()` is `None` between the two. Only the second one can fail if
> the reset is deleted, and that is the one that pins the invariant.

## 6. Test clients

- `fastapi.testclient.TestClient(app, base_url='http://testserver', raise_server_exceptions=True, ...)`
  — httpx-backed, sync API, usable as a context manager (which runs lifespan). Importing it
  emits `StarletteDeprecationWarning: Using 'httpx' with 'starlette.testclient' is
  deprecated; install 'httpx2' instead`. `httpx2` is not installed and is not required; the
  warning is informational and pytest is not configured to turn warnings into errors.
- `Flask.test_client(use_cookies=True, **kwargs)` — `client.get("/x?limit=5", headers=...)`,
  response exposes `.status_code`, `.is_json`, `.get_json()`.

## 7. Decisions taken for Phase 3 as a consequence

1. **FastAPI establishes from a pure-ASGI middleware** (`SentrykitMiddleware`), with an
   `async` yield-dependency (`sentrykit_context`) as the route-scoped alternative. No sync
   dependency form is offered, because it cannot work (§1).
2. **The per-request lifecycle is establish-at-the-boundary / reset-at-teardown**, in a
   `finally` (ASGI) or in `teardown_request` (Flask). This is correctness, not tidiness: §5
   measured the leak.
3. **The verbosity-aware error renderer is shared** and lives in `integrations/base.py`,
   built from the **exception**, because ambient state is not available to it on every path
   (§2, §3). The exception→status mapping lives there too, so both providers refuse
   identically:
   `AuthzDenied`/`NoContext` → **403**, `ArgumentRejected`/`NoValidArguments` → **400**,
   `ValidationFailed` → **422**, `DefaultUnavailable` → **400**, `ConfigurationError`/
   `AuditUnavailable` → **500**.
4. **Integration test modules call `pytest.importorskip` at module top**, so the default-env
   gate stays green with them skipped and the web-env gate runs them.
5. A route declaring a pydantic `response_model` strips unknown keys, which would drop the
   `_authz` key the engine attached. The examples return plain mappings and the docs say so.
