# Example: flask_app

A minimal governed Flask app. Three routes, one `@protect` decorator per service function, one
`FlaskProvider` — and the same URLs, the same policy and the same service layer as
`examples/fastapi_app`, so the two can be read side by side to see how little differs between
frameworks.

## What it demonstrates

| | Where |
| --- | --- |
| **Gate** — a role decides whether the call happens at all | `bob` cannot search, `alice` cannot export |
| **Argument filtering** — the caller proposes, the policy disposes | `?region=cn` is dropped, not obeyed |
| **Default injection** — omitted arguments are filled from grants | `GET /orders` with no query string |
| **Denial** — a `forbid` that reads the proposed arguments | `fmt="pdf"` is refused for everyone |
| **The `_authz` envelope** — on success and on refusal alike | every response body |
| **A protected non-route callable** | `GET /orders/summary` calls `summarize_orders()` |
| **Blueprint-scoped wiring** | `protect_blueprint(orders, provider=provider)` |

## Layout

- `policy.py` — the reviewed Cedar text (`POLICY_TEXT`) and the mutable grant data
  (`build_grants()`). Policies-as-code, grants-as-data, in about sixty lines.
- `service.py` — the three protected callables. No Flask import anywhere in it.
- `main.py` — `create_app()`: wiring, the auth stub, and the routes.

## Who may do what

| Principal | Role | May | Argument constraints |
| --- | --- | --- | --- |
| `alice` | `support` | `orders.search`, `orders.summarize` | `region` ∈ {`eu`, `uk`}, default `eu`; `limit` ≤ 50, default `10` |
| `bob` | `auditor` | `orders.export` | none — but `fmt="pdf"` is forbidden by policy |

The caller is identified by the `x-user` header. That is an authentication *stub*: a real app
returns the subject of a verified session or token from `_identify`.

## Run it

```bash
pixi run -e web run-flask     # flask --app examples.flask_app.main run --debug
```

The app runs at `http://127.0.0.1:5000` and is configured with `verbosity="verbose"`, so the
`_authz` envelope shows the processed arguments, the defaults that were injected and the
arguments that were dropped. A real service would ship at the `summary` default.

## Try it

Defaults injected — Alice supplies nothing, policy supplies both arguments:

```bash
curl -s localhost:5000/orders -H 'x-user: alice'
# {"region":"eu","limit":10,"orders":[...],
#  "_authz":{"decision":"allow","defaults_applied":{"region":"eu","limit":10}, ...}}
```

A disallowed value is dropped and then defaulted — the call still happens, with an argument
the policy authorized:

```bash
curl -s 'localhost:5000/orders?region=cn&limit=5' -H 'x-user: alice'
# {"region":"eu","limit":5, ...
#  "_authz":{"rejected":[{"name":"region","rule":"allow-set","policy":"alice-region", ...}]}}
```

Drop the `limit=5` and *every* argument the caller supplied has been rejected. That is a
refusal rather than a silent substitution: proceeding would mean running a call that has
nothing of the caller's intent left in it.

```bash
curl -s 'localhost:5000/orders?region=cn' -H 'x-user: alice' -i | head -1
# HTTP/1.1 400 BAD REQUEST   -> {"error":"NoValidArguments", ...}
```

The gate — Bob is an auditor, not support:

```bash
curl -s localhost:5000/orders -H 'x-user: bob' -i | head -1
# HTTP/1.1 403 FORBIDDEN     -> {"error":"AuthzDenied","_authz":{"action":"Action::\"orders.search\"", ...}}
```

No principal at all fails closed rather than running unguarded:

```bash
curl -s localhost:5000/orders -i | head -1
# HTTP/1.1 403 FORBIDDEN     -> {"error":"NoContext", ...}
```

Bob may export, but not as PDF — the `no-pdf-exports` forbid reads `context.args.fmt`, so the
refusal happens before the export function is entered:

```bash
curl -s localhost:5000/orders/export -H 'x-user: bob' -H 'content-type: application/json' \
     -d '{"fmt":"csv"}'
# {"fmt":"csv","exported":42,"_authz":{"decision":"allow", ...}}

curl -s localhost:5000/orders/export -H 'x-user: bob' -H 'content-type: application/json' \
     -d '{"fmt":"pdf"}' -i | head -1
# HTTP/1.1 403 FORBIDDEN     -> at verbosity="debug", _authz.determining_policies == ["no-pdf-exports"]
```

The route below is *not* protected; the function it calls is, and it is governed by the same
ambient principal:

```bash
curl -s localhost:5000/orders/summary -H 'x-user: alice'   # 200
curl -s localhost:5000/orders/summary -H 'x-user: bob' -i | head -1   # 403 AuthzDenied
```

## The one thing worth copying

`protect_blueprint` registers a `before_request` hook that establishes the ambient principal
and a `teardown_request` hook that releases it. The release is not tidiness. Flask serves a
request on a pooled worker thread and its test client serves one in the caller's own context,
so a context left un-reset by request *N* is still ambient when request *N+1* starts — and
*N+1* would be authorized as *N*'s principal. Never establish without wiring the teardown.
