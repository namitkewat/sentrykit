# Example: fastapi_app

A three-route orders API showing what one decorator plus one middleware buys you: a role
gate, per-principal argument filtering, policy-supplied defaults, an argument-aware `forbid`,
and the `_authz` envelope travelling with every answer.

## Layout

| File | What is in it |
| --- | --- |
| `policy.py` | `POLICY_TEXT` (Cedar *logic*, reviewed in git) and `build_grants()` (roles and argument constraints — *data*) |
| `service.py` | The three `@protect`-ed callables. No web framework, no request object |
| `main.py` | `create_app()`: settings, grants, policy, provider, `protect_app`, routes |

`search_orders(region, limit)` deliberately declares **no Python defaults**, so the values a
caller gets when they omit a parameter come from *policy* and nowhere else.

## Who may do what

| Principal | Role | May | Argument constraints |
| --- | --- | --- | --- |
| `alice` | `support` | `orders.search`, `orders.summarize` | `region` ∈ {`eu`, `uk`}, default `eu`; `limit` ≤ 50, default `10` |
| `bob` | `auditor` | `orders.export` | — |

A `forbid` policy (`no-pdf-exports`) refuses `fmt="pdf"` for everyone, including `bob`, by
reading `context.args.fmt`. That is how an exception is expressed without editing the permit.

## Running it

```bash
pixi run -e web run-fastapi        # uvicorn examples.fastapi_app.main:app --reload
```

Authentication is a stub: the **`x-user`** header names the principal. That is the seam a real
app replaces with its session, bearer token, or gateway assertion — nothing below the
`identify` callback changes when it does.

The app calls `configure(verbosity="verbose")` so the envelope carries processed values,
applied defaults and rejection reasons. A production service would leave it at `summary`.

## Things to try

Default injection — `region` and `limit` were never sent, and policy filled both in:

```bash
curl -s localhost:8000/orders -H 'x-user: alice'
# {"region":"eu","limit":10,"orders":[...],
#  "_authz":{"decision":"allow","defaults_applied":{"region":"eu","limit":10}, ...}}
```

Argument filtering — `cn` is not in alice's allow-set, so it is **dropped and then
defaulted**; the call still succeeds and the envelope says exactly what happened:

```bash
curl -s 'localhost:8000/orders?region=cn&limit=5' -H 'x-user: alice'
# {"region":"eu","limit":5, ...
#  "_authz":{"decision":"allow","rejected":[{"name":"region","rule":"allow-set",
#             "policy":"alice-region","value":"cn"}], ...}}
```

Nothing left to run with — every proposed argument was refused, so the call is not made:

```bash
curl -s -i 'localhost:8000/orders?region=cn' -H 'x-user: alice'
# 400  {"detail":"Every supplied argument was rejected by policy.",
#       "error":"NoValidArguments", "_authz":{...}}
```

The role gate — `bob` is an auditor, not support:

```bash
curl -s -i localhost:8000/orders -H 'x-user: bob'
# 403  {"detail":"The policy denied action Action::\"orders.search\".",
#       "error":"AuthzDenied", "_authz":{"decision":"deny", ...}}
```

Fail closed — no principal means no call, not an unguarded one:

```bash
curl -s -i localhost:8000/orders
# 403  {"detail":"No principal in context for action Action::\"orders.search\"; ...",
#       "error":"NoContext", ...}
```

A policy that reads the argument — `bob` may export, but not as a PDF:

```bash
curl -s -X POST localhost:8000/orders/export -H 'x-user: bob' \
     -H 'content-type: application/json' -d '{"fmt":"csv"}'      # 200
curl -s -i -X POST localhost:8000/orders/export -H 'x-user: bob' \
     -H 'content-type: application/json' -d '{"fmt":"pdf"}'      # 403 AuthzDenied
```

At `verbosity="debug"` that last refusal also names the policy that decided it:
`"determining_policies":["no-pdf-exports"]`.

The gate is on the callable, not the URL — `/orders/summary` is an ordinary unguarded route
that calls a protected function:

```bash
curl -s localhost:8000/orders/summary -H 'x-user: alice'   # 200, body carries _authz
curl -s -i localhost:8000/orders/summary -H 'x-user: bob'  # 403 AuthzDenied
```

## Two details worth copying

- `GET /orders` is a **sync `def`** route on purpose. FastAPI runs it in an AnyIO worker
  thread, and the principal established by the middleware travels with it — so protecting a
  blocking service function needs no special handling.
- **No route declares a pydantic `response_model`.** One would strip the `_authz` key the
  engine attaches to the returned mapping.
