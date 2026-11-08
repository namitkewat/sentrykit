# Example: flask_app

An orders-and-refunds desk on Flask, governed by sentrykit. Seven routes, seven protected
callables, three principals, and one reviewed policy directory — enough to show every surface
the library has: the gate, per-principal argument rules, an argument ceiling declared in
reviewed Cedar text, policy-supplied defaults, multi-argument decisions, multi-hop
relationships, and the `_authz` envelope travelling with every answer.

The URLs, `service.py`, `policy.py` and `policies/` are identical to `examples/fastapi_app`.
Diff the two directories: only the boundary wiring differs.

The seven callables query `examples/desk`, a seeded SQLite order desk of four hundred
orders that knows nothing about authorization. That is what makes the argument layer
legible: a `limit` refilled with 10 brings back ten rows and one refilled with 25 brings
back twenty-five, so narrowing is something a reader sees in the answer rather than
something the envelope merely reports.

## Layout

| File | What is in it |
| --- | --- |
| `policies/10-orders.cedar` | Reviewed policy *logic* for orders, including the `@constraints` argument ceiling |
| `policies/20-refunds.cedar` | Reviewed policy logic for refunds — a broad permit with two narrow `forbid` rules over it: one decides on an argument *together with* the principal, one on the relationship *between* two arguments |
| `policy.py` | `POLICY_DIR` / `POLICY_TEXT` (the files above) and `build_grants()` (the entity graph and the per-principal argument constraints — *data*) |
| `service.py` | The seven `@protect`-ed callables. No Flask import anywhere in it — they read and write `examples/desk` |
| `main.py` | `create_app()`: settings, grants, policy source, provider, `protect_blueprint`, routes. Plus `FLOWS` and `serve()`, the demonstration |

Read `service.py` for the one design rule worth copying: **`status` and `scope` carry Python
defaults, and nothing else does.** An argument whose value policy decides has to stay
omittable, or a Python default fills the hole before a policy default can reach it.

## Who may do what

Roles and edges are grant *data*. No policy file names a person.

| Principal | Role | Place in the graph | Argument constraints (grant data) |
| --- | --- | --- | --- |
| `alice` | `support` | `Team::"eu-support"` → `Division::"emea"` → `Project::"orders-eu"` | search: `region` ∈ {`eu`,`uk`} default `eu`; `limit` ≤ 50 default `10`. refunds: `order_id` must match `ord-[0-9]{4}` **and has no default**; `amount` 1–750 default `50`; `region` ∈ {`eu`,`uk`} default `eu` |
| `bob` | `auditor` | `Team::"us-support"` → `Division::"amer"` → `Project::"orders-us"` | export: `fmt` ∉ {`xml`} default `csv` |
| `dana` | `admin`, which has `Role::"support"` as a parent | `Team::"eu-support"` → `Division::"emea"` → `Project::"orders-eu"` | search: `limit` default `25` with **no bound of her own**; `region` default `eu` |

`Role::"admin"` having `Role::"support"` as a parent is one edge instead of a second grant on
every admin: Dana satisfies `principal in Role::"support"` because of it.

## Three places an argument rule can come from

1. **The decorator.** `@protect` bare — as on `desk_status` — derives the action from the
   callable's import path; `@protect(action=..., resource=...)` names them. It also accepts
   `governor=`, which pins one callable to a specific `Governor` instead of the
   process-installed one. There is no sibling decorator for plain callables; `@protect` is
   the whole surface.
2. **Grant data.** Allow-sets, deny-sets, patterns, minimums, maximums and defaults, per
   (principal, action, argument), in `policy.py`. Mutable, and the only half an admin surface
   ever writes.
3. **Reviewed policy.** The `@constraints` annotation in `policies/10-orders.cedar`. It is a
   **Cedar policy annotation, not a Python decorator**: text on the policy, parsed when the
   directory is loaded. It states the widest value *anybody* may pass, and it **intersects**
   with the caller's grant, so it can only narrow.

A value that breaches either layer is **rejected, and the caller's own default is put in the
gap** so the call proceeds. The result is their default. Nothing is trimmed to the bound that
was breached — flow 6 below exists to make that visible.

## Running it

```bash
pixi run -e web run-flask   # flask --app examples.flask_app.main:serve run --debug
```

`serve()` drives every flow through Flask's test client, prints what happened, and then
returns the app for the CLI to serve at `http://127.0.0.1:5000`. `create_app()` stays silent,
because every test builds its own app with it.

`serve()` reseeds the desk before it drives anything, so the refund ids and export handles
in the bodies below come out the same on every run. `create_app()` does not reseed: an app that
emptied its database on startup would be a poor example of anything.

sentrykit logs `Argument dropped by policy` on its own logger each time it rejects a value,
so seven of those land on stderr before the table:

```
#   who    request                                                            code  what the policy did
--  -----  -----------------------------------------------------------------  ----  --------------------
1   alice  GET  /orders/status                                                200   allowed
2   alice  GET  /orders/summary                                               200   allowed
3   alice  GET  /orders                                                       200   defaulted: limit=10 region='eu'
4   alice  GET  /orders?region=cn&limit=5                                     200   narrowed: region='cn' rejected (allow-set, alice-region), refilled with 'eu'
5   alice  GET  /orders?limit=500&status=open                                 200   narrowed: limit=500 rejected (maximum, alice-limit), refilled with 10 | defaulted: region='eu'
6   dana   GET  /orders?limit=500&status=open                                 200   narrowed: limit=500 rejected (maximum, support-may-search), refilled with 25 | defaulted: region='eu'
7   alice  GET  /orders/ord-0003                                              200   allowed
8   bob    GET  /orders/ord-0003                                              403   denied: The policy denied action Action::"orders.read".
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
21  dana   POST /refunds/rf-0002/approve                                      200   allowed
22  alice  POST /refunds/rf-0002/approve                                      403   denied: The policy denied action Action::"refunds.approve".
```

Authentication is a stub: the **`x-user`** header names the principal. A real app returns the
subject of a verified session or token from `_identify`, and nothing below that callback
changes when it does.

The app calls `configure(verbosity="verbose")` so the envelope carries processed values,
applied defaults and rejection reasons. A production service would leave it at `summary`.

Flask serializes JSON with sorted keys, so `_authz` comes first in every body below and the
keys inside it read alphabetically. That is Flask's JSON provider, not sentrykit.

## Every flow as a `curl`

### The decorator surface

**1 — the bare `@protect`.** No `action=`, no `resource=`: sentrykit derives both from the
callable's import path, and `policies/10-orders.cedar` names that action verbatim.

```bash
curl -s localhost:5000/orders/status -H 'x-user: alice'
# {"_authz":{"action":"Action::\"examples.flask_app.service.desk_status\"",
#            "decision":"allow","principal":"User::\"alice\"",
#            "resource":"Resource::\"examples.flask_app.service.desk_status\""},
#  "desk":"orders","open":true,"open_orders":198,"pending_refunds":4}
```

**2 — the gate is on the callable, not the URL.** `/orders/summary` is an ordinary unguarded
route; `summarize_orders()` inside it is protected.

```bash
curl -s localhost:5000/orders/summary -H 'x-user: alice'
# {"_authz":{"action":"Action::\"orders.summarize\"","decision":"allow", ...},
#  "oldest_open":"ord-0319","open_orders":198,
#  "regions":{"eu":81,"uk":54,"us":63}}
```

### Default injection and reject-and-refill

**3 — nothing proposed.** Both governed arguments come from Alice's own defaults. `status`
was never governed and Python answered for it.

```bash
curl -s localhost:5000/orders -H 'x-user: alice'
# {"_authz":{"decision":"allow","defaults_applied":{"limit":10,"region":"eu"},
#            "processed":{"limit":10,"region":"eu"}, ...},
#  "count":10,"limit":10,
#  "orders":[{"customer":"Marta Rossi","items":2,"order_id":"ord-0003",
#             "region":"eu","status":"open","total":93500}, ...],
#  "region":"eu","status":"open"}
```

**4 — an allow-set rejection, refilled.** `cn` is not one of Alice's regions, so it is
rejected and `eu` is put in the gap. `limit=5` was fine and stands.

```bash
curl -s 'localhost:5000/orders?region=cn&limit=5' -H 'x-user: alice'
# {"_authz":{"decision":"allow","defaults_applied":{"region":"eu"},
#            "processed":{"limit":5,"region":"eu"},
#            "rejected":[{"name":"region","policy":"alice-region",
#                         "reason":"Value is not one of the permitted values",
#                         "rule":"allow-set","value":"cn"}], ...},
#  "count":5,"limit":5,"orders":[ ...5 rows... ],"region":"eu","status":"open"}
```

**5 — several arguments decided in one call.** `limit=500` is rejected and refilled with 10;
`region` was never proposed and is defaulted to `eu`; `status` passes through untouched.

```bash
curl -s 'localhost:5000/orders?limit=500&status=open' -H 'x-user: alice'
# {"_authz":{"decision":"allow","defaults_applied":{"limit":10,"region":"eu"},
#            "processed":{"limit":10,"region":"eu","status":"open"},
#            "rejected":[{"name":"limit","policy":"alice-limit",
#                         "reason":"Value is above the maximum of 50",
#                         "rule":"maximum","value":500}], ...},
#  "count":10,"limit":10,"orders":[ ...10 rows... ],"region":"eu","status":"open"}
```

**6 — the reviewed ceiling, and the clearest statement of what refilling means.** Dana's
grant sets no maximum, so her only bound is the `@constraints` ceiling in
`policies/10-orders.cedar`. She asks for 500, breaches the ceiling of 100, and **runs with
25 — her own default**. The rejection names `support-may-search`, the reviewed policy, because
that is the layer that produced it.

```bash
curl -s 'localhost:5000/orders?limit=500&status=open' -H 'x-user: dana'
# {"_authz":{"decision":"allow","defaults_applied":{"limit":25,"region":"eu"},
#            "processed":{"limit":25,"region":"eu","status":"open"},
#            "rejected":[{"name":"limit","policy":"support-may-search",
#                         "reason":"Value is above the maximum of 100",
#                         "rule":"maximum","value":500}], ...},
#  "count":25,"limit":25,"orders":[ ...25 rows... ],"region":"eu","status":"open"}
```

Grants filter before ceilings, so whichever bound is tighter is the one that reports. Run the
same request as `alice` and the rejection names `alice-limit` and her maximum of 50 instead.

### Relationships

**7 and 8 — one policy, two answers, and it names neither person.**
`project-members-may-read-project-orders` says a member of `Project::"orders-eu"` may read an
order in `Project::"orders-eu"`. Alice reaches that project through Team then Division; the
order reaches it through an edge of its own. Bob's chain is the same length and ends at
`Project::"orders-us"`. Nothing in the order row names that project: the edge lives in the
entity graph the policy walks, not in a column the desk would have to keep true.

```bash
curl -s localhost:5000/orders/ord-0003 -H 'x-user: alice'
# {"_authz":{"action":"Action::\"orders.read\"","decision":"allow",
#            "processed":{"order_id":"ord-0003"},"resource":"Order::\"ord-0003\"", ...},
#  "address":"35 Harbour Road, Utrecht 62299, NL","customer":"Marta Rossi",
#  "items":[{"name":"Keyboard Tray","price":16750,"quantity":4,"sku":"sku-0005"},
#           {"name":"Screen Filter","price":5300,"quantity":5,"sku":"sku-0022"}],
#  "order_id":"ord-0003","region":"eu","shipment":null,"status":"open","total":93500}

curl -s localhost:5000/orders/ord-0003 -H 'x-user: bob' -i | head -1
# HTTP/1.1 403 FORBIDDEN
# {"_authz":{"decision":"deny", ...},
#  "detail":"The policy denied action Action::\"orders.read\".","error":"AuthzDenied"}
```

### Export: three ways to be refused, one way to be narrowed

**9 — plainly allowed.** `scope` was not proposed, so it is absent from `processed` and
Python's own default filled it.

```bash
curl -s -X POST localhost:5000/orders/export -H 'x-user: bob' \
     -H 'content-type: application/json' -d '{"fmt":"csv"}'
# {"_authz":{"decision":"allow","processed":{"fmt":"csv"}, ...},
#  "fmt":"csv","job_id":"exp-0004","region":"eu","requested_by":"bob",
#  "rows":81,"scope":"open"}
```

Two of those fields came from neither the request nor the signature. `requested_by` is the
ambient principal, read with `current_principal()` inside the callable — a service layer
learning who is calling without taking a parameter for it, and without being handed a
request. `region` is the `EXPORT_REGION` constant in `service.py`: `orders.export` is
governed on `fmt` and `scope`, and no grant supplies a region for it.

**10 — `fmt` omitted, so Bob's default is injected.**

```bash
curl -s -X POST localhost:5000/orders/export -H 'x-user: bob' \
     -H 'content-type: application/json' -d '{"scope":"open"}'
# {"_authz":{"decision":"allow","defaults_applied":{"fmt":"csv"},
#            "processed":{"fmt":"csv","scope":"open"}, ...},
#  "fmt":"csv","job_id":"exp-0005","region":"eu","requested_by":"bob",
#  "rows":81,"scope":"open"}
```

**11 — a deny-set rejection, refilled.** `xml` is rejected, `csv` fills the gap, and `scope`
survives — which is what keeps the call alive.

```bash
curl -s -X POST localhost:5000/orders/export -H 'x-user: bob' \
     -H 'content-type: application/json' -d '{"fmt":"xml","scope":"open"}'
# {"_authz":{"decision":"allow","defaults_applied":{"fmt":"csv"},
#            "rejected":[{"name":"fmt","policy":"bob-fmt",
#                         "reason":"Value is explicitly denied","rule":"deny-set",
#                         "value":"xml"}], ...},
#  "fmt":"csv","job_id":"exp-0006","region":"eu","requested_by":"bob",
#  "rows":81,"scope":"open"}
```

**12 — the same value, alone.** Nothing the caller sent survived, so the call is refused
rather than rebuilt from defaults: refilling refines a proposal, it does not rescue one. The
body carries an `allowed` block saying what may be passed instead.

```bash
curl -s -X POST localhost:5000/orders/export -H 'x-user: bob' \
     -H 'content-type: application/json' -d '{"fmt":"xml"}' -i | head -1
# HTTP/1.1 400 BAD REQUEST
# {"_authz":{"allowed":{"fmt":{"deny":["xml"],"has_default":true,
#                              "policy":"bob-fmt","required":false}},
#            "decision":"deny",
#            "rejected":[{"name":"fmt","policy":"bob-fmt", ...}]},
#  "detail":"Every supplied argument was rejected by policy.","error":"NoValidArguments"}
```

**13 — a `forbid` that reads the proposal.** Cedar sees the caller's raw arguments before the
argument layer touches anything, so `no-pdf-exports` refuses the side effect at the gate. Bob
may export; he may not export a PDF.

```bash
curl -s -X POST localhost:5000/orders/export -H 'x-user: bob' \
     -H 'content-type: application/json' -d '{"fmt":"pdf"}' -i | head -1
# HTTP/1.1 403 FORBIDDEN
# {"_authz":{"action":"Action::\"orders.export\"","decision":"deny", ...},
#  "detail":"The policy denied action Action::\"orders.export\".","error":"AuthzDenied"}
```

At `verbosity="debug"` that refusal also names the policy that decided it:
`"determining_policies":["no-pdf-exports"]`.

**14 — the role gate.** Bob is an auditor, not support.

```bash
curl -s localhost:5000/orders -H 'x-user: bob' -i | head -1
# HTTP/1.1 403 FORBIDDEN
# {"_authz":{"action":"Action::\"orders.search\"","decision":"deny", ...},
#  "detail":"The policy denied action Action::\"orders.search\".","error":"AuthzDenied"}
```

A refusal of this shape **names nothing**. No permit reaches Bob for `orders.search`, so no
policy was determining, the request falls through to Cedar's default deny, and
`determining_policies` is empty even at `verbosity="debug"` — flow 8 reads the same way.
That is what to expect whenever nothing permitted the call. A refusal by a `forbid`, as in
flows 13, 16 and 18, names the `forbid` that fired.

### Refunds: a broad permit, and two narrow rules that read the proposal

**15 and 16 — refused by the relationship, not by either value.** A refund of 750 is inside
Alice's bounds and `uk` is one of her regions. Together they trip
`no-large-cross-region-refunds`, which forbids anything over 200 outside `eu`.

```bash
curl -s -X POST localhost:5000/refunds -H 'x-user: alice' \
     -H 'content-type: application/json' \
     -d '{"order_id":"ord-0007","amount":100,"region":"uk"}'
# {"_authz":{"decision":"allow", ...},
#  "amount":100,"order_id":"ord-0007","refund_id":"rf-0015","region":"uk",
#  "status":"pending"}

curl -s -X POST localhost:5000/refunds -H 'x-user: alice' \
     -H 'content-type: application/json' \
     -d '{"order_id":"ord-0007","amount":750,"region":"uk"}' -i | head -1
# HTTP/1.1 403 FORBIDDEN
# {"detail":"The policy denied action Action::\"refunds.issue\".", ...}
```

Nothing in the route compares `amount` to `region`. Cedar receives the whole proposal and
answers about all of it at once, so sentrykit needs no extra syntax for a rule of this shape.

**17 — the two layers, separately visible.** At 900 the gate says yes: it is under the desk
limit of 1000. Alice's own grant then rejects the value and refills it with 50.

```bash
curl -s -X POST localhost:5000/refunds -H 'x-user: alice' \
     -H 'content-type: application/json' \
     -d '{"order_id":"ord-0007","amount":900,"region":"eu"}'
# {"_authz":{"decision":"allow","defaults_applied":{"amount":50},
#            "processed":{"amount":50,"order_id":"ord-0007","region":"eu"},
#            "rejected":[{"name":"amount","policy":"alice-amount",
#                         "reason":"Value is above the maximum of 750",
#                         "rule":"maximum","value":900}], ...},
#  "amount":50,"order_id":"ord-0007","refund_id":"rf-0016","region":"eu",
#  "status":"pending"}
```

**18 and 19 — the same call, two principals.** `support-may-issue-refunds` permits the call
unconditionally, and `refunds-above-the-desk-limit-need-an-admin` forbids anything over 1000
from a principal who is not an admin. That rule decides on **an argument together with the
principal**: Alice trips it, Dana is exempted by its last clause.

```bash
curl -s -X POST localhost:5000/refunds -H 'x-user: alice' \
     -H 'content-type: application/json' \
     -d '{"order_id":"ord-0007","amount":5000,"region":"eu"}' -i | head -1
# HTTP/1.1 403 FORBIDDEN   -> {"error":"AuthzDenied", ...}

curl -s -X POST localhost:5000/refunds -H 'x-user: dana' \
     -H 'content-type: application/json' \
     -d '{"order_id":"ord-0007","amount":5000,"region":"eu"}'
# {"_authz":{"decision":"allow", ...},
#  "amount":5000,"order_id":"ord-0007","refund_id":"rf-0017","region":"eu",
#  "status":"pending"}
```

Alice's refusal is a **named** deny: a `forbid` that fires is determining, so at
`verbosity="debug"` her envelope carries
`"determining_policies":["refunds-above-the-desk-limit-need-an-admin"]`.

The permit underneath is unconditional on purpose. Fold the desk limit into a `when` on it and
the permit would depend on `context.args has amount` — false for a caller who has proposed
nothing yet, which is exactly what an agent asking which tools it may attempt looks like.
Permit broadly, forbid narrowly.

**20 — a pattern rejection with nothing to refill from.** `order_id` is governed by a pattern
and carries no default, so a value that fails it leaves a hole the policy cannot fill. The
refusal names the argument rather than an action: the gate had already said yes.

```bash
curl -s -X POST localhost:5000/refunds -H 'x-user: alice' \
     -H 'content-type: application/json' \
     -d '{"order_id":"refund-me","amount":100,"region":"eu"}' -i | head -1
# HTTP/1.1 400 BAD REQUEST
# {"_authz":{"decision":"deny",
#            "rejected":[{"name":"order_id",
#                         "reason":"No policy default is configured."}]},
#  "detail":"Argument 'order_id' is required and no policy default is configured.",
#  "error":"DefaultUnavailable"}
```

**21 and 22 — the admin action.** Policy says `Role::"admin"` may approve; the grant store
says who holds `admin`, and the reviewed file never changes when that answer does.

```bash
curl -s -X POST localhost:5000/refunds/rf-0002/approve -H 'x-user: dana'
# {"_authz":{"decision":"allow", ...},
#  "amount":7650,"approved_by":"dana","order_id":"ord-0091",
#  "refund_id":"rf-0002","region":"eu","status":"approved"}

curl -s -X POST localhost:5000/refunds/rf-0002/approve -H 'x-user: alice' -i | head -1
# HTTP/1.1 403 FORBIDDEN
# {"detail":"The policy denied action Action::\"refunds.approve\".","error":"AuthzDenied"}
```

### Fail closed

No principal means no call, not an unguarded one.

```bash
curl -s localhost:5000/orders -i | head -1
# HTTP/1.1 403 FORBIDDEN
# {"_authz":{"action":"Action::\"orders.search\"","decision":"deny", ...},
#  "detail":"No principal in context for action Action::\"orders.search\"; the call was denied.",
#  "error":"NoContext"}
```

## Three details worth copying

**`protect_blueprint` scopes the hooks to one blueprint.** It registers a `before_request`
hook that establishes the ambient principal, a `teardown_request` hook that releases it, and
the error handlers — on `orders` only, so an ungoverned surface can live beside it under the
same app. `protect_app` is the whole-app form.

**The release is correctness, not tidiness.** Flask serves a request on a pooled worker
thread and its test client serves one in the caller's own context, so a context left un-reset
by request *N* is still ambient when request *N+1* starts — and *N+1* would be authorized as
*N*'s principal. Never establish without wiring the teardown.

**The app is built by a factory.** `create_app()` calls `configure()` and `install()`, which
mutate process-global state; a module-level `app = create_app()` would run that wiring for
anyone who merely imported the module. `flask --app ...:serve` calls `serve()`, which builds
one app of its own, and every test builds its own with `create_app()`.
