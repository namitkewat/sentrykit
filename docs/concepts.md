# Concepts

## The one idea

> The caller *proposes*; the **policy decides**.

A web client or a language model says what it would like to do. sentrykit decides whether it
may, **which of the proposed arguments survive**, and **what to fill in** for the rest — then
runs the call, or refuses it, before the side effect happens.

That last clause is the positioning. sentrykit is a **pre-action** authorization layer, not
an output validator. An output validator inspects what a model produced; by then the refund
has been issued. sentrykit refuses the refund.

Five things follow from the one idea, and the rest of this page is mostly about them:

1. **Argument constraints resolved per `(principal, action)`** — allow-sets, deny-sets,
   patterns and numeric bounds, decided per argument.
2. **Narrowing instead of refusal.** A value above what the principal may have is rejected
   and their own default fills the gap, so the call proceeds. Narrowing *refines* a proposal
   rather than rescuing one: with no default configured the argument is simply dropped, and if
   every argument the caller supplied is rejected the call is refused.
3. **Defaults supplied by the principal's grant** for the arguments the caller omitted — and
   for the ones that were just dropped.
4. **Constraints validated when they are written.** A constraint no value could satisfy is
   refused at the grant rather than discovered by whoever calls next.
5. **A record of every decision and every admin mutation**, masked before the append-only
   write, hash-chained, and pinned to a digest of the policy logic that produced it.

Sitting across the first four: an **argument ceiling** declared in reviewed policy text says
what *anybody* may pass for an action, and intersects with what the store grants this
principal — so the reviewed file states the maximum and can only narrow.

## The pipeline

Every protected call runs through the same six steps, in this order:

```
gate  ->  filter args  ->  inject defaults  ->  validate  ->  invoke  ->  envelope
```

The order carries meaning:

1. **Gate.** Cedar answers one boolean question: may this principal perform this action on
   this resource, in this context? There is no point reasoning about arguments for a call
   that is not permitted at all.
2. **Filter.** Each proposed argument is checked against the constraints granted to this
   principal for this action — allow-set, deny-set, pattern, range. Violations become
   *data*, not exceptions.
3. **Defaults.** Arguments the caller omitted — *and arguments that were just dropped* — are
   filled in from the principal's defaults. Filtering has to come first for this to work: a
   dropped argument gets replaced rather than leaving a hole.
4. **Validate.** The final argument set is checked against a pydantic model derived from the
   callable's own signature. Running last means the callable never sees a value policy did
   not sanction, and a validation failure is genuinely about types rather than about
   authorization.
5. **Invoke.**
6. **Envelope.** The caller is told what was processed, rejected and defaulted.

`Governor.plan()` performs steps 1–4 and `Governor.invoke()` performs 5–6. They are separate
so a decision can be reached *without* performing the side effect — which is what tool-manifest
filtering needs in order to decide whether a model should even be shown a tool.

## Who is acting: ambient context

A protected callable rarely receives the principal as an argument. A Flask view takes a
request; an agent tool takes whatever the model proposed; a background job takes nothing.
Threading a principal through every signature between the boundary and the call is the tax
that stops teams from protecting inner functions at all.

So a **context provider** calls `establish(principal, **environment)` once at the boundary,
and `@protect` reads it wherever the callable lives. Three rules follow:

- An explicit `_as=` on the call beats the ambient principal.
- **No principal means deny.** Not "run unauthenticated", not "skip the check".
- `ContextVar` values follow `await` and `asyncio.to_thread`, but not a bare
  `ThreadPoolExecutor.submit`. Use `bind_context` for that — and note that forgetting to is
  *safe*: the worker starts with no principal, and by the previous rule that denies.

This split — the decorator supplies the action and arguments, the provider supplies the
principal and environment — is the whole reason one decorator can guard a Flask view, a
background function and an MCP tool unchanged.

## Policies-as-code, grants-as-data

Cedar separates policy *logic* from *entity data*, and sentrykit leans on that split:

- **Policy logic** lives in files and changes through review. Git history is the
  change-control evidence.
- **Grants** are data — a role is a parent edge, an argument constraint is an attribute, a
  time-boxed grant is an attribute plus a `context.now` condition.

"Add a role" is therefore CRUD on entity data; reviewed policy logic never changes at
runtime. Because `Action::"admin.grant"` is an ordinary Cedar action, the admin surface ends
up governed by the same engine it administers.

## Argument constraints

Constraints are resolved per `(principal, action)`. Lookup runs least- to most-specific: the
`"*"` wildcard set, then the bare action id, then the full uid — each layered over the last,
so a baseline can be refined per action.

| Rule | Effect |
| --- | --- |
| `allow` | The value must be one of these |
| `deny` | Neither the value nor anything inside it may be one of these |
| `pattern` | A regex the value must match in full |
| `minimum` / `maximum` | Inclusive numeric bounds |
| `default` | Injected when the caller supplies none, or theirs was dropped |
| `required` | The call cannot proceed without it |

An argument with **no entry** is unconstrained — the coarse gate already permitted the call.
An argument with an *empty* constraint is also unconstrained. Neither is a deny.

A few deliberate sharp edges:

- A default **never overrides** a value that survived filtering. The caller's own valid input
  wins.
- A default is **checked against its own constraint** before it is injected, and one that
  fails is withheld rather than applied. Otherwise the way to defeat a constraint would be to
  stop proposing a value: a supplied value is filtered, an omitted one is filled in, and only
  the first path would have run a check.
- **The callable's own default is a default too, and answers to the same rule.** When a
  governed argument ends up with no value — the caller proposed none that survived, and the
  grant holds none — sentrykit passes nothing for it, and Python fills the slot from the
  signature. That value is checked against the constraint like any other default: if it
  satisfies the rule the call proceeds on it and the envelope names the parameter in
  `signature_defaults`; if it does not, the call is refused with `SignatureDefaultRejected`.
  Without that check a bound could be exceeded *upward* — a caller refused a value above a
  ceiling would run on the signature's value instead, which may be larger than the one they
  asked for.
- `True` does not match an allow-set of `(1,)`, and a `bool` is not a number for range
  purposes — Python would say otherwise, and authorization is the wrong place for that
  surprise.
- An unparseable `pattern` **rejects the value** and logs once, rather than raising. Filtering
  promises not to raise, so a malformed grant fails closed.
- **`deny` reads inside containers; every other rule judges the whole value.** A deny-set is
  matched against the value and then against what the value *contains* — list and tuple
  elements, set members, and both the keys and the values of a mapping, recursively. So
  `deny=("prod",)` refuses `"prod"` and `["dev", "prod"]` alike, and wrapping a forbidden value
  in a list is not a way past the rule. `allow`, `pattern` and the bounds do the opposite: they
  compare the value as a whole, so a container is refused outright rather than checked
  element-wise. The asymmetry is deliberate — reading a *denial* element-wise can only refuse
  more, while reading a *permission* element-wise would have to decide what `allow=("eu","uk")`
  means for `["eu"]` or for `[]`, and a wrong answer there grants something nobody granted.
  There is no way to say "every element must be in this set" today.
- A structure nested beyond a fixed depth, or one that refers to itself, is **refused** by a
  deny-set rather than searched. A value that cannot be read cannot be shown to satisfy a rule.
- **A numeric bound compares anything real.** `int`, `float`, `Decimal` and `Fraction` all work,
  each at its own precision — which is what makes `maximum=1000` usable on
  `def issue_refund(amount: Decimal)`. The bound itself is written as an `int` or a `float`;
  `Decimal` compares against both exactly, so nothing is lost. A NaN satisfies no bound and is
  reported as not comparable, in either direction.

### Two layers: the grant and the ceiling

Constraints reach a decision from two places, and they **intersect**:

- a **grant** in the store says what *this principal* may pass — mutable, per-principal, and
  the only layer that can carry a `default`;
- a **ceiling** declared in a reviewed `.cedar` file says what *anybody* may pass for that
  action — version-controlled, covered by the policy-set hash, and unable to widen anything.

Because intersection can only narrow, the reviewed file states the maximum and the store
states what each principal actually has. A ceiling is also the one thing a policy can declare
that reaches narrow-and-continue rather than the gate: Cedar can only deny, so "you asked for
500, you may not have that — here is the call with your own default instead" has nowhere else
to live. See [Argument ceilings](policies.md#argument-ceilings).

### A constraint has to be satisfiable

Because constraints are data, one can be written that nothing satisfies. `minimum=100,
maximum=10` is the obvious case; a permitted value the pattern rejects and a default outside
the allow-set are the quieter ones. Discovered at call time, each is a refusal of everything,
found by whoever calls next.

`ArgumentConstraint.inconsistencies()` names them, and a grant store runs it **at the write**:

```python
store.grant(GrantSpec(principal=..., kind="constraint", subject="limit",
                      constraint=ArgumentConstraint(minimum=100, maximum=10)))
# ConfigurationError: the constraint on argument 'limit' cannot be satisfied: ...
```

Four checks: the pattern compiles, `minimum` is not above `maximum`, every `allow` member
satisfies the constraint's other rules, and a configured `default` satisfies the constraint.
The last two delegate to the same `check()` the filter runs, so what a grant promises and what
the filter enforces cannot drift apart.

The check is deliberately **not** a validator on the model itself. A store also *reads*
constraints, and refusing at construction would make one bad row already on disk fail the load
of every principal in the file — a wider refusal than the fault deserves. The write is where
the fault is introduced and where someone is present to fix it; the call path stays fail-closed
per argument either way.

## Relationships compose underneath

The argument layer stands on Cedar's gate, and composes with what the engine underneath is
already good at. Nested, multi-hop relationships — user → team → project → resource,
delegation, on-behalf-of, expiry, break-the-glass — are resolved **deterministically by
Cedar's entity hierarchy**, never inferred by a model and never reimplemented as a ladder of
`if` statements.

Roles, teams, projects and delegation edges are all the same thing: a parent edge. Cedar
computes the transitive closure, so a policy can name only the far end of a chain:

```cedar
@id("project-members-may-read-project-orders")
permit (
  principal in Project::"orders-eu",
  action == Action::"order.read",
  resource in Project::"orders-eu"
);
```

Given `alice -> Team::"eu-support" -> Division::"emea" -> Project::"orders-eu"` and
`Order::"o-1" -> Project::"orders-eu"`, alice may read the order. The policy mentions neither
the team nor the division. Sever any one edge and the access disappears — because the
relationship *is* the authorization. An agent acting for a human is the same pattern:
delegation, expressed as an edge, resolved by the same machinery.

The constraints then apply to whatever that chain permitted: the hierarchy decides *whether*
the call may happen, and the argument layer decides what it may carry.

## Errors

| Error | Raised when |
| --- | --- |
| `NoContext` | No ambient principal and no `_as=`. Fail-closed, always. |
| `AuthzDenied` | The gate refused. Carries `determining_policies` and, for engine failures, `engine_errors`. |
| `ArgumentRejected` | An argument violated its constraint under `arg_handling="strict"`. |
| `NoValidArguments` | The caller supplied arguments and **every one** was rejected. |
| `DefaultUnavailable` | A required argument has neither a supplied value nor a default. |
| `ValidationFailed` | The final argument set failed the callable's model. Carries pydantic's structured errors. |
| `ReservedKey` | Supplied data spelled one of Cedar's reserved `__` keys. Refused under either fail mode. |
| `ConfigurationError` | Bad settings, an unparseable policy, or no installed governor. |

`NoValidArguments` fires *even when defaults could complete the call*. That is deliberate:
filling in defaults after discarding the entire request would answer a question the caller
did not ask — they wanted one customer's orders and would silently get their own. Partial
rejection is different, and narrows.

## Fail modes

`fail_mode` is the most commonly misread setting, so it is worth stating plainly. It
arbitrates **engine failure only**:

| Situation | `closed` | `open` |
| --- | --- | --- |
| A policy denies | deny | **deny** |
| No policy matches | deny | **deny** |
| No principal | deny | **deny** |
| Cedar cannot evaluate (unparseable policy, evaluation error) | deny | allow, and record the failure |

Conflating a policy denial with an engine failure would let a typo in a policy quietly open a
door. `AuthzDenied.engine_errors` is populated only in the last row, so an operator can tell
a correctly enforced boundary from a broken policy set.

The last row has one exception. A failed evaluation reports no determining policies, so it
also reports no [argument ceilings](policies.md#argument-ceilings) — the call would proceed
*unbounded*. A governor whose policy set declares any ceiling therefore refuses an engine
failure under either fail mode.

`fail_mode="open"` exists to tolerate *operator* error — a policy set that will not evaluate
should not take an application down with it. It is not a tolerance for caller input, which is
why the boundary below is enforced ahead of the gate rather than through it.

## Arguments as policy input

The proposed arguments are exposed to policy as `context.args`, so a Cedar `forbid` can
inspect them directly. That backstop is defense in depth: the Python-side filter is the
enforcement, and the `forbid` catches a filter that was never configured.

Everything in `context.args` is **caller data**. Two consequences follow, and the second one
is the sharp edge.

### Supplied data cannot spell Cedar's escape forms

Cedar's request JSON reserves record keys beginning with `__` for its own escape forms:
`__entity` promotes a record into a typed entity reference, `__extn` into an extension value.
sentrykit refuses any supplied mapping that spells one, anywhere in the request, with
`ReservedKey` — so a `dict`-valued argument cannot promote itself into a typed entity.

The refusal is deliberately not routed through `fail_mode`: it happens before Cedar is
consulted, so there is no engine failure for `open` to tolerate.

### An entity-valued argument lets the caller choose the entity — *type included*

If your callable annotates a parameter as `EntityRef`, you have said that the caller names an
entity, and every web and agent integration validates the caller's JSON against that
annotation **before** the decorator runs. `{"type": "Region", "id": "eu"}` therefore reaches
policy as a genuine `Region::"eu"` — and `{"type": "Group", "id": "approved"}` reaches it as a
genuine `Group::"approved"`, because the caller picked the type too.

That matters because Cedar's `in` is reflexive, so this looks like a guard and is not one:

```
@id("region-must-be-approved")
forbid (principal, action, resource)
when { context.args has region && !(context.args.region in Group::"approved") };
```

A caller who passes the *approved group itself* as the region is trivially "in" it, and the
`forbid` does not fire. **Pin the type.** Cedar's `is` operator is the whole fix:

```
@id("region-must-be-approved")
forbid (principal, action, resource)
when {
  context.args has region &&
  !(context.args.region is Region && context.args.region in Group::"approved")
};
```

Two further defenses, either of which also closes it, and which compose:

- **Bound the argument.** An allow-set of `EntityRef` values in a grant, or an
  [argument ceiling](policies.md#argument-ceilings) in the policy, decides which entities the
  caller may name before Cedar ever sees the value.
- **Declare a Cedar schema.** A schema saying `args.region` is a `Region` makes the mismatched
  request fail to parse at all, which is `no-decision` — refused under the default
  `fail_mode="closed"`.

If a parameter is not meant to be caller-chosen, do not annotate it as an `EntityRef`: build
the reference in your own code from something you trust.

## Verbosity

The envelope trades transparency against disclosing policy structure and argument values.
Trimming happens when the envelope is *built*, so a field excluded by verbosity is never
carried on the object at all.

| | `off` | `summary` | `verbose` | `debug` |
| --- | --- | --- | --- | --- |
| Envelope at all | — | yes | yes | yes |
| Decision, action, resource, reason | — | yes | yes | yes |
| `narrowed`, `narrowed_arguments`, `guidance` | — | yes | yes | yes |
| Rejected argument names and reasons | — | yes | yes | yes |
| Rejected argument **values** | — | — | yes | yes |
| Principal, processed arguments | — | — | yes | yes |
| `defaults_applied` values | — | names only | yes | yes |
| Determining policies, trace | — | — | — | yes |

At `summary`, `defaults_applied` keeps the argument names as keys with `null` values, so the
field has one shape at every verbosity and `defaults_applied.keys()` always works.

The three outcome fields have nothing for verbosity to trim: `narrowed` is a boolean,
`narrowed_arguments` repeats names that `rejected` already carries at `summary`, and `guidance`
is a sentence built from those names alone — no values, no policy ids. That is deliberate. A
caller who may not be told *which* value was refused can still be told *that* the result is good,
and withholding the outcome from them is how a successful narrowed call gets reported as a
failure.

### Narrowing is defined against the proposal

`narrowed` is true when the call ran with a value the caller did **not** propose. That is not the
same as `rejected` being non-empty, and the difference runs both ways:

| situation | `rejected` | `narrowed` |
| --- | --- | --- |
| a proposed value was refused and refilled from the principal's default | non-empty | **true** |
| a proposed value was refused and nothing refilled it | non-empty | **true**, and `guidance` marks it unverified |
| a value was refused but the argument kept a surviving value of the caller's own | non-empty | false |
| a default was injected for an argument the caller never mentioned | empty | **false** — nothing was taken away |
| a configured default was withheld for failing its own constraint | non-empty | false, unless the caller proposed that argument |

`narrowed` is omitted from the rendered envelope when false, so an ordinary allow stays terse.

### How the envelope reaches you, and why `_authz` is the second-best way

There are two channels, and the one most people meet first is the narrower of the two.

**`last_envelope()` is the mechanism.** Every decision — allow and refusal alike — leaves its
envelope on the context, whatever the protected callable returned. That is the channel the
framework providers read, and the only one that always works.

**The `_authz` key is a convenience layered on top.** When a protected callable returns a
*mapping*, sentrykit writes the envelope into it under `_authz`, so the report travels with the
answer and an agent's model reads it without anyone wiring anything. That is genuinely useful
and it is why the README leads with it. But it is conditional on your return type, and the
condition is not a small one:

```python
@protect(action="orders.search")
def as_dict(region: str = "eu") -> dict:       # -> {"region": "eu", "_authz": {...}}
    ...

@protect(action="orders.search")
def as_list(region: str = "eu") -> list[dict]:  # -> [{"region": "eu"}]   no _authz, ever
    ...
```

A `list`, a `str`, a pydantic model and `None` cannot carry a key, and rewrapping them would
change your function's declared return type. A web route returning a JSON array is the most
common shape there is, so **do not read `_authz` as the mechanism** — if you do, narrowing is
invisible for most of your surface and you will not find out from a test that only exercises a
dict-returning handler.

What you get instead, without doing anything:

| boundary | channel | carries |
| --- | --- | --- |
| any protected call | `last_envelope()` | the whole envelope |
| FastAPI / Flask route | `x-sentrykit-narrowed`, `x-sentrykit-narrowed-arguments` response headers | that it happened, and to which arguments |
| MCP tool | `_meta` keys `sentrykit/narrowed`, `sentrykit/narrowedArguments`, plus one appended text block carrying `guidance` | the facts, and the sentence the model reads |
| Pydantic-AI tool | `ToolReturn` — `metadata` for your application, `content` as an extra prompt part | the facts, and the sentence the model reads |

The headers appear **only when something was narrowed**, which is the same rule the `narrowed`
field follows. `guidance` is deliberately not a header: it is prose, it runs past 300
characters, and an HTTP field value cannot spell it. The agent adapters *append* rather than
substitute, so the tool's own result reaches the model untouched and the note rides beside it.

Behind the headers is an `EnvelopeRecorder`, installed per request by the provider, which
accumulates every decision in the response rather than keeping only the last — a route may make
several protected calls, and "was anything narrowed while serving this" is the question a
response-level report has to answer. It also solves a problem `last_envelope()` cannot: a
**sync** framework route runs in a worker thread holding a context *copy*, so nothing it sets
survives its return. The recorder is a mutable object reached *through* the context variable, so
the copy points at the same instance and the mutation reaches the boundary. A hand-written
`ContextProvider` that does not inherit `BaseContextProvider` needs to call `record_decisions()`
and close it to get any of this. See ADR-029.

## Two output channels, never conflated

- **Operational logs** — ordinary `logging`, for developers. Ephemeral. Argument *names*,
  rules and policy ids; never values. A deny is normal operation and logs at `INFO`.
- **The audit log** — not `logging`. A hash-chained record stream, masked before the write,
  written append-only. It is a data product, not a side effect. The chain is *detection, not
  prevention* — [Audit & compliance](audit.md) states what it does and does not cover.

## What sentrykit is not

- Not a content filter or an output validator. It refuses the side effect, not the text.
- Not an authentication system. It decides what an already-identified principal may do.
- Not a place for business rules that are not authorization decisions.

Nor is it a policy engine in its own right. General-purpose engines — Cedar (including Amazon
Verified Permissions), OPA, Casbin — and relationship-based systems such as OpenFGA answer a
boolean question at the gate: may this principal perform this action on this resource.
sentrykit is built on Cedar, and adds the layer above that decision: which arguments
the call may carry, which defaults to supply when the caller omits them, and a record of
both. If you already run a policy engine, that argument layer is the part you would otherwise
assemble yourself.
