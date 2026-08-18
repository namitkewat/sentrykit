# Concepts

## The one idea

> The caller *proposes*; the **policy decides**.

A web client or a language model says what it would like to do. sentrykit decides whether it
may, **which of the proposed arguments survive**, and **what to fill in** for the rest — then
runs the call, or refuses it, before the side effect happens.

That last clause is the positioning. sentrykit is a **pre-action** authorization layer, not
an output validator. An output validator inspects what a model produced; by then the refund
has been issued. sentrykit refuses the refund.

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
and `@protect` reads it wherever the callable lives (ADR-003). Three rules follow:

- An explicit `_as=` on the call beats the ambient principal.
- **No principal means deny.** Not "run unauthenticated", not "skip the check".
- `ContextVar` values follow `await` and `asyncio.to_thread`, but not a bare
  `ThreadPoolExecutor.submit`. Use `bind_context` for that — and note that forgetting to is
  *safe*: the worker starts with no principal, and by the previous rule that denies.

This split — the decorator supplies the action and arguments, the provider supplies the
principal and environment — is the whole reason one decorator can guard a Flask view, a
background function and an MCP tool unchanged.

## Relationships are resolved by policy

The differentiator is not that sentrykit checks a role. It is that nested, multi-hop
relationships are resolved **deterministically by Cedar's entity hierarchy**, never inferred
by a model and never reimplemented as a ladder of `if` statements.

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
relationship *is* the authorization.

An agent acting for a human is the same pattern: delegation, expressed as an edge, resolved
by the same machinery (ADR-008).

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
| `deny` | The value must not be one of these |
| `pattern` | A regex the value must match in full |
| `minimum` / `maximum` | Inclusive numeric bounds |
| `default` | Injected when the caller supplies none, or theirs was dropped |
| `required` | The call cannot proceed without it |

An argument with **no entry** is unconstrained — the coarse gate already permitted the call.
An argument with an *empty* constraint is also unconstrained. Neither is a deny.

A few deliberate sharp edges:

- A default **never overrides** a value that survived filtering. The caller's own valid input
  wins.
- `True` does not match an allow-set of `(1,)`, and a `bool` is not a number for range
  purposes — Python would say otherwise, and authorization is the wrong place for that
  surprise.
- An unparseable `pattern` **rejects the value** and logs once, rather than raising. Filtering
  promises not to raise, so a malformed grant fails closed.

## Errors

| Error | Raised when |
| --- | --- |
| `NoContext` | No ambient principal and no `_as=`. Fail-closed, always. |
| `AuthzDenied` | The gate refused. Carries `determining_policies` and, for engine failures, `engine_errors`. |
| `ArgumentRejected` | An argument violated its constraint under `arg_handling="strict"`. |
| `NoValidArguments` | The caller supplied arguments and **every one** was rejected. |
| `DefaultUnavailable` | A required argument has neither a supplied value nor a default. |
| `ValidationFailed` | The final argument set failed the callable's model. Carries pydantic's structured errors. |
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

## Verbosity

The envelope trades transparency against disclosing policy structure and argument values.
Trimming happens when the envelope is *built*, so a field excluded by verbosity is never
carried on the object at all.

| | `off` | `summary` | `verbose` | `debug` |
| --- | --- | --- | --- | --- |
| Envelope at all | — | yes | yes | yes |
| Decision, action, resource, reason | — | yes | yes | yes |
| Rejected argument names and reasons | — | yes | yes | yes |
| Rejected argument **values** | — | — | yes | yes |
| Principal, processed arguments | — | — | yes | yes |
| `defaults_applied` values | — | names only | yes | yes |
| Determining policies, trace | — | — | — | yes |

At `summary`, `defaults_applied` keeps the argument names as keys with `null` values, so the
field has one shape at every verbosity and `defaults_applied.keys()` always works.

## Two output channels, never conflated

- **Operational logs** — ordinary `logging`, for developers. Ephemeral. Argument *names*,
  rules and policy ids; never values. A deny is normal operation and logs at `INFO`.
- **The audit log** — not `logging`. A tamper-evident record stream, masked before the write,
  written append-only. It is a data product, not a side effect. (Phase 2.)

## What sentrykit is not

- Not a content filter or an output validator. It refuses the side effect, not the text.
- Not an authentication system. It decides what an already-identified principal may do.
- Not a place for business rules that are not authorization decisions.
