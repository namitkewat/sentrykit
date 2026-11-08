# Example: pydantic_ai_agent

One agent, seven governed tools, three humans — and a manifest that changes depending on whose
behalf the agent is running. The model **proposes** a call; the **policy decides** whether it
happens, which arguments survive it, and which values fill the gaps.

It runs with nothing installed beyond the `agent` environment, and it uses a real model when
one is within reach. Every authorization outcome is identical either way.

## On-behalf-of is the whole point

An agent acting for a human **is** that human, as far as the policy is concerned. There is no
bot identity, no service account, and no `delegated_by` anywhere in `policy.py` or in
`policies/*.cedar` — `alice`'s role edge and `alice`'s argument constraints are what govern the
call *her agent's model* proposed. The delegation is expressed by the application choosing
whose `deps` it runs with, and by nothing else.

That is also why the model cannot reach it. `deps` is supplied by the application at `run()`
time and never appears in anything the model can write: not in the prompt it sees, not in the
tool schemas, not in the arguments it proposes.

## Layout

| File | What is in it |
| --- | --- |
| `policies/10-orders.cedar` | Reviewed Cedar *logic* for the orders desk, including the argument ceiling |
| `policies/20-refunds.cedar` | Reviewed Cedar logic for refunds — two rules about the relationship *between* arguments |
| `policy.py` | `POLICY_DIR`/`POLICY_TEXT`, and `build_grants()`: the entity graph, roles and per-principal argument rules — *data* |
| `service.py` | The eight `@protect`-ed callables. No `RunContext`, no `deps`, no LLM |
| `agent.py` | `build_agent()`: settings, grants, policy, provider, `governed_tool` — plus the deterministic drivers `offered_tools`, `propose`, `dispatch` and the printed demonstration |

The callables in `service.py` do real work: they read and write [`examples.desk`](../desk), a
seeded SQLite orders desk that takes no principal and imports nothing from sentrykit. That is
what makes narrowing legible rather than merely reported — a `limit` refilled with 10 brings
back ten orders, and a caller refused `region="cn"` is left holding the orders of the region
policy gave them instead of a field that says `eu`.

Policy logic is loaded from the directory, never from a string:

```python
install(
    policy_source=FilesystemPolicySource(POLICY_DIR),
    grant_store=store,
    context_provider=provider,
)
```

`policies=` and `policy_source=` are mutually exclusive, which is the wiring saying out loud
that there is one place policy logic lives.

## Who may do what

| Principal | Role grant | Team | May |
| --- | --- | --- | --- |
| `alice` | `support` | `eu-support` | search, read EU orders, brief, issue refunds up to the desk limit |
| `bob` | `auditor` | `us-support` | export orders |
| `dana` | `admin` | `eu-support` | everything support may do, plus approve refunds and exceed the desk limit |

`Role::"admin"` has `Role::"support"` as a parent, so dana satisfies `principal in
Role::"support"` without a second grant. `Team::"eu-support"` → `Division::"emea"` →
`Project::"orders-eu"`, and `Order::"ord-0003"` hangs off the same project — which is how
`read_order` is decided without either side of the permit naming a person.

Their argument rules, all of them *data* in the grant store:

| Principal | Action | Argument | Rule | Default |
| --- | --- | --- | --- | --- |
| `alice` | `orders.search` | `region` | allow-set `eu`, `uk` | `eu` |
| `alice` | `orders.search` | `limit` | maximum 50 | `10` |
| `alice` | `refunds.issue` | `order_id` | pattern `ord-[0-9]{4}` | none |
| `alice` | `refunds.issue` | `amount` | minimum 1, maximum 750 | `50` |
| `alice` | `refunds.issue` | `region` | allow-set `eu`, `uk` | `eu` |
| `bob` | `orders.export` | `fmt` | deny-set `xml` | `csv` |
| `dana` | `orders.search` | `limit` | none of her own | `25` |
| `dana` | `orders.search` | `region` | none of her own | `eu` |

## Running it

```bash
pixi run -e agent run-agent        # python -m examples.pydantic_ai_agent.agent
```

It prints each principal's manifest, every flow below with its outcome, the ceiling case, the
nested decision, which policy decided two refusals, and then a free-form run on whatever model
it found. sentrykit logs a `Argument dropped by policy` warning on stderr for every rejection,
one per narrowed argument.

`build_agent()` calls `configure(verbosity="verbose")` so the envelope carries processed
values, applied defaults and rejection reasons — the model is one of the audiences for that
explanation, and it is what lets it choose a different call instead of guessing. A production
agent would leave it at `summary`.

Nothing is wired at import: there is no module-level `agent = build_agent()`, because
`configure()` and `install()` mutate process-global state and `default_model()` probes the
network, and importing a module should do neither.

`demonstrate()` resets the desk before it drives anything, because several flows **write**: a
permitted refund books a row with a freshly allocated id, and an export books a job. Starting
from identical rows is what makes two runs agree and the ids below worth quoting. Building the
agent resets nothing — a service that emptied its database on startup would be a poor example
of anything.

### The optional live model

The free-form section runs on a local [Ollama](https://ollama.com) daemon when there is one —
no API key, no account:

1. install Ollama;
2. pull a model whose template supports tools, e.g. `ollama pull qwen2.5:3b`;
3. optionally `SENTRYKIT_OLLAMA_MODEL=qwen2.5:3b` to pin which one, and
   `SENTRYKIT_OLLAMA_URL` if the daemon is not on `http://localhost:11434`.

Setting `SENTRYKIT_OLLAMA_URL` to an *empty* value turns the search off outright — no socket is
opened and the deterministic model is used. That is how the test suite stays hermetic, and it
is also the switch to reach for when you have a daemon and want the reproducible run anyway.

With a daemon answering, that section reads like this — the model chose the tool and drafted
the arguments itself:

```
model: OpenAIChatModel (gemma4:e4b)

alice : proposed brief_orders
        answered The desk has 198 orders open, spread across three regions -- 81 in the EU, 54 in the UK and 63 in the US. The oldest one still open is ord-0319.
bob   : proposed export_orders, export_orders
        answered I started a CSV export of the open orders. It covers 81 orders and came back as job exp-0004.
```

With none, `pydantic_ai.models.test.TestModel` drives the same tools with generated arguments
and prints why:

```
model: TestModel
  -- no tool-capable model answered at http://127.0.0.1:1
This section runs on a stand-in that calls every visible tool with generated
arguments. Install Ollama and pull a tool-capable model to see a real one
propose these calls; every authorization outcome above is identical either way.
```

The fallback is not a lesser mode. Every authorization outcome in the table below is identical
either way, because the decision is made from the principal and the proposed arguments and
never from which model proposed them. A live model adds one thing: sometimes it drafts a call
badly, and watching sentrykit refuse a call the model should not have proposed is the point,
not a failure of the demonstration. A small model can also exceed its retries or answer
malformed JSON; the example catches that and prints it, and the policy layer is unaffected.

## The four surfaces an argument rule can be written on

1. **The decorator.** `@protect` bare — `desk_status` — derives
   `Action::"examples.pydantic_ai_agent.service.desk_status"` from the callable's import path
   and synthesizes a matching resource. Convenient, and fragile in one way: renaming or moving
   the function changes the id and the policy stops matching, so pass an explicit `action=` as
   soon as the policy is expected to outlive the module layout. `@protect` also accepts
   `governor=`, pinning a callable to a specific `Governor` instead of the process default.
2. **The grant store.** Allow-sets, deny-sets, patterns, minimums, maximums and defaults, per
   principal and per action — the table above. This is the half an admin surface may mutate.
3. **Reviewed policy.** `@constraints` in `policies/10-orders.cedar` is a **Cedar policy
   annotation, not a Python decorator**. It declares an argument *ceiling*: what anybody
   reaching that permit may pass. It intersects with the principal's own grant and can only
   narrow.
4. **The whole request.** `refunds-above-the-desk-limit-need-an-admin` weighs a proposed
   argument against the principal; `no-large-cross-region-refunds` weighs two proposed
   arguments against each other. Both are Cedar evaluating the request it was given at once;
   sentrykit needs no new syntax for either, and no per-argument rule could express either.

## Things to try

Every snippet below runs offline. Start here:

```python
import asyncio

from pydantic_ai.models.test import TestModel

from examples.pydantic_ai_agent.agent import (
    Caller,
    build_agent,
    dispatch,
    offered_tools,
    propose,
)
from examples.pydantic_ai_agent.service import (
    approve_refund,
    export_orders,
    read_order,
    search_orders,
)

agent = build_agent(TestModel())      # passing a model skips the daemon probe
```

`offered_tools` reports what the *model* was told exists, by running one turn on a
`FunctionModel` that calls nothing and reports `AgentInfo.function_tools`. `propose` makes the
model propose exactly one tool call and returns what came back. `dispatch` goes around the
model entirely and invokes the governed tool by name.

### The manifest is per-caller

Same agent, same seven registered tools:

```python
asyncio.run(offered_tools(agent, Caller("alice")))
# ['desk_status', 'brief_orders', 'search_orders', 'read_order', 'issue_refund']
asyncio.run(offered_tools(agent, Caller("bob")))
# ['desk_status', 'export_orders']
asyncio.run(offered_tools(agent, Caller("dana")))
# ['desk_status', 'brief_orders', 'search_orders', 'read_order', 'issue_refund', 'approve_refund']
```

A manifest probe proposes no arguments, so a permit that read `context.args` would evaluate to
false against it and hide the tool from everybody — including the people who may use it. That
is why `support-may-issue-refunds` is unconditional and the desk limit is a separate `forbid`:
the entitlement is decidable before the model proposes anything, and the argument rules are
decided once it has. Where a policy genuinely has to be written the other way,
`governed_tool(..., filter_manifest=False)` opts that one tool out of filtering, and
enforcement is completely intact.

### 1 — the bare decorator

```python
asyncio.run(propose(agent, Caller("alice"), "desk_status"))
# {'desk': 'orders', 'open': True, 'open_orders': 198, 'pending_refunds': 4,
#  '_authz': {'decision': 'allow',
#             'action': 'Action::"examples.pydantic_ai_agent.service.desk_status"',
#             'resource': 'Resource::"examples.pydantic_ai_agent.service.desk_status"',
#             'principal': 'User::"alice"'}}
```

### 2 — a protected callable that is not a tool

`brief_orders` is a tool; its body calls `summarize_orders`, which is protected and is *not*
registered. Two decisions, two envelopes, one tool call:

```python
asyncio.run(propose(agent, Caller("alice"), "brief_orders"))
# {'brief': {'open_orders': 198, 'regions': {'eu': 81, 'uk': 54, 'us': 63},
#            'oldest_open': 'ord-0319',
#            '_authz': {'decision': 'allow', 'action': 'Action::"orders.summarize"',
#                       'resource': 'Tool::"orders"', 'principal': 'User::"alice"'}},
#  'open_orders': 198,
#  'headline': '198 open orders across 3 regions, oldest ord-0319',
#  'orders': ['ord-0001', 'ord-0003', 'ord-0006'],
#  '_authz': {'decision': 'allow', 'action': 'Action::"orders.brief"',
#             'resource': 'Tool::"orders"', 'principal': 'User::"alice"'}}
```

It names three ids and reports the true total beside them, so the distance between the whole
order book and what was served is in the answer itself. Three is `BRIEF_LIMIT` in
`service.py`: `brief_orders` has no parameter to put it in, and adding one would change what
the model is told it may propose.

The gate is on the *call*, not on the registration: no model was ever told `summarize_orders`
exists, and it is decided anyway. Two decisions means two audit records at whatever sink is
wired, and the outer one is written before the body runs, so a refusal inside cannot erase the
fact that the outer call was permitted. An inner refusal propagates out unchanged rather than
becoming a partial answer.

### 3 — default injection

`region` and `limit` have no Python defaults, so the model may leave both out — and then every
value the call runs with came from alice's grants:

```python
asyncio.run(propose(agent, Caller("alice"), "search_orders"))
# {'region': 'eu', 'limit': 10, 'status': 'open', 'count': 10,
#  'orders': [{'order_id': 'ord-0003', 'region': 'eu', 'status': 'open',
#              'customer': 'Marta Rossi', 'total': 93500, 'items': 2},
#             ...],   # ten rows, lowest id first
#  '_authz': {'decision': 'allow', 'action': 'Action::"orders.search"',
#             'resource': 'Tool::"orders"', 'principal': 'User::"alice"',
#             'processed': {'status': 'open', 'region': 'eu', 'limit': 10},
#             'defaults_applied': {'region': 'eu', 'limit': 10}}}
```

`status` is not in `defaults_applied`, because it was never absent: it has a Python default,
nobody's policy has an opinion about it, and Python answered for it.

`limit` is readable twice over in that result — as the number the call ran with, and as the
number of rows it brought back. The two agree because the second was produced by the first.

### 4 — an allow-set, rejected and refilled

`cn` is not in alice's allow-set, so it is thrown away and her own default takes its place. The
call still succeeds and the envelope says exactly what happened:

```python
asyncio.run(propose(agent, Caller("alice"), "search_orders", region="cn", limit=5))
# {'region': 'eu', 'limit': 5, 'status': 'open', 'count': 5,
#  'orders': [...],   # five EU orders -- the region she was given, not the one she asked for
#  '_authz': {'decision': 'allow', 'action': 'Action::"orders.search"',
#             'resource': 'Tool::"orders"', 'principal': 'User::"alice"',
#             'processed': {'limit': 5, 'status': 'open', 'region': 'eu'},
#             'rejected': [{'name': 'region', 'rule': 'allow-set',
#                           'reason': 'Value is not one of the permitted values',
#                           'policy': 'alice-region', 'value': 'cn'}],
#             'defaults_applied': {'region': 'eu'}}}
```

### 5 — several arguments processed in one call

One rejected and refilled, one omitted and defaulted, one untouched:

```python
asyncio.run(propose(agent, Caller("alice"), "search_orders", limit=500, status="open"))
# -> narrowed: limit=500 rejected (maximum, alice-limit) -> limit=10; defaulted: region='eu'
```

### 6 — the ceiling, and why the answer is not the bound

dana has no `limit` bound of her own, so the ceiling declared in `policies/10-orders.cedar` is
her only one. She proposes 500. The ceiling is 100. She runs with **25** — her own default:

```python
asyncio.run(propose(agent, Caller("dana"), "search_orders", limit=500, status="open"))
# {'region': 'eu', 'limit': 25, 'status': 'open', 'count': 25,
#  'orders': [...],   # twenty-five rows, where alice's identical call brought back ten
#  '_authz': {'decision': 'allow', 'action': 'Action::"orders.search"',
#             'resource': 'Tool::"orders"', 'principal': 'User::"dana"',
#             'processed': {'status': 'open', 'limit': 25, 'region': 'eu'},
#             'rejected': [{'name': 'limit', 'rule': 'maximum',
#                           'reason': 'Value is above the maximum of 100',
#                           'policy': 'support-may-search', 'value': 500}],
#             'defaults_applied': {'limit': 25, 'region': 'eu'}}}
```

Reject-and-refill: a value the principal may not pass is discarded and their default fills the
gap. The rejection names `support-may-search` because the reviewed ceiling is what refused her;
a rejection from her own grant names the grant instead.

### 7 and 8 — a relationship, resolved by Cedar

```python
asyncio.run(propose(agent, Caller("alice"), "read_order", order_id="ord-0003"))
# -> allowed
asyncio.run(dispatch(agent, Caller("bob"), read_order, order_id="ord-0003"))
# -> denied: The policy denied action Action::"orders.read".
```

Same call, same argument, same chain length. Nothing in the permit names either of them:
alice's team rolls up to `Project::"orders-eu"` and bob's to `Project::"orders-us"`.
`read_order` is hidden from bob's manifest, so the second one has to go around the model —
which is the next section's point.

Alice's answer is the order in full — customer, one-line address, priced lines and shipment —
beside `'found': True`. An id the desk does not hold comes back as `{'order_id': …, 'found':
False}` instead of raising, because an exception out of a tool body reaches the model as a
failed call, which is exactly the shape a refusal has. A row that is not there and a call that
was refused are two different answers, and blurring them would cost the model the one
distinction it most needs.

### 9, 10, 11 — one argument, three fates

```python
asyncio.run(propose(agent, Caller("bob"), "export_orders", fmt="csv"))
# -> allowed
asyncio.run(propose(agent, Caller("bob"), "export_orders", scope="open"))
# -> defaulted: fmt='csv'
asyncio.run(propose(agent, Caller("bob"), "export_orders", fmt="xml", scope="open"))
# -> narrowed: fmt='xml' rejected (deny-set, bob-fmt) -> fmt='csv'
```

A tool call carries the advertised schema's defaults, so `scope` arrives even when the model
did not propose it. That is why the third call above still narrows: `fmt` is rejected, `scope`
survives, and a rejected argument is refilled alongside whatever survived.

All three book a job, and the job is worth looking at — this is what the first of them returned:

```python
# {'job_id': 'exp-0004', 'fmt': 'csv', 'scope': 'open', 'region': 'eu', 'rows': 81,
#  'requested_by': 'bob', '_authz': {...}}
```

The desk allocates `job_id`, so it counts on from the jobs already stored; the other two book
`exp-0005` and `exp-0006`.

`requested_by` is **not** an argument. `export_orders(fmt, scope="open")` has no parameter for
it, so the body reads the ambient principal with `current_principal()` — which means the stored
row records the human the agent was acting for, and the model can neither see that name nor
influence it. That is the mechanism worth copying: a service layer can learn who it is acting
for without taking a parameter, without being handed a request, and without importing a
framework to ask. `region` is the stated `EXPORT_REGION` constant, because no argument carries
one and borrowing the `region` rule from `orders.search` would apply a rule about searching to
an export.

The stored `scope` and `region` are what make the handle worth having: the job remembers the
narrowing it was created under, so whoever presents the id later can be held to it rather than
trusted about it.

### 12 — narrowing refines a proposal, it does not rescue one

When *nothing* the caller sent survives, there is no call left to make, and a default does not
rescue it:

```python
asyncio.run(propose(agent, Caller("alice"), "issue_refund",
                    order_id="refund-me", amount=900))
# {'detail': 'Every supplied argument was rejected by policy.',
#  'error': 'NoValidArguments',
#  '_authz': {'decision': 'deny',
#             'reason': 'Every supplied argument was rejected by policy.',
#             'rejected': [{'name': 'order_id', 'rule': 'pattern',
#                           'reason': "Value does not match the required pattern 'ord-[0-9]{4}'",
#                           'policy': 'alice-order-id'},
#                          {'name': 'amount', 'rule': 'maximum',
#                           'reason': 'Value is above the maximum of 750',
#                           'policy': 'alice-amount'}],
#             'allowed': {'order_id': {'pattern': 'ord-[0-9]{4}', 'policy': 'alice-order-id',
#                                      'required': False, 'has_default': False},
#                         'amount': {'minimum': 1, 'maximum': 750, 'policy': 'alice-amount',
#                                    'required': False, 'has_default': True},
#                         'region': {'allow': ['eu', 'uk'], 'policy': 'alice-refund-region',
#                                    'required': False, 'has_default': True}}}}
```

Both proposed arguments were refused, and `region` — which has no Python default — was never
proposed at all, so there was nothing to refill alongside. `amount` has a default of 50 and it
does not rescue the call: a default fills a gap in a proposal, it does not stand in for one.

The envelope on this refusal explains the *arguments*: what was rejected, and — under
`allowed` — what would have been accepted instead, which is the most useful thing a model can
be told. It is built from the refusal rather than from a decision, so it carries no `action`
and no `resource`: the gate is not what refused. The same is true of flow 20's
`DefaultUnavailable` below.

### 13 — a policy that reads the proposed argument

`bob` may export, and still cannot export a PDF:

```python
asyncio.run(propose(agent, Caller("bob"), "export_orders", fmt="pdf"))
# {'detail': 'The policy denied action Action::"orders.export".',
#  'error': 'AuthzDenied',
#  '_authz': {'decision': 'deny',
#             'reason': 'The policy denied action Action::"orders.export".',
#             'action': 'Action::"orders.export"', 'resource': 'Tool::"orders"'}}
```

Cedar sees the caller's **raw** proposed arguments, before any per-principal filtering, so the
`forbid` reads what the model actually wrote. At `verbosity="debug"` the envelope also names
the policy that decided it: `'determining_policies': ['no-pdf-exports']`.

### 14 — the role gate, and why hiding is not the enforcement

`bob` may not search, and his model is never told the tool exists. Proposing it anyway gets the
model a correction, not a dispatch:

```python
asyncio.run(propose(agent, Caller("bob"), "search_orders", region="eu", limit=3))
# "Unknown tool name: 'search_orders'. Available tools: 'desk_status', 'export_orders'"
```

A host that ignores the manifest and dispatches the tool directly meets the identical decision:

```python
asyncio.run(dispatch(agent, Caller("bob"), search_orders))
# {'detail': 'The policy denied action Action::"orders.search".',
#  'error': 'AuthzDenied',
#  '_authz': {'decision': 'deny',
#             'reason': 'The policy denied action Action::"orders.search".',
#             'action': 'Action::"orders.search"', 'resource': 'Tool::"orders"'}}
```

### 15 and 16 — a rule about the pair, not about either argument

Both arguments are individually fine in both calls. Only the combination differs:

```python
asyncio.run(propose(agent, Caller("alice"), "issue_refund",
                    order_id="ord-0007", amount=100, region="uk"))
# -> allowed
asyncio.run(propose(agent, Caller("alice"), "issue_refund",
                    order_id="ord-0007", amount=750, region="uk"))
# -> denied: The policy denied action Action::"refunds.issue".
```

`no-large-cross-region-refunds` forbids a refund over 200 outside `eu`. No per-argument rule
could say that; Cedar evaluates the whole request and says it in four lines.

### 17 — the gate said yes, the argument layer still narrowed

```python
asyncio.run(propose(agent, Caller("alice"), "issue_refund",
                    order_id="ord-0007", amount=900, region="eu"))
# {'refund_id': 'rf-0016', 'order_id': 'ord-0007', 'amount': 50, 'region': 'eu',
#  'status': 'pending',
#  '_authz': {'decision': 'allow', 'action': 'Action::"refunds.issue"',
#             'resource': 'Tool::"refunds"', 'principal': 'User::"alice"',
#             'processed': {'order_id': 'ord-0007', 'region': 'eu', 'amount': 50},
#             'rejected': [{'name': 'amount', 'rule': 'maximum',
#                           'reason': 'Value is above the maximum of 750',
#                           'policy': 'alice-amount', 'value': 900}],
#             'defaults_applied': {'amount': 50}}}
```

900 is within the desk's limit of 1000, so the gate permitted the call. It is above alice's own
750, so the argument layer rejected the value and refilled with her default of 50. Two layers,
two different questions, one call.

The row the desk wrote carries the **50**, which is the part worth dwelling on: the side effect
that really happened is the one policy settled on, not the one the model proposed. It is also
the first snippet here with a visible side effect, so the id depends on what came before it —
the desk is seeded with fourteen refunds, the allowed call in 15 above booked `rf-0015`, and
this one books the next. `run-agent` resets the desk first, so its own ids are the same on
every run.

### 18 and 19 — the desk limit, and who is exempt from it

```python
asyncio.run(propose(agent, Caller("alice"), "issue_refund",
                    order_id="ord-0007", amount=5000, region="eu"))
# -> denied: The policy denied action Action::"refunds.issue".
asyncio.run(propose(agent, Caller("dana"), "issue_refund",
                    order_id="ord-0007", amount=5000, region="eu"))
# -> allowed
```

The same call, refused for one principal and permitted for the other by one `forbid` that
reads the proposed `amount` *and* the principal together. At `verbosity="debug"` alice's
refusal names it: `'determining_policies': ['refunds-above-the-desk-limit-need-an-admin']`.

Contrast that with flow 14 above, where nothing at all matched bob and the decision was the
**default deny**. That refusal names no policy — `determining_policies` is `[]` even at
`debug`, because there is no rule to point at and saying otherwise would be inventing one.

### 20 — a pattern with nothing to refill from

```python
asyncio.run(propose(agent, Caller("alice"), "issue_refund",
                    order_id="refund-me", amount=100, region="eu"))
# {'detail': "Argument 'order_id' is required and no policy default is configured.",
#  'error': 'DefaultUnavailable',
#  '_authz': {'decision': 'deny',
#             'reason': "Argument 'order_id' is required and no policy default is configured.",
#             'rejected': [{'name': 'order_id',
#                           'reason': 'No policy default is configured.'}]}}
```

That is the right answer rather than a shortcoming: no default order id could be correct, and
inventing one would refund the wrong order. A pattern is where you *want* the refusal.

### 21 and 22 — the admin action

```python
asyncio.run(propose(agent, Caller("dana"), "approve_refund", refund_id="rf-0002"))
# -> allowed
asyncio.run(dispatch(agent, Caller("alice"), approve_refund, refund_id="rf-0002"))
# -> denied: The policy denied action Action::"refunds.approve".
```

`approve_refund` is in dana's manifest and absent from alice's, because alice would be refused
whatever she passed — which is exactly when a tool is hidden.

Dana's answer is the settled refund, including `'approved_by': 'dana'`. That name is the desk's
admin *of record*, resolved from its own roster — the desk is never told who called it. Which
principal was authorized to approve this is in the audit trail instead, where it cannot drift
out of step with the decision that permitted it. Approving twice is not an error and does not
change the approver, and an id the desk does not hold comes back as `'found': False`.

## The invariant: hidden **if and only if** denied

*Only if* — hiding is never the line of defence. The dispatch path runs the identical decision,
so ignoring the manifest buys nothing. "The model did not know the tool was there" is not an
access-control argument, and an example that demonstrated only the filtering would be teaching
one.

*If* — a tool the principal may invoke is never hidden. Filtering is a usability affordance: it
stops the model proposing calls that cannot succeed and burning turns on refusals it could not
have predicted. Turn it off with `governed_tool(..., filter_manifest=False)` and enforcement is
completely intact; the model simply gets refusals instead of a shorter menu.

The manifest probe answers only the *entitlement* question, because it is the only one that is
decidable before the model has proposed anything. A tool with a required parameter and no
policy default is refused on dispatch for everybody, and hiding every such tool from everybody
would be a filter that lied. The same reasoning is why `issue_refund` opts out: a permit that
conditions on a proposed argument cannot be decided before there are any.

## Two details worth copying

- **`governed_tool` re-declares your arguments as optional, and that is deliberate.** Both
  agent frameworks validate the model's proposal against the advertised JSON schema *before*
  dispatch, so a parameter the schema marks `required` can never be omitted — and an argument
  that can never be omitted can never be filled in from a policy default. So
  [`proposable`](../../src/sentrykit/integrations/tools.py) re-declares every parameter with no
  Python-level default as keyword-only and optional, and forwards only what the model actually
  proposed. The trade-off: a parameter in that set cannot carry a meaningful `None`, since the
  shim reads `None` as *not proposed*. Name the set yourself with `optional=` when the default
  is wrong. Here the default is right for every tool: `region`, `limit`, `fmt`, `amount`,
  `order_id` and `refund_id` are all omittable, and `status` and `scope` keep their Python
  defaults and stay out of it.
- **The tool you write takes no `ctx`.** `governed_tool` registers a synthesized adapter that
  prepends `ctx: RunContext[...]` and calls your plain, `@protect`-ed function with the model's
  arguments only. `ctx` is absent from the JSON schema the model sees, your docstring's `Args:`
  descriptions survive, and — because the decorated function is returned **unchanged** — the
  rest of the program can still import and call it directly. `governed_tool` is a *registration*
  helper, not a second `@protect`; a plain callable needs only the decorator.
