# Example: pydantic_ai_agent

One agent, two tools, two humans — and a manifest that changes depending on whose behalf the
agent is running. It shows the per-run tool filter, a role gate, per-principal argument
filtering, policy-supplied defaults, an argument-aware `forbid`, and the `_authz` envelope
travelling with every answer, including the refusals.

It runs **fully offline**. No API key, no network call, no live model.

## On-behalf-of is the whole point

An agent acting for a human **is** that human, as far as the policy is concerned.
There is no bot identity, no service account, and no `delegated_by` anywhere in `policy.py` —
`alice`'s role edge and `alice`'s argument constraints are what govern the call *her agent's
model* proposed. The delegation is expressed by the application choosing whose `deps` it runs
with, and by nothing else.

That is also why the model cannot reach it. `deps` is supplied by the application at `run()`
time and never appears in anything the model can write: not in the prompt it sees, not in the
tool schemas, not in the arguments it proposes. A model that decides to call `export_orders`
on alice's behalf gets alice's answer to that question, which is *no*.

## Layout

| File | What is in it |
| --- | --- |
| `policy.py` | `POLICY_TEXT` (Cedar *logic*, reviewed in git) and `build_grants()` (roles and argument constraints — *data*) |
| `service.py` | The two `@protect`-ed callables. No `RunContext`, no `deps`, no LLM |
| `agent.py` | `build_agent()`: settings, grants, policy, provider, `governed_tool` — plus the offline drivers `offered_tools`, `propose` and `dispatch_context` |

`search_orders(region, limit)` deliberately declares **no Python defaults**, so any value it
runs with came from the caller or from *policy*, and from nowhere else.

## Who may do what

| Principal | Role | May | Argument constraints |
| --- | --- | --- | --- |
| `alice` | `support` | `orders.search` | `region` ∈ {`eu`, `uk`}, default `eu`; `limit` ≤ 50, default `10` |
| `bob` | `auditor` | `orders.export` | — |

The two permits are disjoint on purpose: each principal has exactly one tool the other may not
touch, which is what makes the per-run manifest observable. A `forbid` policy
(`no-pdf-exports`) then refuses `fmt="pdf"` for everyone, including `bob`, by reading
`context.args.fmt`.

## Running it

```bash
pixi run -e agent run-agent        # python -m examples.pydantic_ai_agent.agent
```

`build_agent()` calls `configure(verbosity="verbose")` so the envelope carries processed
values, applied defaults and rejection reasons — the model is one of the audiences for that
explanation, and it is what lets it choose a different call instead of guessing. A production
agent would leave it at `summary`.

The default model is `TestModel`, which calls every visible tool and reports what came back.
Set **`SENTRYKIT_EXAMPLE_MODEL`** to a Pydantic-AI model name to point the free-form run at a
real model instead — the only thing in this example that can reach the network:

```bash
SENTRYKIT_EXAMPLE_MODEL=anthropic:claude-sonnet-4-5 pixi run -e agent run-agent
```

Nothing is wired at import: there is no module-level `agent = build_agent()`, because
`configure()` and `install()` mutate process-global state and importing a module should not.

## Things to try

Every snippet below runs offline. Start here:

```python
import asyncio

from examples.pydantic_ai_agent.agent import (
    Caller,
    build_agent,
    dispatch_context,
    offered_tools,
    propose,
)

agent = build_agent()
```

`offered_tools` reports what the *model* was told exists, by running one turn on a
`FunctionModel` that calls nothing and reports `AgentInfo.function_tools`. `propose` makes the
model propose exactly one tool call and returns what came back.

**The manifest is per-caller.** Same agent, same two registered tools:

```python
asyncio.run(offered_tools(agent, Caller("alice")))
# ['search_orders']
asyncio.run(offered_tools(agent, Caller("bob")))
# ['export_orders']
```

**Argument filtering, then default injection.** `cn` is not in alice's allow-set, so it is
dropped and then defaulted; the call still succeeds and the envelope says exactly what
happened:

```python
asyncio.run(propose(agent, Caller("alice"), "search_orders", region="cn", limit=5))
# {'region': 'eu', 'limit': 5, 'orders': ['order-0', 'order-1', 'order-2'],
#  '_authz': {'decision': 'allow', 'action': 'Action::"orders.search"',
#             'resource': 'Tool::"orders"', 'principal': 'User::"alice"',
#             'processed': {'limit': 5, 'region': 'eu'},
#             'rejected': [{'name': 'region', 'rule': 'allow-set',
#                           'reason': 'Value is not one of the permitted values',
#                           'policy': 'alice-region', 'value': 'cn'}],
#             'defaults_applied': {'region': 'eu'}}}
```

**Defaults for arguments nobody proposed.** `search_orders` declares no Python defaults, so the
model may leave both out — and then every value it runs with came from alice's grants:

```python
asyncio.run(propose(agent, Caller("alice"), "search_orders"))
# {'region': 'eu', 'limit': 10, 'orders': ['order-0', 'order-1', 'order-2'],
#  '_authz': {'decision': 'allow', 'action': 'Action::"orders.search"',
#             'resource': 'Tool::"orders"', 'principal': 'User::"alice"',
#             'processed': {'region': 'eu', 'limit': 10},
#             'defaults_applied': {'region': 'eu', 'limit': 10}}}
```

That the model *can* omit them is not free — see the first "detail worth copying" below.
`export_orders` opts out with `optional=()`, because `fmt` is a genuine choice by whoever wants
the export, not something policy could supply.

**Nothing left to run with.** Every proposed argument was refused, so the call is not made and
no default rescues it:

```python
asyncio.run(propose(agent, Caller("alice"), "search_orders", region="cn", limit=999))
# {'detail': 'Every supplied argument was rejected by policy.',
#  'error': 'NoValidArguments',
#  '_authz': {'decision': 'deny', 'reason': 'Every supplied argument was rejected by policy.',
#             'rejected': [{'name': 'region', ...}, {'name': 'limit', ...}],
#             'allowed': {'region': {'allow': ['eu', 'uk'], ...},
#                         'limit': {'maximum': 50, ...}}}}
```

**bob may not search — and his model is never told the tool exists.** Proposing it anyway gets
the model a correction, not a dispatch:

```python
asyncio.run(propose(agent, Caller("bob"), "search_orders", region="eu", limit=3))
# "Unknown tool name: 'search_orders'. Available tools: 'export_orders'"
```

**…and hiding is not the enforcement.** A host that ignores the manifest and dispatches the
adapter directly meets the identical decision:

```python
from examples.pydantic_ai_agent.service import search_orders
from sentrykit.integrations.pydantic_ai import tool_adapter

asyncio.run(tool_adapter(search_orders)(dispatch_context(agent, Caller("bob"))))
# {'detail': 'The policy denied action Action::"orders.search".',
#  'error': 'AuthzDenied',
#  '_authz': {'decision': 'deny', 'reason': 'The policy denied action Action::"orders.search".',
#             'action': 'Action::"orders.search"', 'resource': 'Tool::"orders"'}}
```

**A policy that reads the argument.** `bob` may export, but not as a PDF:

```python
asyncio.run(propose(agent, Caller("bob"), "export_orders", fmt="csv"))
# {'fmt': 'csv', 'exported': 42,
#  '_authz': {'decision': 'allow', 'action': 'Action::"orders.export"',
#             'resource': 'Tool::"orders"', 'principal': 'User::"bob"',
#             'processed': {'fmt': 'csv'}}}

asyncio.run(propose(agent, Caller("bob"), "export_orders", fmt="pdf"))
# {'detail': 'The policy denied action Action::"orders.export".',
#  'error': 'AuthzDenied',
#  '_authz': {'decision': 'deny', 'reason': 'The policy denied action Action::"orders.export".',
#             'action': 'Action::"orders.export"', 'resource': 'Tool::"orders"'}}
```

At `verbosity="debug"` that last refusal also names the policy that decided it:
`'determining_policies': ['no-pdf-exports']`.

## The invariant: hidden **if and only if** denied

The two `bob` snippets above are the two halves of it, and they are worth reading together.

*Only if* — hiding is never the line of defence. The dispatch path runs the identical
`Governor.plan(...)`, so ignoring the manifest buys nothing: `search_orders` refuses `bob` the
same way whether or not he was ever told it existed. "The model did not know the tool was
there" is not an access-control argument, and an example that demonstrated only the filtering
would be teaching one.

*If* — a tool the principal may invoke is never hidden. Filtering is a usability affordance:
it stops the model proposing calls that cannot succeed and burning turns on refusals it could
not have predicted. Turn it off with `governed_tool(..., filter_manifest=False)` and
enforcement is completely intact; the model simply gets refusals instead of a shorter menu.

The manifest probe answers only the *entitlement* question, because it is the only one that is
decidable before the model has proposed anything. A tool with a required parameter and no
policy default is refused on dispatch for everybody, and hiding every such tool from everybody
would be a filter that lied.

## Two details worth copying

- **`governed_tool` re-declares your arguments as optional, and that is deliberate.** Both
  agent frameworks validate the model's proposal against the advertised JSON schema *before*
  dispatch, so a parameter the schema marks `required` can never be omitted — and an argument
  that can never be omitted can never be filled in from a policy default. So
  [`proposable`](../../src/sentrykit/integrations/tools.py) re-declares every parameter with no
  Python-level default as keyword-only and optional, and forwards only what the model actually
  proposed. It is the same move the FastAPI example makes one layer out when its route writes
  `if region is not None`; on an agent boundary the boundary *is* the tool signature. The
  trade-off: a parameter in that set cannot carry a meaningful `None`, since the shim reads
  `None` as *not proposed*. Name the set yourself with `optional=` when the default is wrong —
  `optional=()` keeps everything required, which is what `export_orders` does.
- **The tool you write takes no `ctx`.** `governed_tool` registers a synthesized adapter that
  prepends `ctx: RunContext[...]` and calls your plain, `@protect`-ed function with the
  model's arguments only. `ctx` is absent from the JSON schema the model sees, your
  docstring's `Args:` descriptions survive, and — because the decorated function is returned
  **unchanged** — the rest of the program can still import and call it directly.
