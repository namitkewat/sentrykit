"""Nine attacks on a tool-calling desk, each run twice: once past the policy, once around it.

    pixi run run-scenarios

The other four examples in this repository each answer "how do I wire this into my framework".
This one answers the question underneath that: **what is the gate worth?** Every scenario is
run through two arms over the same seeded database --- the plain function with nothing in the
way, and the same function wrapped --- so that the difference is two outcomes side by side
rather than an assertion.

## What is here

* :mod:`examples.scenarios.desk_tools` --- eight plain callables. No decorators, and nothing
  imported from sentrykit at all. This is the application before any of this exists.
* :mod:`examples.scenarios.governed` --- the same eight function objects, wrapped. One body
  per tool, so the two arms cannot drift into measuring different code.
* :mod:`examples.scenarios.policy` --- the grants, as data, and where the reviewed pack lives.
* ``policies/`` --- the reviewed Cedar logic, including the two argument ceilings.
* :mod:`examples.scenarios.attack` --- every hostile input, in one place.
* :mod:`examples.scenarios.harness` --- the A/B runner, and what keeps the comparison fair.
* :mod:`examples.scenarios.scenarios` --- the nine, as data.

## The three scenarios that matter most are the ones that go badly

``laundered-handle`` shows a narrowed call handing back an opaque id and somebody else
presenting it, and nothing in this library stops that. ``handle-own-region`` shows a call
policy correctly allowed whose answer was still wrong. ``honest-boundary`` shows an argument
decided exactly as written and a desk-wide figure leaking in the answer anyway.

They are in the suite because an authorization layer that only ships the cases it wins is not
describing a boundary, and a reader deciding whether to adopt this needs the boundary more than
they need the wins. Pre-action authorization governs the call: who may invoke it, with which
arguments, with which defaults. It does not govern what the body computes, and it cannot
enforce a narrowing that is not in the request.

## Nothing is wired at import

Importing this package reads no policy, installs no governor and touches no database.
:func:`examples.scenarios.harness.wire` does all three, and ``__main__`` calls it.
"""
