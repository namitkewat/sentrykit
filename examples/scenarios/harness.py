"""The A/B harness: one proposal, run twice -- once past the policy, once around it.

Every other example in this repository shows what a decision *is*. This one shows what a
decision is *worth*, which needs a second arm: the same proposal, against the same database,
reaching the same function body, with the authorization layer taken out. Without that arm
"security improves" is a sentence; with it, it is two numbers side by side.

## What makes the comparison fair

Three things, and all three are mechanical rather than promised:

* **One body per tool.** :mod:`examples.scenarios.desk_tools` holds the plain functions and
  :mod:`examples.scenarios.governed` wraps those same function objects. Neither arm has a
  body of its own, so there is no second implementation to drift.
* **One proposal per scenario.** The arguments are decided once and handed to both arms. A
  live model, when one is reachable, proposes once and its proposal is what both arms run.
* **One starting state per arm.** The desk is reset before each arm, because several of these
  scenarios *write* -- one of them cancels most of the order book -- and an arm that started
  from the wreckage of the previous one would be measuring the wrong thing.

## What the two arms are allowed to differ in

Only the gate. The ungoverned arm calls the plain function with no principal established and
no policy consulted, which is what an application looks like before any of this is wired in.
The governed arm establishes the principal and calls the wrapped twin. Nothing else about the
process changes between them -- same settings, same database, same arguments.

## Where the principal comes from, with no framework in the room

There is no web request here and no agent SDK, so there is no context provider either. The
grant store materializes the principal (:meth:`~sentrykit.stores.base.GrantStore.get_principal`
turns an id into roles, parent edges and argument constraints) and
:func:`~sentrykit.context.principal_context` establishes it for the block. That is the whole
wiring, and it is the shape a scheduled job or a queue worker wants: the integrations exist to
*derive* an identity from a request, and a program that already knows who it is acting for
does not need one.

## Why the audit section is the deliverable

The governed arm leaves a record per decision, hash-chained and masked before the write. The
ungoverned arm leaves nothing -- not an empty log, *nothing*, because there was no decision to
record. Printing both facts next to each other is the honest form of the claim: the trail is
not a feature of the database, it is a consequence of there having been a gate.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from examples import desk
from examples.scenarios import governed
from examples.scenarios.policy import POLICY_DIR, build_grants
from sentrykit import (
    AuthzAuditRecord,
    Principal,
    SentrykitError,
    configure,
    install,
    principal_context,
    verify_chain,
)
from sentrykit.stores.filesystem import FilesystemPolicySource
from sentrykit.stores.memory import InMemoryAuditSink

UNGOVERNED: Final = "ungoverned"
"""Label for the arm that calls the plain function with nothing in the way."""

GOVERNED: Final = "governed"
"""Label for the arm that establishes a principal and calls the wrapped twin."""

SCRIPTED: Final = "scripted"
"""Proposal source when the arguments came from this file rather than from a model.

An attacker is a script, not a model, so most of these proposals are written down. It also
makes the printed table reproducible, which is what lets the documentation quote it.
"""

CHANNEL: Final = "internal"
"""The channel recorded on every decision here, and the honest value for this suite.

There is no request. A program that already knows whose behalf it acts on is not arriving
over HTTP and is not an agent dispatch, and labelling it as either would put an untrue fact in
the audit record. ``internal`` is also what the engine fills in when nobody says -- stating it
anyway is the difference between a default and a decision.
"""


@dataclass(frozen=True)
class Step:
    """One call in a scenario, which may be the second call of a sequence.

    Attributes:
        principal: Whose behalf this call runs on, by grant-store id. Ignored by the
            ungoverned arm, which establishes nobody.
        tool: The tool name, as :data:`examples.scenarios.governed.TOOLS` keys it.
        arguments: What is proposed, when it does not depend on an earlier call.
        derive: Builds the arguments from every result so far, for a call that presents
            something an earlier call handed back. Takes precedence over ``arguments``.
    """

    principal: str
    tool: str
    arguments: Mapping[str, object] = field(default_factory=dict)
    derive: Callable[[tuple[object, ...]], Mapping[str, object]] | None = None

    def bind(self, results: tuple[object, ...]) -> Mapping[str, object]:
        """Return the arguments this step runs with.

        Args:
            results: What every earlier step in this arm returned, oldest first.

        Returns:
            :attr:`arguments`, or whatever :attr:`derive` built from ``results``.
        """
        return self.arguments if self.derive is None else self.derive(results)


@dataclass(frozen=True)
class Scenario:
    """One named attack, and how to tell whether it worked.

    Attributes:
        key: Short stable id, used in the printed table and in tests.
        title: One short line for a human.
        claim: What this scenario is for -- the sentence a reader should leave with.
        steps: The calls, in order. A refusal stops the sequence, because a refused call
            hands nothing to the call that was going to present it.
        effect: Turns the results of a completed arm into one legible line. Never called for
            an arm that was refused; the refusal is its own effect.
        prepare: Runs after the desk is reset and before the first call, for a scenario whose
            attack is something written into the data rather than something proposed.
        note: Extra prose printed under this scenario's block, where the one-line claim is
            not enough.
    """

    key: str
    title: str
    claim: str
    steps: tuple[Step, ...]
    effect: Callable[[tuple[object, ...]], str]
    prepare: Callable[[], object] | None = None
    note: str = ""


@dataclass(frozen=True)
class Arm:
    """What one arm of one scenario did.

    Attributes:
        label: :data:`UNGOVERNED` or :data:`GOVERNED`.
        effect: One line describing what actually happened -- rows served, orders cancelled,
            or the refusal that stopped it.
        refused: The error name when the arm was refused, otherwise ``None``. The ungoverned
            arm can only populate this with a domain error, since nothing there refuses on
            policy grounds.
        results: Each completed call's return value, oldest first.
    """

    label: str
    effect: str
    refused: str | None = None
    results: tuple[object, ...] = ()


@dataclass(frozen=True)
class Verdict:
    """One scenario, both arms, and the records the governed arm left behind.

    Attributes:
        scenario: What was run.
        proposal: Where the arguments came from -- :data:`SCRIPTED`, or a model id.
        ungoverned: The arm with no gate.
        governed: The arm with one.
        records: The audit records the governed arm wrote, oldest first.
    """

    scenario: Scenario
    proposal: str
    ungoverned: Arm
    governed: Arm
    records: tuple[AuthzAuditRecord, ...] = ()


def wire() -> tuple[InMemoryAuditSink, Callable[[str], Principal]]:
    """Install the governor for the suite and return the sink and a principal resolver.

    ``verbose`` verbosity so the envelope carries processed values, applied defaults and
    rejection reasons: the scenarios are about *which* argument was thrown away and what
    replaced it, and a summary envelope would say only that something was.

    Returns:
        The in-memory audit sink every governed decision is written to, and a callable that
        turns a grant-store id into a materialized principal.

    Raises:
        LookupError: From the returned resolver, when the store has never heard of that id. A
            missing principal would otherwise fail closed several frames later as a refusal,
            which is correct in production and unhelpful in a demonstration.
    """
    configure(verbosity="verbose")
    store = build_grants()
    sink = InMemoryAuditSink(name="scenarios")
    install(
        policy_source=FilesystemPolicySource(POLICY_DIR),
        grant_store=store,
        audit_sink=sink,
    )

    def resolve(name: str) -> Principal:
        """Materialize one principal out of the grant store."""
        principal = store.get_principal(name)
        if principal is None:
            raise LookupError(f"no principal {name!r} in the scenario grant store")
        return principal

    return sink, resolve


def run_arm(
    scenario: Scenario,
    label: str,
    table: Mapping[str, Callable[..., object]],
    resolve: Callable[[str], Principal],
) -> Arm:
    """Reset the desk, run every step of ``scenario`` through ``table``, and describe it.

    Args:
        scenario: The scenario to run.
        label: :data:`UNGOVERNED` or :data:`GOVERNED`. Decides whether a principal is
            established at all; the ungoverned arm establishes nobody, which is the
            difference being measured.
        table: The callables to drive -- ``governed.PLAIN`` or ``governed.TOOLS``.
        resolve: Turns a step's principal id into a materialized principal.

    Returns:
        The arm, carrying either an effect line or the name of the error that stopped it.
    """
    desk.reset_desk()
    if scenario.prepare is not None:
        scenario.prepare()

    results: list[object] = []
    for step in scenario.steps:
        arguments = dict(step.bind(tuple(results)))
        try:
            if label == GOVERNED:
                with principal_context(resolve(step.principal), channel=CHANNEL):
                    results.append(table[step.tool](**arguments))
            else:
                results.append(table[step.tool](**arguments))
        except SentrykitError as refusal:
            return Arm(label, f"refused -- {refusal}", type(refusal).__name__, tuple(results))
        except Exception as failure:
            # A desk error reaching here is an answer about the domain, not about policy, and
            # the distinction is one of the things the suite exists to keep visible.
            return Arm(label, f"failed -- {failure}", type(failure).__name__, tuple(results))
    return Arm(label, scenario.effect(tuple(results)), None, tuple(results))


def run_scenario(
    scenario: Scenario,
    sink: InMemoryAuditSink,
    resolve: Callable[[str], Principal],
    *,
    proposal: str = SCRIPTED,
) -> Verdict:
    """Run both arms of one scenario and collect the records the governed arm wrote.

    The ungoverned arm runs first because that is the order a reader wants -- what happens
    without this, then what happens with it -- and it costs nothing to choose, since each arm
    resets the desk before it starts and neither can see what the other wrote.

    Args:
        scenario: The scenario to run.
        sink: The suite's audit sink. Records are sliced by position rather than cleared, so
            the hash chain spans the whole run and :func:`~sentrykit.verify_chain` over the
            full log still means something.
        resolve: Turns a step's principal id into a materialized principal.
        proposal: Where the arguments came from, for the printed table.

    Returns:
        The verdict for this scenario.
    """
    ungoverned = run_arm(scenario, UNGOVERNED, governed.PLAIN, resolve)
    written = len(sink.records)
    governed_arm = run_arm(scenario, GOVERNED, governed.TOOLS, resolve)
    # Left as it was found, rather than left to the next arm's reset to tidy. Every arm starts
    # clean either way, so this one reset only decides what the *last* scenario leaves behind
    # -- and relying on the suite happening to end on a read-only scenario would make a
    # cancelled order book escape the moment somebody reordered the list. The arms' results are
    # already computed and the audit records already written, so nothing here reads the desk.
    desk.reset_desk()
    return Verdict(scenario, proposal, ungoverned, governed_arm, sink.records[written:])


def render_proposal(scenario: Scenario) -> str:
    """Render a scenario's steps as the Python calls they are.

    A derived step is rendered as the expression it is rather than the value it resolves to,
    because the value is an id allocated at run time and the shape is the point: the second
    call presents something the first call handed back.

    Args:
        scenario: The scenario.

    Returns:
        One call per step, joined with ``" -> "``.
    """
    rendered: list[str] = []
    for step in scenario.steps:
        if step.derive is not None:
            rendered.append(f"{step.principal}: {step.tool}(<from the previous call>)")
            continue
        inner = ", ".join(f"{name}={value!r}" for name, value in step.arguments.items())
        rendered.append(f"{step.principal}: {step.tool}({inner})")
    return " -> ".join(rendered)


def banner(title: str) -> None:
    """Print a section heading.

    Args:
        title: The heading text.
    """
    print(f"\n=== {title} " + "=" * max(0, 92 - len(title)))


def show_scenario(verdict: Verdict) -> None:
    """Print one scenario as a block: the proposal, then both arms, then the claim.

    A block rather than a row in a wide table, because the two effect lines are sentences and
    a sentence does not fit in a column.

    Args:
        verdict: What to print.
    """
    print(f"\n[{verdict.scenario.key}] {verdict.scenario.title}")
    print(f"  proposed    {render_proposal(verdict.scenario)}  ({verdict.proposal})")
    print(f"  ungoverned  {verdict.ungoverned.effect}")
    print(f"  governed    {verdict.governed.effect}")
    print(f"  so          {verdict.scenario.claim}")
    if verdict.scenario.note:
        for line in verdict.scenario.note.splitlines():
            print(f"              {line}")


def show_audit(verdicts: Sequence[Verdict], sink: InMemoryAuditSink) -> None:
    """Print the records the governed arms wrote, and verify the chain over all of them.

    Args:
        verdicts: Every scenario that ran, in order.
        sink: The suite's sink, read for the whole run rather than per scenario.
    """
    banner("the trail the governed arm left, and the trail the other one did not")
    total = 0
    print(f"{'#':>4}  {'scenario':<26}  {'who':<6}  {'action':<34}  {'outcome':<26}  narrowed")
    for verdict in verdicts:
        total += len(verdict.records)
        for record in verdict.records:
            narrowed = ", ".join(item.name for item in record.rejected) or "-"
            print(
                f"{record.sequence:>4}  {verdict.scenario.key:<26}  "
                f"{record.principal.id:<6}  {record.action:<34}  {record.outcome:<26}  {narrowed}"
            )
    chain = verify_chain(sink.records)
    print(
        f"\n{total} records from {len(verdicts)} scenarios, and {len(sink.records)} in the log."
        f"\nChain over the whole log: {'intact' if chain.ok else f'BROKEN at {chain.broken_at}'}."
        "\n\nA narrowed call's outcome is `allowed`, because it was: the call ran. Which argument"
        "\nwas thrown away is the last column, from the record's own `rejected` field, and the"
        "\nother outcomes in that vocabulary are the ways a call did not run at all."
        "\n\nThe ungoverned arm ran every one of those calls and wrote none of them. That is not"
        "\nan empty log, it is the absence of one: nothing decided, so nothing to record. An"
        "\naudit trail is a consequence of there having been a gate, not a property of the"
        "\ndatabase underneath."
    )


def show_envelope(verdict: Verdict) -> None:
    """Print the ``_authz`` envelope of a governed arm's last result, in full.

    One scenario is worth reading at this level, because the envelope is what a caller -- or a
    model -- actually has to work from, and summarizing it here would be summarizing the thing
    under discussion.

    Args:
        verdict: The scenario to open up.
    """
    banner(f"the envelope, in full, for {verdict.scenario.key}")
    if verdict.governed.refused is not None:
        # Refused is the one case where reading the last result would mislead: a sequence that
        # stopped part-way still has the earlier steps' payloads, and printing one of those as
        # "the envelope for this scenario" would describe a call that was not the refused one.
        print(f"no envelope: the governed arm was refused -- {verdict.governed.effect}")
        return
    payload = verdict.governed.results[-1] if verdict.governed.results else None
    envelope = payload.get("_authz") if isinstance(payload, Mapping) else None
    if envelope is None:
        print("no envelope: the result carried no `_authz` key")
        return
    print(json.dumps(envelope, indent=2, sort_keys=True, default=str))


def tool_schemas() -> list[dict[str, Any]]:
    """Declare the three tools the live pass offers a model, in OpenAI's tool-call form.

    Three rather than eight: the live pass exists to watch a model read planted text and
    decide what to do about it, and offering it the destructive tools would be testing
    something else. Both model tiers read this same shape.

    Returns:
        The declarations, ready for :func:`examples.models.chat`.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": "read_ticket",
                "description": "Read one support ticket and every message on it.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ticket_id": {"type": "string", "description": "The ticket, tkt-NNNN."}
                    },
                    "required": ["ticket_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "search_orders",
                "description": (
                    "Search this desk's orders. Leave out any argument you are unsure of: "
                    "policy fills those in."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "region": {"type": "string", "description": "eu, uk or us."},
                        "limit": {"type": "integer", "description": "How many orders to return."},
                        "status": {"type": "string", "description": "open, closed or cancelled."},
                    },
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_tenant_orders",
                "description": "List the open orders belonging to one tenant's customers.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tenant_id": {"type": "string", "description": "The tenant id."},
                        "limit": {"type": "integer", "description": "How many orders to return."},
                    },
                    "required": ["tenant_id"],
                },
            },
        },
    ]


def proposed_call(message: Mapping[str, Any]) -> tuple[str, dict[str, object]] | None:
    """Read the first tool call out of an assistant message, from either tier.

    Args:
        message: What :func:`examples.models.chat` returned.

    Returns:
        The proposed tool name and its arguments, or ``None`` when the model proposed no
        call. The two tiers disagree about whether ``arguments`` is an object or a JSON
        string, so both are accepted rather than one being trusted.
    """
    calls = message.get("tool_calls") or ()
    if not isinstance(calls, Sequence) or not calls:
        return None
    first = calls[0]
    function = first.get("function") if isinstance(first, Mapping) else None
    if not isinstance(function, Mapping):
        return None
    name = str(function.get("name") or "")
    raw = function.get("arguments")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return None
    arguments = dict(raw) if isinstance(raw, Mapping) else {}
    return (name, arguments) if name else None
