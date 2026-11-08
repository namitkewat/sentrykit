"""The two invariants an append-only audit log rests on: nothing raw reaches it, and it links.

The masking invariant is checked two ways, because each catches what the other cannot.

*Behaviourally*, a real :class:`~sentrykit.engine.Governor` decides every way it can — an
allow, a lenient argument drop, a constrained principal, and a denial — and every record it
produced is serialized to JSON and searched for the raw strings that went in. Two cases are
the ones that are easy to get wrong. A dropped argument was *refused*, but the value the
caller proposed is still attached to the rejection to explain why, and it is every bit as
sensitive as one that got through. A constrained principal's record then carries the
constraint itself — and an allow-set *enumerates* permitted values, so the record names
values the caller never proposed and may never have been shown.

*Statically*, every module under ``src/sentrykit/`` is parsed with ``ast`` and checked for
calls that hand a record to an audit sink. Masking runs inside
:class:`~sentrykit.audit.AuditTrail`, so "masking runs before the write" holds only for as
long as the trail is the only thing that writes. This is the audit-side analogue of the
import scan in ``test_core_imports.py``: a future caller that reaches around the trail fails
the suite rather than the compliance review.

The chain is the other invariant, and it is only testable under load: one trail is shared by
every thread a host serves a request on, and appending to the chain reads its tail before it
advances it. So a governor is driven from several threads at once and the log it produced is
verified. A chain that links only while one thread runs reports a healthy log as tampered
with, which is the worst thing an integrity control can do: a bad verdict is meant to be
fatal, so a false one costs an operator the control itself.
"""

from __future__ import annotations

import ast
import json
import re
import threading
from pathlib import Path
from typing import Annotated, Any

import pytest

import sentrykit
from sentrykit.audit import GENESIS_HASH, AuditTrail, AuthzAuditRecord, verify_chain
from sentrykit.cedar import Entity, EntityRef
from sentrykit.constraints import ArgumentConstraint, ConstraintSet
from sentrykit.context import Principal
from sentrykit.engine import ArgumentSpec, Governor
from sentrykit.errors import AuditUnavailable, AuthzDenied
from sentrykit.masking import Masker, Sensitive
from sentrykit.stores.base import PolicyBundle
from sentrykit.stores.memory import InMemoryAuditSink

# --- the behavioural half ------------------------------------------------------------------

RAW_ACCOUNT = "ACCT-3141592653-TOPSECRET"
RAW_SECRET = "hunter2-plaintext-password-xyz"
RAW_ATTRIBUTE = "attribute-value-nobody-should-see"

RAW_PERMITTED_ACCOUNT = "ACCT-2718281828-PERMITTED"
"""An account the constrained principal *may* pass.

An allow-set enumerates permitted values, so a record describing the constraint spells out
accounts nobody proposed. A permitted peer's account number is exactly as sensitive as the
caller's own, which is why it belongs in :data:`RAW_VALUES` alongside it.
"""

RAW_DENIED_ACCOUNT = "ACCT-1618033988-WITHDRAWN"
"""An account the constrained principal may *not* pass. A deny-set names it just as plainly,
and "the value this principal was stopped from reaching" is not a safer thing to write down.
"""

RAW_VALUES = (
    RAW_ACCOUNT,
    RAW_SECRET,
    RAW_ATTRIBUTE,
    RAW_PERMITTED_ACCOUNT,
    RAW_DENIED_ACCOUNT,
)
"""Every raw string that goes in. No record may contain any of them, in any field."""

LOOKUP = EntityRef("Action", "tool.lookup")
ACCOUNTS = EntityRef("Tool", "accounts")

POLICY = """
@id("support-may-look-up-an-account")
@obligations("redact:secret")
permit (
  principal in Role::"support",
  action == Action::"tool.lookup",
  resource == Tool::"accounts"
);

@id("frozen-principals-are-forbidden")
@obligations("redact:secret")
forbid (principal, action, resource)
when { principal has frozen && principal.frozen };
"""

ENTITIES = (
    Entity(EntityRef("Role", "support")),
    Entity(ACCOUNTS),
)


def lookup(
    account: Annotated[str, Sensitive("hmac")] = "",
    secret: str = "",
    region: str = "eu-west",
    limit: Annotated[int, Sensitive("hmac")] = 10,
) -> dict[str, str]:
    """``account`` is sensitive by signature; ``secret`` only by policy obligation.

    ``limit`` is sensitive by signature too and numeric, so it is the argument a constraint
    bounds — and a bound is the part of a described constraint that must reach the sink as
    written.
    """
    return {"account": account, "region": region}


@pytest.fixture
def sink() -> InMemoryAuditSink:
    return InMemoryAuditSink()


def _governor_over(sink: InMemoryAuditSink, *, strict: bool = True) -> Governor:
    """A governor auditing every decision into ``sink``, masked on the way in."""
    bundle = PolicyBundle.from_text(POLICY, entities=ENTITIES, source="pack", origin="pack.cedar")
    trail = AuditTrail(sink, masker=Masker(key=b"a-test-hmac-key"), bundle=bundle, strict=strict)
    return Governor(bundle.engine(), audit=trail, bundle=bundle)


@pytest.fixture
def audited(sink: InMemoryAuditSink) -> Governor:
    """A governor whose every decision lands in ``sink``, masked on the way in."""
    return _governor_over(sink)


def _rendered(sink: InMemoryAuditSink) -> str:
    """Every record the sink holds, as one JSON blob to search."""
    return json.dumps(
        [record.model_dump(mode="json") for record in sink.records],
        default=str,
        ensure_ascii=False,
    )


def _decide(governor: Governor, principal: Principal, *, account: str = RAW_ACCOUNT) -> None:
    governor.plan(
        ArgumentSpec.from_callable(lookup),
        principal=principal,
        action=LOOKUP,
        resource=ACCOUNTS,
        proposed={"account": account, "secret": RAW_SECRET, "region": "eu-west"},
    )


def _governed(**arguments: ArgumentConstraint) -> Principal:
    """A support principal whose named arguments carry the given per-principal constraints."""
    return Principal(
        id="casey",
        roles=("support",),
        constraints={str(LOOKUP): ConstraintSet(arguments=arguments)},
    )


def _described(record: AuthzAuditRecord, argument: str) -> dict[str, Any]:
    """The rules the record says governed ``argument``, exactly as they reached the sink."""
    by_action: dict[str, Any] = record.principal.constraints
    return dict(by_action[str(LOOKUP)][argument])


@pytest.mark.unit
def test_an_allowed_call_writes_no_raw_sensitive_value_to_the_sink(
    audited: Governor, sink: InMemoryAuditSink
) -> None:
    _decide(
        audited,
        Principal(id="alice", roles=("support",), attributes={"secret": RAW_ATTRIBUTE}),
    )

    written = _rendered(sink)

    assert len(sink.records) == 1
    assert sink.records[0].outcome == "allowed"
    for raw in RAW_VALUES:
        assert raw not in written


@pytest.mark.unit
def test_an_allowed_call_still_records_that_it_masked_those_fields(
    audited: Governor, sink: InMemoryAuditSink
) -> None:
    _decide(audited, Principal(id="alice", roles=("support",)))

    record = sink.records[0]

    # Non-vacuity: the fields really were in the record, and really were masked.
    assert record.masked["account"] == "hmac"
    assert record.masked["secret"] == "redact"
    assert str(record.proposed["account"]).startswith("hmac:")
    assert record.proposed["secret"] == "[redacted]"
    assert record.proposed["region"] == "eu-west"


@pytest.mark.unit
def test_the_processed_arguments_the_callable_ran_with_are_masked_too(
    audited: Governor, sink: InMemoryAuditSink
) -> None:
    _decide(audited, Principal(id="alice", roles=("support",)))

    record = sink.records[0]

    assert record.processed["secret"] == "[redacted]"
    assert RAW_ACCOUNT not in str(record.processed)


@pytest.mark.unit
def test_the_proposed_arguments_are_not_smuggled_through_the_environment(
    audited: Governor, sink: InMemoryAuditSink
) -> None:
    """``merge_environment`` exposes the raw proposal to policy under ``args``."""
    _decide(audited, Principal(id="alice", roles=("support",)))

    environment = sink.records[0].environment

    assert "args" not in environment
    assert RAW_ACCOUNT not in json.dumps(environment, default=str)


@pytest.mark.unit
def test_a_principal_attribute_sharing_a_masked_name_is_masked_as_well(
    audited: Governor, sink: InMemoryAuditSink
) -> None:
    _decide(
        audited,
        Principal(id="alice", roles=("support",), attributes={"secret": RAW_ATTRIBUTE}),
    )

    assert sink.records[0].principal.attributes["secret"] == "[redacted]"


@pytest.mark.unit
def test_a_leniently_dropped_argument_never_carries_its_raw_value_into_the_sink(
    audited: Governor, sink: InMemoryAuditSink
) -> None:
    """The rejection explains itself by carrying the value that was refused.

    The allow-set that refused it is a real permitted account, not a placeholder, because a
    search for the raw strings that went in can only find what actually went in. It is also
    the default, so this is a genuine reject-and-refill: without one, the only value left for
    a governed argument would be the signature's, which the allow-set refuses, and the call
    would be refused instead of narrowed.
    """
    constrained = _governed(
        account=ArgumentConstraint(
            allow=(RAW_PERMITTED_ACCOUNT,),
            default=RAW_PERMITTED_ACCOUNT,
            policy="grant-accounts",
        )
    )

    _decide(audited, constrained)

    record = sink.records[0]
    written = _rendered(sink)

    assert [item.name for item in record.rejected] == ["account"]
    assert record.rejected[0].reason
    assert record.rejected[0].value != RAW_ACCOUNT
    for raw in RAW_VALUES:
        assert raw not in written


@pytest.mark.unit
def test_the_constraint_a_record_describes_carries_none_of_its_values_in_the_clear(
    audited: Governor, sink: InMemoryAuditSink
) -> None:
    """Three of a described constraint's rules hold values rather than describe a shape.

    ``allow`` and ``deny`` enumerate values outright, and a per-principal ``pattern`` can
    pin one as a literal. All three ride in the same record as the caller's own masked
    argument, into a sink that cannot be corrected afterwards — so a record masking the
    argument and spelling out the constraint two fields away has published the value anyway.
    """
    constrained = _governed(
        account=ArgumentConstraint(
            allow=(RAW_PERMITTED_ACCOUNT,),
            deny=(RAW_DENIED_ACCOUNT,),
            pattern=f"^{RAW_PERMITTED_ACCOUNT}$",
            policy="grant-accounts",
        )
    )

    _decide(audited, constrained, account=RAW_PERMITTED_ACCOUNT)

    record = sink.records[0]
    described = _described(record, "account")
    written = _rendered(sink)

    for raw in RAW_VALUES:
        assert raw not in written
    # Non-vacuity: the constraint is still *described*, it is only unreadable. An auditor can
    # still see that this principal was fenced to one account and refused another.
    assert set(described) >= {"allow", "deny", "pattern", "policy", "required"}
    assert described["policy"] == "grant-accounts"
    assert [str(member).startswith("hmac:") for member in described["allow"]] == [True]
    assert [str(member).startswith("hmac:") for member in described["deny"]] == [True]
    assert str(described["pattern"]).startswith("hmac:")
    # Masked under the *argument's* name on both sides, which is what keeps the allow-set
    # answerable: was what the caller proposed one of the values they were permitted to pass?
    assert record.proposed["account"] in described["allow"]


@pytest.mark.unit
def test_a_bound_in_a_described_constraint_reaches_the_sink_as_written(
    audited: Governor, sink: InMemoryAuditSink
) -> None:
    """A bound is a rule, not a value.

    Masking one would cost an auditor what the principal was actually permitted to do and
    would recover nothing, because ``maximum`` names no account and no principal. The
    allow-set on the other argument is here so the assertion can tell a record whose
    constraints were walked and masked from one that was never walked at all.
    """
    constrained = _governed(
        account=ArgumentConstraint(
            allow=(RAW_PERMITTED_ACCOUNT,),
            default=RAW_PERMITTED_ACCOUNT,
            policy="grant-accounts",
        ),
        limit=ArgumentConstraint(minimum=1, maximum=50, policy="grant-page-size"),
    )

    _decide(audited, constrained)

    record = sink.records[0]

    assert record.masked["limit"] == "hmac"
    assert _described(record, "limit")["minimum"] == 1
    assert _described(record, "limit")["maximum"] == 50
    assert RAW_PERMITTED_ACCOUNT not in _rendered(sink)


@pytest.mark.unit
def test_a_denied_call_writes_no_raw_sensitive_value_to_the_sink(
    audited: Governor, sink: InMemoryAuditSink
) -> None:
    frozen = Principal(
        id="sam",
        roles=("support",),
        attributes={"frozen": True, "secret": RAW_ATTRIBUTE},
    )

    with pytest.raises(AuthzDenied):
        _decide(audited, frozen)

    written = _rendered(sink)

    assert len(sink.records) == 1
    assert sink.records[0].decision == "deny"
    assert sink.records[0].determining_policies == ("frozen-principals-are-forbidden",)
    for raw in RAW_VALUES:
        assert raw not in written


@pytest.mark.unit
def test_a_denial_still_records_the_arguments_that_were_attempted(
    audited: Governor, sink: InMemoryAuditSink
) -> None:
    frozen = Principal(id="sam", roles=("support",), attributes={"frozen": True})

    with pytest.raises(AuthzDenied):
        _decide(audited, frozen)

    record = sink.records[0]

    assert set(record.proposed) == {"account", "secret", "region"}
    assert record.proposed["secret"] == "[redacted]"
    assert record.masked["secret"] == "redact"


@pytest.mark.unit
def test_a_governor_with_no_audit_sink_decides_the_same_and_records_nothing(
    sink: InMemoryAuditSink,
) -> None:
    """No ``audit=`` means no records are built at all, and the decision is the same."""
    bundle = PolicyBundle.from_text(POLICY, entities=ENTITIES, source="pack")
    engine = bundle.engine()
    principal = Principal(id="alice", roles=("support",))
    spec = ArgumentSpec.from_callable(lookup)

    unaudited = Governor(engine)
    audited = Governor(
        engine,
        audit=AuditTrail(sink, masker=Masker(key=b"a-test-hmac-key"), bundle=bundle),
        bundle=bundle,
    )

    quiet = unaudited.plan(
        spec,
        principal=principal,
        action=LOOKUP,
        resource=ACCOUNTS,
        proposed={"account": RAW_ACCOUNT},
        invocation_id="inv-1",
    )
    loud = audited.plan(
        spec,
        principal=principal,
        action=LOOKUP,
        resource=ACCOUNTS,
        proposed={"account": RAW_ACCOUNT},
        invocation_id="inv-1",
    )

    assert unaudited.audit is None
    assert unaudited.bundle is None
    assert quiet.allowed is loud.allowed
    assert quiet.processed == loud.processed
    assert quiet.rejected == loud.rejected
    # Only the audited governor produced a record.
    assert len(sink.records) == 1


# --- the chain, under the concurrency a host actually serves -------------------------------

THREADS = 8
"""How many threads decide at once.

Not a stress figure — it is the ordinary deployment. Flask's threaded development server,
gunicorn's gthread workers, waitress, and the threadpool FastAPI runs sync endpoints on all
put concurrent requests on threads in one process, sharing one trail.
"""

DECISIONS_PER_THREAD = 200
"""Decisions each thread asks for.

Appending is quick, so a handful of calls per thread can finish without ever overlapping
inside it. This many is enough that they overlap in nearly every run on an unsynchronized
trail — and on a synchronized one the chain either links or it does not, so the test never
flakes red against correct code.
"""

BARRIER_TIMEOUT = 30.0
"""Seconds a thread waits for its peers before giving up.

Only reached if a thread never starts at all, and then the barrier breaks and every thread
returns — so the assertions below fail on the record count instead of hanging the suite.
"""


@pytest.mark.unit
def test_the_chain_still_links_when_several_threads_decide_at_once(
    audited: Governor, sink: InMemoryAuditSink
) -> None:
    """One trail, many threads: every record links, and no position is handed out twice.

    Appending is read-modify-write — read the chain's tail, build the chained record, write
    it, advance — and two threads interleaving inside that produce a log whose records do not
    link and whose sequence numbers repeat. :func:`~sentrykit.audit.verify_chain` reads the
    result as a record removed or altered, so the control accuses a healthy log.
    """
    spec = ArgumentSpec.from_callable(lookup)
    principal = Principal(id="alice", roles=("support",))
    ready = threading.Barrier(THREADS, timeout=BARRIER_TIMEOUT)
    failures: list[Exception] = []

    def decide() -> None:
        try:
            # Released together, so the threads collide from the first decision rather than
            # staggering themselves across however long it takes to start eight of them.
            ready.wait()
            for _ in range(DECISIONS_PER_THREAD):
                audited.plan(
                    spec,
                    principal=principal,
                    action=LOOKUP,
                    resource=ACCOUNTS,
                    proposed={"account": RAW_ACCOUNT, "secret": RAW_SECRET},
                )
        except Exception as exc:
            # Carried out rather than swallowed: ``join`` discards what a thread raises, and
            # a decision that failed would otherwise read as a chain that is merely short.
            failures.append(exc)

    threads = [threading.Thread(target=decide) for _ in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    records = sink.records
    expected = THREADS * DECISIONS_PER_THREAD

    assert failures == []
    assert len(records) == expected
    assert len({record.sequence for record in records}) == expected
    assert verify_chain(records).ok


# --- a lost record has to incriminate the next one -----------------------------------------

REFUSED_WRITES = 3
"""How many records the sink swallows before it comes back.

More than one, because what lands afterwards has to carry a *count* and not a flag.
"""


class _FlakyAuditSink(InMemoryAuditSink):
    """Refuses its first few writes, then accepts everything. A full disk, in miniature.

    Coming back is the part that matters. A sink that never recovers leaves no later record
    to carry the loss out on, and the records it refused are gone either way — so the case
    worth testing is the one where the log resumes and has to say what is missing from it.
    """

    def __init__(self, *, refusals: int) -> None:
        super().__init__(name="flaky")
        self._remaining = refusals

    def write(self, record: AuthzAuditRecord) -> None:
        if self._remaining:
            self._remaining -= 1
            raise AuditUnavailable(self.name, "no space left on device")
        super().write(record)


@pytest.mark.unit
def test_a_record_the_sink_refused_is_counted_onto_the_next_one_that_lands() -> None:
    """A lost record leaves no gap for :func:`~sentrykit.audit.verify_chain` to find.

    The chain advances only on a successful write, so the records either side of an outage
    link cleanly and the run verifies — correctly, since nothing was altered. The count is
    what stops that from reading as "nothing happened": without it a caller could probe the
    whole policy boundary while the sink was down and the log would look clean across the
    hole.
    """
    sink = _FlakyAuditSink(refusals=REFUSED_WRITES)
    governor = _governor_over(sink, strict=False)
    alice = Principal(id="alice", roles=("support",))

    for _ in range(REFUSED_WRITES + 2):
        _decide(governor, alice)

    landed = sink.records

    assert len(landed) == 2
    assert landed[0].dropped_since_last_write == REFUSED_WRITES
    # Cleared on the write that reported it, so one loss is never declared twice.
    assert landed[1].dropped_since_last_write == 0
    # Intact and contiguous across the hole, which is exactly why the count has to exist.
    assert [record.sequence for record in landed] == [0, 1]
    assert verify_chain(landed).ok


@pytest.mark.unit
def test_a_refusal_lost_under_strict_is_counted_although_the_caller_saw_only_the_denial() -> None:
    """Strict mode is where a loss is *most* likely to go unrecorded, not least.

    A strict sink failure refuses the governed call — but on a call that was already being
    refused, surfacing it would replace the precise denial the caller needs, so it stops
    there. Here three denials reach the caller as denials, nothing reaches the sink, and the
    next record to land is the only trace that the boundary was tested at all.
    """
    sink = _FlakyAuditSink(refusals=REFUSED_WRITES)
    governor = _governor_over(sink, strict=True)
    frozen = Principal(id="sam", roles=("support",), attributes={"frozen": True})

    for _ in range(REFUSED_WRITES):
        with pytest.raises(AuthzDenied):
            _decide(governor, frozen)

    assert sink.records == ()

    _decide(governor, Principal(id="alice", roles=("support",)))

    assert sink.records[0].dropped_since_last_write == REFUSED_WRITES


@pytest.mark.unit
def test_a_record_with_no_losses_hashes_a_payload_the_count_is_absent_from(make_record) -> None:  # type: ignore[no-untyped-def]
    """The property that keeps a log written before this field existed verifiable.

    Every record already in a deployed log hashed a payload with no
    ``dropped_since_last_write`` key in it. A key that appeared at its default would change
    every one of those digests and turn an intact log into a broken one on the next read.
    Leaving it out at zero costs nothing, because a count that is *set* is in the payload —
    so it can be neither stripped off a record that reported a loss nor invented on one that
    did not.
    """
    clean: AuthzAuditRecord = make_record().chained(prev_hash=GENESIS_HASH, sequence=0)
    lossy: AuthzAuditRecord = make_record().chained(
        prev_hash=GENESIS_HASH, sequence=0, dropped_since_last_write=4
    )

    assert "dropped_since_last_write" not in clean.payload()
    assert lossy.payload()["dropped_since_last_write"] == 4
    assert clean.verify()
    assert lossy.verify()
    assert not lossy.model_copy(update={"dropped_since_last_write": 0}).verify()
    assert not clean.model_copy(update={"dropped_since_last_write": 9}).verify()


# --- the static half -----------------------------------------------------------------------

PACKAGE_ROOT = Path(sentrykit.__file__).parent

ALLOWED_SINK_WRITERS = frozenset(
    {
        # The only place a record is constructed, masked and chained.
        "audit.py",
        # A pure forwarder: ``CompositeAuditSink`` *is* an ``AuditSink``, and fans an
        # already-masked, already-chained record out to its members. It never builds one.
        "stores/composite.py",
    }
)

_SINK_RECEIVER = re.compile(r"sink", re.IGNORECASE)
"""Receivers that name an audit sink -- ``self._sink``, ``sink``, ``self._audit_sink``."""

_STREAM_RECEIVER = re.compile(r"handle|stream|buffer|stdout|stderr|file|\bfh\b|\bfp\b", re.I)
"""Receivers that are a byte or text stream. ``handle.write(line)`` is not an audit write."""

_RECORD_ARGUMENTS = frozenset({"record", "records", "masked_record", "chained_record"})
"""Bare argument names that mean "an audit record", for a receiver that hides its own type."""


def _core_sources() -> list[Path]:
    """Every ``.py`` file shipped in the package."""
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def _relative(path: Path) -> str:
    return path.relative_to(PACKAGE_ROOT).as_posix()


def _audit_sink_writes(source: str) -> list[str]:
    """Every call in ``source`` that hands a record to an audit sink."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "write" or not node.args:
            continue
        receiver = ast.unparse(node.func.value)
        if _STREAM_RECEIVER.search(receiver):
            continue
        first = node.args[0]
        names_a_sink = bool(_SINK_RECEIVER.search(receiver))
        passes_a_record = isinstance(first, ast.Name) and first.id in _RECORD_ARGUMENTS
        if names_a_sink or passes_a_record:
            found.append(f"{receiver}.write({ast.unparse(first)})")
    return found


@pytest.mark.unit
@pytest.mark.parametrize("source_path", _core_sources(), ids=_relative)
def test_only_the_audit_trail_and_its_fan_out_write_to_an_audit_sink(source_path: Path) -> None:
    writes = _audit_sink_writes(source_path.read_text(encoding="utf-8"))

    if _relative(source_path) in ALLOWED_SINK_WRITERS:
        return
    assert not writes, f"{_relative(source_path)} writes to an audit sink: {writes}"


@pytest.mark.unit
def test_the_audit_trail_really_is_the_module_that_writes() -> None:
    """Without this the scan above could pass because nothing writes anywhere."""
    trail = _audit_sink_writes((PACKAGE_ROOT / "audit.py").read_text(encoding="utf-8"))

    assert trail, "audit.py no longer writes to a sink; the scan above has become vacuous"


@pytest.mark.unit
def test_the_engine_reaches_a_sink_only_through_the_trail() -> None:
    engine = _audit_sink_writes((PACKAGE_ROOT / "engine.py").read_text(encoding="utf-8"))

    assert engine == []


@pytest.mark.unit
def test_the_scan_reaches_every_module_that_could_hold_a_write() -> None:
    scanned = {_relative(path) for path in _core_sources()}

    assert scanned >= {"audit.py", "engine.py", "decorator.py", "stores/base.py"}
    assert scanned >= ALLOWED_SINK_WRITERS


@pytest.mark.unit
@pytest.mark.parametrize(
    "source",
    [
        "self._sink.write(record)",
        "sink.write(record)",
        "for sink in self._sinks:\n    sink.write(entry)",
        "target.write(record)",
        "def go(self):\n    self._audit_sink.write(masked_record)",
        "class G:\n    def go(self):\n        replica.write(records)",
    ],
)
def test_the_scanner_would_catch_a_write_that_bypassed_the_trail(source: str) -> None:
    assert _audit_sink_writes(source)


@pytest.mark.unit
@pytest.mark.parametrize(
    "source",
    [
        "self._handle.write(line)",
        'self._handle.write(json.dumps(payload) + "\\n")',
        "sys.stdout.write(text)",
        "buffer.write(data)",
        "self._file.write(record_line)",
        "path.write_text(policies)",
    ],
)
def test_the_scanner_leaves_ordinary_stream_writes_alone(source: str) -> None:
    assert _audit_sink_writes(source) == []


@pytest.mark.unit
def test_a_record_is_immutable_once_it_has_been_built(make_record) -> None:  # type: ignore[no-untyped-def]
    """Chaining produces a new record, so a written one cannot be edited in place."""
    record: AuthzAuditRecord = make_record()

    with pytest.raises(Exception, match=r"frozen|immutable"):
        record.reason = "rewritten"  # type: ignore[misc]
