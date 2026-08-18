"""The invariant ADR-007 rests on: nothing raw ever reaches an append-only sink.

Checked two ways, because each catches what the other cannot.

*Behaviourally*, a real :class:`~sentrykit.engine.Governor` decides three ways — an allow, a
lenient argument drop, and a denial — and every record it produced is serialized to JSON and
searched for the raw strings that went in. The drop case is the one that is easy to get wrong:
the argument was refused, but the value the caller proposed is still attached to the rejection
to explain *why*, and it is every bit as sensitive as one that got through.

*Statically*, every module under ``src/sentrykit/`` is parsed with ``ast`` and checked for
calls that hand a record to an audit sink. Masking runs inside
:class:`~sentrykit.audit.AuditTrail`, so "masking runs before the write" holds only for as
long as the trail is the only thing that writes. This is the audit-side analogue of the phase
1 import scan: a future caller that reaches around the trail fails the suite rather than the
compliance review.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Annotated

import pytest

import sentrykit
from sentrykit.audit import AuditTrail, AuthzAuditRecord
from sentrykit.cedar import Entity, EntityRef
from sentrykit.constraints import ArgumentConstraint, ConstraintSet
from sentrykit.context import Principal
from sentrykit.engine import ArgumentSpec, Governor
from sentrykit.errors import AuthzDenied
from sentrykit.masking import Masker, Sensitive
from sentrykit.stores.base import PolicyBundle
from sentrykit.stores.memory import InMemoryAuditSink

# --- the behavioural half ------------------------------------------------------------------

RAW_ACCOUNT = "ACCT-3141592653-TOPSECRET"
RAW_SECRET = "hunter2-plaintext-password-xyz"
RAW_ATTRIBUTE = "attribute-value-nobody-should-see"
RAW_VALUES = (RAW_ACCOUNT, RAW_SECRET, RAW_ATTRIBUTE)

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
) -> dict[str, str]:
    """``account`` is sensitive by signature; ``secret`` only by policy obligation."""
    return {"account": account, "region": region}


@pytest.fixture
def sink() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture
def audited(sink: InMemoryAuditSink) -> Governor:
    """A governor whose every decision lands in ``sink``, masked on the way in."""
    bundle = PolicyBundle.from_text(POLICY, entities=ENTITIES, source="pack", origin="pack.cedar")
    trail = AuditTrail(sink, masker=Masker(key=b"a-test-hmac-key"), bundle=bundle)
    return Governor(bundle.engine(), audit=trail, bundle=bundle)


def _rendered(sink: InMemoryAuditSink) -> str:
    """Every record the sink holds, as one JSON blob to search."""
    return json.dumps(
        [record.model_dump(mode="json") for record in sink.records],
        default=str,
        ensure_ascii=False,
    )


def _decide(governor: Governor, principal: Principal) -> None:
    governor.plan(
        ArgumentSpec.from_callable(lookup),
        principal=principal,
        action=LOOKUP,
        resource=ACCOUNTS,
        proposed={"account": RAW_ACCOUNT, "secret": RAW_SECRET, "region": "eu-west"},
    )


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
    """The rejection explains itself by carrying the value that was refused."""
    constrained = Principal(
        id="casey",
        roles=("support",),
        constraints={
            'Action::"tool.lookup"': ConstraintSet(
                arguments={
                    "account": ArgumentConstraint(allow=("ACCT-OK",), policy="grant-accounts")
                }
            )
        },
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
def test_a_governor_wired_the_phase_one_way_decides_the_same_and_records_nothing(
    sink: InMemoryAuditSink,
) -> None:
    """No ``audit=`` means no records are built at all — phase 1 behaviour, unchanged."""
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
