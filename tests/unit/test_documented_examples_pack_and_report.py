"""The shipped-pack and audit-report examples in the docs do what those pages say they do.

Same reason as the other pinning modules, restated once more because it keeps being the thing
that matters: documentation that has drifted from the code is worse than none, because a
reader trusts it, copies it, and then debugs the wrong thing.

This file pins the pack half of `docs/policies.md` (the shipped policy pack, the schema
opt-in, template-linked grants, administering grants) and the report half of
`docs/audit.md`. Every literal asserted here appears verbatim on one of those pages. If a
page and this file disagree, one of them is a bug.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentrykit import (
    AuditWindow,
    Entity,
    EntityRef,
    Principal,
    configure,
    establish,
    install,
    protect,
)
from sentrykit.cli import EXIT_OK, build_report, main, render_markdown
from sentrykit.errors import SentrykitError
from sentrykit.policy import PATTERNS, LinkedPolicySource, link_template, pack_template
from sentrykit.stores import InMemoryAuditSink

# --- docs/policies.md — The shipped policy pack ------------------------------------------


@pytest.fixture
def pack_entities() -> list[Entity]:
    """The entity shapes the page's examples decide against."""
    return [
        Entity(EntityRef("Role", "support")),
        Entity(EntityRef("Role", "auditor")),
        Entity(
            EntityRef("Resource", "orders"),
            attributes={"required_role": EntityRef("Role", "support")},
        ),
        Entity(
            EntityRef("Resource", "vault"),
            attributes={
                "emergency_only": True,
                "emergency_role": EntityRef("Role", "auditor"),
            },
        ),
    ]


@pytest.mark.unit
def test_the_pack_composes_with_a_directory_the_way_the_page_shows(
    tmp_path: Path, pack_entities: list[Entity]
) -> None:
    """`install(policy_source=["pack://", "file://./policies"])`, verbatim from the page."""
    directory = tmp_path / "policies"
    directory.mkdir()
    (directory / "00-house.cedar").write_text(
        '@id("anyone-may-ping")\npermit (principal, action == Action::"ping", resource);\n',
        encoding="utf-8",
    )

    governor = install(policy_source=["pack://", f"file://{directory}"], entities=pack_entities)

    bundle = governor.bundle
    assert bundle is not None
    ids = [entry.policy_id for entry in bundle.provenance]
    # The page's claim about *where* the namespace appears: on the provenance index.
    assert "pack/rbac-required-role" in ids
    assert "policies/anyone-may-ping" in ids


@pytest.mark.unit
def test_a_subset_dsn_loads_only_those_patterns(pack_entities: list[Entity]) -> None:
    """`pack://rbac,ownership` — the page's "take a subset when you want one"."""
    governor = install(policy_source="pack://rbac,ownership", entities=pack_entities)

    bundle = governor.bundle
    assert bundle is not None
    assert [entry.policy_id for entry in bundle.provenance] == [
        "rbac-required-role",
        "resource-owner",
    ]


@pytest.mark.unit
def test_the_pattern_table_reads_as_the_page_prints_it() -> None:
    """The `PATTERNS` snippet, output included."""
    assert PATTERNS["break-glass"].policy_ids == (
        "emergency-resource-forbidden-without-flag",
        "break-the-glass",
    )
    assert PATTERNS["break-glass"].requires == (
        "resource.emergency_only",
        "resource.emergency_role",
        "context.break_glass",
        "context.justification",
    )


@pytest.mark.unit
def test_the_raw_and_namespaced_spellings_are_where_the_page_says(
    tmp_path: Path, pack_entities: list[Entity]
) -> None:
    """Cedar reports the raw `@id`; the record's provenance carries the namespaced one."""
    sink = InMemoryAuditSink()
    configure(hmac_key="dev-key-not-for-production")
    directory = tmp_path / "policies"
    directory.mkdir()
    (directory / "00-house.cedar").write_text(
        '@id("anyone-may-ping")\npermit (principal, action == Action::"ping", resource);\n',
        encoding="utf-8",
    )
    install(
        policy_source=["pack://", f"file://{directory}"],
        entities=pack_entities,
        audit_sink=sink,
    )

    @protect(action='Action::"access"', resource='Resource::"orders"')
    def read_orders(customer_id: str) -> dict[str, object]:
        return {"customer_id": customer_id}

    with establish(Principal(id="alice", roles=("support",)), channel="web"):
        read_orders(customer_id="c-1")

    record = sink.records[-1]
    assert record.determining_policies == ("rbac-required-role",)
    assert record.provenance[0]["policy_id"] == "pack/rbac-required-role"
    assert record.provenance[0]["source"] == "pack"


@pytest.mark.unit
def test_break_the_glass_takes_three_things_not_one(pack_entities: list[Entity]) -> None:
    """The `establish(..., break_glass=True, justification=...)` example, and its refusals."""
    install(policy_source="pack://", entities=pack_entities)

    @protect(action='Action::"access"', resource='Resource::"vault"')
    def open_vault(item: str) -> dict[str, object]:
        return {"item": item}

    ana = Principal(id="ana", roles=("auditor",))

    with establish(ana, channel="web", break_glass=True, justification="incident 4471"):
        assert open_vault(item="master-key")["item"] == "master-key"

    # The flag alone is not enough, and neither is the entitlement alone.
    with establish(ana, channel="web"), pytest.raises(SentrykitError):
        open_vault(item="master-key")
    unentitled = Principal(id="mallory", roles=())
    with (
        establish(unentitled, channel="web", break_glass=True, justification="please"),
        pytest.raises(SentrykitError),
    ):
        open_vault(item="master-key")


@pytest.mark.unit
def test_the_schema_is_off_by_default_and_on_by_dsn() -> None:
    """`pack://?schema=true` is the page's opt-in; without it the bundle carries none."""
    from sentrykit.registry import build_policy_source

    plain = build_policy_source("pack://")
    opted_in = build_policy_source("pack://?schema=true")
    assert plain is not None
    assert opted_in is not None

    assert plain.load().schema is None
    assert "entity Role in [Role];" in (opted_in.load().schema or "")


@pytest.mark.unit
def test_the_linked_template_reads_exactly_as_the_page_prints_it() -> None:
    """The `link_template` example, and the generated policy text shown beneath it."""
    link = link_template(
        pack_template("time-boxed-grant"),
        link_id="oncall-ana",
        principal='User::"ana"',
        resource='Resource::"paging"',
        expires_at=datetime(2026, 9, 1, tzinfo=UTC),
        granted_by="ops",
        reason="on-call rotation",
    )

    assert link.policy == (
        '@id("oncall-ana")\n'
        "permit (\n"
        '  principal == User::"ana",\n'
        "  action,\n"
        '  resource == Resource::"paging"\n'
        ")\n"
        "when { context has now && context.now <= 1788220800 };\n"
    )
    assert link.grant.expires_at == datetime(2026, 9, 1, tzinfo=UTC)
    assert link.grant.granted_by == "ops"

    # And it composes, which is the line after the snippet.
    governor = install(policy_source=["pack://", LinkedPolicySource([link])])
    bundle = governor.bundle
    assert bundle is not None
    assert "linked/oncall-ana" in [entry.policy_id for entry in bundle.provenance]


# --- docs/audit.md — The yearly report is a query -----------------------------------------


@pytest.fixture
def seeded_log(tmp_path: Path, pack_entities: list[Entity]) -> Path:
    """A real log, written through the real pipeline — four allows and three refusals."""
    log = tmp_path / "audit.jsonl"
    configure(hmac_key="dev-key-not-for-production")
    install(
        policy_source="pack://",
        entities=pack_entities,
        audit_sink=f"jsonl://{log}",
    )

    @protect(action='Action::"access"', resource='Resource::"orders"')
    def read_orders(customer_id: str) -> dict[str, object]:
        return {"customer_id": customer_id}

    @protect(action='Action::"access"', resource='Resource::"vault"')
    def open_vault(item: str) -> dict[str, object]:
        return {"item": item}

    alice = Principal(id="alice", roles=("support",))
    mallory = Principal(id="mallory", roles=())
    ana = Principal(id="ana", roles=("auditor",))

    for _ in range(3):
        with establish(alice, channel="web"):
            read_orders(customer_id="c-1")
    for _ in range(2):
        with establish(mallory, channel="web"), pytest.raises(SentrykitError):
            read_orders(customer_id="c-9")
    with establish(ana, channel="web"), pytest.raises(SentrykitError):
        open_vault(item="master-key")
    with establish(ana, channel="web", break_glass=True, justification="incident 4471"):
        open_vault(item="master-key")
    return log


@pytest.mark.unit
def test_the_report_aggregates_by_outcome_as_the_page_shows(seeded_log: Path) -> None:
    """The `## Outcomes` table on the page, and the determining-policy column beside it."""
    from sentrykit.registry import build_audit_sink

    sink = build_audit_sink(f"jsonl://{seeded_log}")
    assert sink is not None
    window = AuditWindow(
        start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2027, 1, 1, tzinfo=UTC)
    )
    report = build_report(sink.query(window), window=window, sink=sink.name)

    assert report.by_outcome == {"allowed": 4, "denied": 3}
    assert report.by_policy["rbac-required-role"] == 3
    assert report.by_policy["break-the-glass"] == 1
    assert report.by_obligation == {"notify:secops": 1, "record:justification": 1}

    document = render_markdown(report)
    assert "| Outcome | Count |" in document
    assert "| allowed | 4 |" in document
    assert "- Records whose own hash recomputes: 7 of 7." in document
    assert "- Chain: intact across the window." in document


@pytest.mark.unit
def test_the_documented_audit_report_invocation_runs(seeded_log: Path, tmp_path: Path) -> None:
    """The `sentrykit audit-report --from … --to … --out … --sink …` line on the page."""
    out = tmp_path / "audit.md"

    code = main(
        [
            "audit-report",
            "--from",
            "2026-01-01",
            "--to",
            "2026-12-31",
            "--out",
            str(out),
            "--sink",
            f"jsonl://{seeded_log}",
        ]
    )

    assert code == EXIT_OK
    document = out.read_text(encoding="utf-8")
    assert document.startswith("# Audit report: 2026-01-01 to 2026-12-31")
    assert "| Records | 7 |" in document


@pytest.mark.unit
def test_a_principal_filtered_window_reports_no_chain_verdict(seeded_log: Path) -> None:
    """The page's "the chain is only checked when the window applies no identity filter"."""
    from sentrykit.registry import build_audit_sink

    sink = build_audit_sink(f"jsonl://{seeded_log}")
    assert sink is not None
    window = AuditWindow(principal='User::"alice"')

    report = build_report(sink.query(window), window=window, sink=sink.name)

    assert report.chain is None
    assert report.verified == report.total == 3


# --- docs/quickstart.md — Skip step 1 entirely / Check it before you ship it ---------------


@pytest.mark.unit
def test_the_quickstart_pack_snippet_authorizes_with_no_policy_written() -> None:
    """The whole point of the section: a working gate with no hand-written policy."""
    install(
        policy_source="pack://",
        entities=[
            Entity(EntityRef("Role", "support")),
            Entity(
                EntityRef("Resource", "orders"),
                attributes={"required_role": EntityRef("Role", "support")},
            ),
        ],
    )

    @protect(action='Action::"access"', resource='Resource::"orders"')
    def search_orders(customer_id: str) -> dict[str, object]:
        return {"customer_id": customer_id}

    with establish(Principal(id="alice", roles=("support",)), channel="web"):
        assert search_orders(customer_id="c-1")["customer_id"] == "c-1"

    with (
        establish(Principal(id="mallory", roles=()), channel="web"),
        pytest.raises(SentrykitError),
    ):
        search_orders(customer_id="c-1")


@pytest.mark.unit
def test_the_documented_policy_validate_invocation_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`sentrykit policy validate ./policies`, and the non-zero exit the page promises."""
    directory = tmp_path / "policies"
    directory.mkdir()
    (directory / "app.cedarschema").write_text(
        "entity User;\nentity Resource;\n"
        'action "read" appliesTo { principal: [User], resource: [Resource], context: {} };\n',
        encoding="utf-8",
    )
    (directory / "00-app.cedar").write_text(
        '@id("anyone-may-read")\npermit (principal, action == Action::"read", resource);\n',
        encoding="utf-8",
    )

    assert main(["policy", "validate", str(directory)]) == EXIT_OK

    # A policy naming an action the schema does not declare fails, and names the @id.
    (directory / "10-broken.cedar").write_text(
        '@id("typo")\npermit (principal, action == Action::"raed", resource);\n',
        encoding="utf-8",
    )
    assert main(["policy", "validate", str(directory)]) != EXIT_OK
    assert "typo" in capsys.readouterr().out


@pytest.mark.unit
def test_policy_validate_with_no_directory_checks_the_shipped_pack(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The page's "a quick way to confirm an install"."""
    assert main(["policy", "validate"]) == EXIT_OK
    assert "validation: passed" in capsys.readouterr().out


# --- docs/policies.md — Administering grants ----------------------------------------------


@pytest.fixture
def admin_policy(tmp_path: Path) -> Path:
    """The permit the page tells you to write, verbatim."""
    directory = tmp_path / "admin-policies"
    directory.mkdir()
    (directory / "00-admin.cedar").write_text(
        '@id("root-may-administer-grants")\n'
        "permit (\n"
        '  principal in Role::"admin",\n'
        '  action in [Action::"admin.grant", Action::"admin.revoke"],\n'
        '  resource == Resource::"admin.grants"\n'
        ");\n",
        encoding="utf-8",
    )
    return directory


@pytest.fixture
def bootstrapped_store(tmp_path: Path) -> Path:
    """The provisioning snippet from 'Bootstrapping the first operator'."""
    from sentrykit.stores import JsonFileGrantStore
    from sentrykit.stores.base import GrantSpec

    path = tmp_path / "var" / "grants.json"
    store = JsonFileGrantStore(path)
    store.add_entity(Entity(EntityRef("Role", "admin")))
    store.add_entity(Entity(EntityRef("Role", "oncall")))
    store.grant(
        GrantSpec(
            principal=EntityRef("User", "root"),
            kind="role",
            subject="admin",
            granted_by="bootstrap",
            reason="initial operator",
        )
    )
    return path


@pytest.mark.unit
def test_the_documented_grant_and_revoke_invocations_run(
    tmp_path: Path,
    admin_policy: Path,
    bootstrapped_store: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The three shell lines on the page, and the record counts the page promises."""
    from sentrykit.registry import build_audit_sink

    log = tmp_path / "audit.jsonl"
    common = [
        "--store",
        f"jsonfile://{bootstrapped_store}",
        "--policy",
        f"file://{admin_policy}",
        "--sink",
        f"jsonl://{log}",
    ]

    assert (
        main(
            [
                "grant",
                'User::"ana"',
                "--role",
                "oncall",
                "--expires",
                "2026-09-01",
                "--reason",
                "on-call rotation",
                "--as",
                'User::"root"',
                *common,
            ]
        )
        == EXIT_OK
    )
    capsys.readouterr()

    # `sentrykit grants` — a *separate* invocation over the same file sees it.
    assert main(["grants", 'User::"ana"', "--store", f"jsonfile://{bootstrapped_store}"]) == EXIT_OK
    listing = capsys.readouterr().out
    assert 'User::"ana" holds 1 grant(s).' in listing
    grant_id = listing.split("id=")[1].split()[0]

    assert (
        main(["revoke", grant_id, "--reason", "shift ended", "--as", 'User::"root"', *common])
        == EXIT_OK
    )

    # Two records per allowed mutation: the decision, then the mutation. `grants` writes none.
    sink = build_audit_sink(f"jsonl://{log}")
    assert sink is not None
    assert [(r.kind, r.outcome) for r in sink.query(AuditWindow())] == [
        ("decision", "allowed"),
        ("mutation", "granted"),
        ("decision", "allowed"),
        ("mutation", "revoked"),
    ]


@pytest.mark.unit
def test_an_operator_the_store_does_not_know_is_refused(
    tmp_path: Path, admin_policy: Path, bootstrapped_store: Path
) -> None:
    """ "An operator the store has never heard of is refused" — there is no back door."""
    from sentrykit.registry import build_audit_sink

    log = tmp_path / "audit.jsonl"

    code = main(
        [
            "grant",
            'User::"eve"',
            "--role",
            "admin",
            "--as",
            'User::"mallory"',
            "--store",
            f"jsonfile://{bootstrapped_store}",
            "--policy",
            f"file://{admin_policy}",
            "--sink",
            f"jsonl://{log}",
        ]
    )

    assert code != EXIT_OK
    assert not log.exists() or list(build_audit_sink(f"jsonl://{log}").query(AuditWindow())) == []  # type: ignore[union-attr]


@pytest.mark.unit
def test_the_proposed_grant_is_argument_filtered(
    tmp_path: Path, admin_policy: Path, bootstrapped_store: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The page's constraint snippet: asking for `admin` stores `oncall`."""
    from sentrykit.constraints import ArgumentConstraint
    from sentrykit.stores import JsonFileGrantStore
    from sentrykit.stores.base import GrantSpec

    store = JsonFileGrantStore(bootstrapped_store)
    store.grant(
        GrantSpec(
            principal=EntityRef("User", "root"),
            kind="constraint",
            subject="subject",
            action='Action::"admin.grant"',
            constraint=ArgumentConstraint(
                allow=("oncall",), default="oncall", policy="grant-admin-scope"
            ),
        )
    )

    code = main(
        [
            "grant",
            'User::"ana"',
            "--role",
            "admin",
            "--as",
            'User::"root"',
            "--store",
            f"jsonfile://{bootstrapped_store}",
            "--policy",
            f"file://{admin_policy}",
        ]
    )

    assert code == EXIT_OK
    assert "Granted role 'oncall'" in capsys.readouterr().out
    stored = JsonFileGrantStore(bootstrapped_store).grants_for('User::"ana"')
    assert [record.spec.subject for record in stored] == ["oncall"]


# --- README.md ----------------------------------------------------------------------------


@pytest.mark.unit
def test_the_readme_quotes_the_pack_policy_verbatim() -> None:
    """The README prints a shipped forbid. If the pack changes, the README has to.

    Quoting policy text in prose is exactly where drift hides: the claim reads as true long
    after the rule stopped saying that. Compared against the file rather than eyeballed.
    """
    from sentrykit.policy import pack_root

    quoted = (
        '@id("delegation-outside-scope-forbidden")\n'
        "forbid (principal, action, resource)\n"
        "when { principal has delegated_actions && !(action in principal.delegated_actions) };"
    )
    shipped = (pack_root() / "40-delegation.cedar").read_text(encoding="utf-8")

    normalized = " ".join(shipped.split())
    assert " ".join(quoted.split()) in normalized

    readme = Path(__file__).resolve().parents[2] / "README.md"
    assert quoted in readme.read_text(encoding="utf-8")
