"""No commit in this repository's history carries a tooling reference.

``CLAUDE.md`` forbids any mention of an AI assistant, a model, or generated-by attribution in
a commit message, and ``scripts/check_commit_msg.py`` enforces it as a ``commit-msg`` hook.
A hook is a good first line and it is not a guarantee: it protects a machine that ran
``pixi run setup``, it does not protect one that did not, ``--no-verify`` walks around it, and
nothing re-checks a message once it has landed. So the property is asserted here, over the
history that actually exists, which is the only place it can be confirmed rather than assumed.

The rules are **imported** from the hook's own module rather than restated. A second copy of
the forbidden-term list is a second thing to keep current, and the copy that drifts is always
the one nobody is looking at.

This module reads git and nothing else, so it skips rather than fails in the two situations
where there is no history to read: an installed distribution, which ships no ``.git``, and a
shallow clone, where ``git log`` can only see the tip. The second one matters more than it
looks — ``actions/checkout`` fetches depth 1 unless told otherwise, and a check that silently
inspects one commit is worse than no check, because it reports success. It skips loudly in
that case, and ``.github/workflows/ci.yml`` asks for the full history so that it does not have
to.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from scripts.check_commit_msg import check

REPO_ROOT = Path(__file__).resolve().parents[2]

# Separators that cannot occur in a commit message: unit separator between the id and the body,
# record separator between commits. Splitting on a newline would break on the first multi-line
# body, and every body in this repository is multi-line.
_FIELD = "\x1f"
_RECORD = "\x1e"


def _git(*arguments: str) -> str:
    """Run a read-only git command in the repository root."""
    return subprocess.run(
        ["git", *arguments],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout.strip()


def _history_is_readable() -> str | None:
    """Return the reason the history cannot be checked, or ``None`` when it can."""
    if not (REPO_ROOT / ".git").exists():
        return "not a git checkout, so there is no history to read"
    try:
        if _git("rev-parse", "--is-shallow-repository") == "true":
            return (
                "the clone is shallow, so git can see only the tip -- fetch the full history "
                "(actions/checkout with fetch-depth: 0) for this check to mean anything"
            )
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover - no git binary
        return f"git could not be run: {exc}"
    return None


def _commits() -> list[tuple[str, str]]:
    """Every commit reachable from any ref, as ``(short id, full message)``."""
    raw = _git("log", "--all", f"--format=%h{_FIELD}%B{_RECORD}")
    found: list[tuple[str, str]] = []
    for record in raw.split(_RECORD):
        if _FIELD not in record:
            continue
        identifier, body = record.split(_FIELD, 1)
        found.append((identifier.strip(), body))
    return found


_UNREADABLE = _history_is_readable()

# Applied per test rather than to the module, because the last test in this file reads no
# history at all -- it checks that the rules can report a bad message -- and that one has to
# keep running where the history cannot be read. It is the test that stops a clean result
# meaning "the scanner is broken".
needs_history = pytest.mark.skipif(_UNREADABLE is not None, reason=_UNREADABLE or "")


@needs_history
@pytest.mark.unit
def test_no_commit_message_mentions_a_tool_or_claims_generated_attribution() -> None:
    offenders = [
        (identifier, problem)
        for identifier, body in _commits()
        for problem in check(body)
        if "disallowed tooling" in problem
    ]

    assert offenders == [], "\n".join(
        f"{identifier}: {problem}" for identifier, problem in offenders
    )


@needs_history
@pytest.mark.unit
def test_every_commit_message_follows_conventional_commits() -> None:
    """The hook's other half, asserted over the same history for the same reason."""
    offenders = [
        (identifier, problem)
        for identifier, body in _commits()
        for problem in check(body)
        if "disallowed tooling" not in problem
    ]

    assert offenders == [], "\n".join(
        f"{identifier}: {problem}" for identifier, problem in offenders
    )


@needs_history
@pytest.mark.unit
def test_the_scan_read_a_real_history_rather_than_a_truncated_one() -> None:
    """The assertion that stops the two tests above passing by looking at nothing."""
    commits = _commits()

    assert len(commits) > 50
    assert _git("rev-parse", "--short", "HEAD") in {identifier for identifier, _ in commits}


@pytest.mark.parametrize(
    "message",
    [
        "fix(engine): something\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        "fix(engine): something\n\nGenerated with an assistant",
        "feat(core): written by Copilot",
        "chore: bump\n\n\U0001f916",
    ],
)
@pytest.mark.unit
def test_the_rules_would_catch_a_message_that_did_mention_a_tool(message: str) -> None:
    """A clean history proves nothing unless the thing reading it can report a dirty one."""
    assert [problem for problem in check(message) if "disallowed tooling" in problem] != []
