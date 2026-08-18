"""Tests for the commit-message policy gate (scripts/check_commit_msg.py)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_commit_msg.py"
_spec = importlib.util.spec_from_file_location("check_commit_msg", _SCRIPT)
assert _spec and _spec.loader
_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gate)


@pytest.mark.unit
@pytest.mark.parametrize(
    "message",
    [
        "feat(engine): add argument filter",
        "fix(cedar): surface determining policies",
        "docs: expand quickstart",
        "refactor(stores)!: rename GrantStore.grant",
    ],
)
def test_accepts_clean_conventional_messages(message: str) -> None:
    assert _gate.check(message) == []


@pytest.mark.unit
def test_rejects_non_conventional_header() -> None:
    problems = _gate.check("updated some stuff")
    assert any("Conventional Commits" in p for p in problems)


@pytest.mark.unit
@pytest.mark.parametrize(
    "message",
    [
        "feat: add filter\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        "fix: patch bug\n\nGenerated with an AI assistant",
        "docs: update readme (as an AI, I improved it)",
    ],
)
def test_rejects_tooling_attribution(message: str) -> None:
    problems = _gate.check(message)
    assert any("disallowed tooling" in p for p in problems)
