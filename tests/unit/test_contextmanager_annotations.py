"""No ``@contextmanager`` in this repo is annotated with the deprecated return type.

Recent typeshed marks one spelling of a very common annotation as deprecated::

    The function "contextmanager" is deprecated
    Annotating the return type as `-> Iterator[Foo]` with `@contextmanager` is deprecated.
    Use `-> Generator[Foo]` instead.

Checked *statically*, with ``ast``, and the reason is the whole point of this module: the
checker that reports it is not the one this project runs. ``mypy`` bundles its own copy of
typeshed, and at the version pinned here that copy carries a single non-overloaded signature
for ``contextmanager`` with no deprecation on it at all — so ``pixi run typecheck`` is green
either way and says nothing about this. A reader's editor, which ships a newer typeshed, says
it on every such function. A rule that only one person's tooling enforces is not a rule, so it
is enforced here instead, where it holds regardless of whose typeshed is newer.

The distinction being enforced is narrow and easy to get wrong in the other direction. It
applies **only** to a function decorated with ``@contextmanager`` or ``@asynccontextmanager``.
An ordinary generator, and in particular a pytest fixture, is correctly annotated
``-> Iterator[None]`` and must be left alone — this repo has many, and a sweep that "fixed"
them would be a regression dressed as hygiene.

``Generator`` is spelled with all three arguments. The one-argument form relies on PEP 696
defaults that arrive in Python 3.13, and both ``ruff`` (``target-version = "py311"``) and
``mypy`` (``python_version = "3.11"``) are configured for 3.11 here, so the short form would be
wrong for the versions this project actually supports.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCANNED_DIRS = ("src", "tests", "examples", "scripts", "docs")

CONTEXT_MANAGER_DECORATORS = frozenset({"contextmanager", "asynccontextmanager"})
DEPRECATED_RETURNS = frozenset({"Iterator", "AsyncIterator"})


def _sources() -> list[Path]:
    """Every ``.py`` file this project owns, excluding generated and vendored trees."""
    found: list[Path] = []
    for directory in SCANNED_DIRS:
        root = REPO_ROOT / directory
        if root.is_dir():
            found.extend(sorted(root.rglob("*.py")))
    return found


def _decorator_name(node: ast.expr) -> str:
    """The bare name of a decorator, however it was reached.

    ``@contextmanager``, ``@contextlib.contextmanager`` and ``@contextmanager()`` all have to
    resolve to the same name, because all three decorate the same way and a scan that only knew
    the first spelling would be a scan somebody could walk around without meaning to.
    """
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _annotation_name(node: ast.expr | None) -> str:
    """The bare name of a return annotation's outermost subscripted type."""
    if isinstance(node, ast.Subscript):
        return _annotation_name(node.value)
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        # A quoted annotation, which `from __future__ import annotations` makes unnecessary but
        # does not forbid. Parsed rather than string-matched so `"Iterator[int]"` and
        # `"collections.abc.Iterator[int]"` both resolve.
        try:
            return _annotation_name(ast.parse(node.value, mode="eval").body)
        except SyntaxError:  # pragma: no cover - an annotation that does not parse
            return ""
    return ""


def _offenders(source: str) -> list[tuple[str, str]]:
    """Every context manager in ``source`` whose return type is the deprecated spelling.

    Returns:
        One ``(function name, annotation name)`` pair per offending function.
    """
    found: list[tuple[str, str]] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        names = {_decorator_name(decorator) for decorator in node.decorator_list}
        if not names & CONTEXT_MANAGER_DECORATORS:
            continue
        returns = _annotation_name(node.returns)
        if returns in DEPRECATED_RETURNS:
            found.append((node.name, returns))
    return found


@pytest.mark.parametrize("source_path", _sources(), ids=lambda path: path.name)
@pytest.mark.unit
def test_a_context_manager_is_annotated_as_a_generator(source_path: Path) -> None:
    offenders = _offenders(source_path.read_text(encoding="utf-8"))

    assert offenders == [], (
        f"{source_path.relative_to(REPO_ROOT).as_posix()} decorates "
        + ", ".join(f"{name}() -> {returns}[...]" for name, returns in offenders)
        + " with @contextmanager. Annotate it as Generator[..., None, None] "
        "(or AsyncGenerator[..., None]) instead."
    )


@pytest.mark.unit
def test_the_scan_reaches_the_whole_project() -> None:
    """A scan that found nothing because it looked nowhere would pass forever."""
    scanned = {path.relative_to(REPO_ROOT).parts[0] for path in _sources()}

    assert scanned == set(SCANNED_DIRS)
    assert len(_sources()) > 50


@pytest.mark.parametrize(
    "source",
    [
        "@contextmanager\ndef f() -> Iterator[int]: ...",
        "@contextlib.contextmanager\ndef f() -> Iterator[int]: ...",
        "@contextmanager\ndef f() -> collections.abc.Iterator[int]: ...",
        '@contextmanager\ndef f() -> "Iterator[int]": ...',
        "@asynccontextmanager\nasync def f() -> AsyncIterator[int]: ...",
        "class C:\n    @contextmanager\n    def f(self) -> Iterator[int]: ...",
    ],
)
@pytest.mark.unit
def test_the_scanner_catches_every_spelling_it_has_to(source: str) -> None:
    assert _offenders(source) != []


@pytest.mark.parametrize(
    "source",
    [
        # The corrected forms.
        "@contextmanager\ndef f() -> Generator[int, None, None]: ...",
        "@asynccontextmanager\nasync def f() -> AsyncGenerator[int, None]: ...",
        # An ordinary generator, and a pytest fixture, are *correctly* Iterator-annotated.
        # These two cases are why the scan reads the decorator list rather than the return
        # type alone, and this repo is full of the second one.
        "def f() -> Iterator[int]: ...",
        "@pytest.fixture\ndef f() -> Iterator[None]: ...",
        "@pytest.fixture(autouse=True)\ndef f() -> Iterator[None]: ...",
    ],
)
@pytest.mark.unit
def test_the_scanner_leaves_alone_what_is_already_correct(source: str) -> None:
    assert _offenders(source) == []
