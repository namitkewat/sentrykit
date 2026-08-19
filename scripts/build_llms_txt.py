#!/usr/bin/env python3
"""Flatten the Markdown documentation build into `llms.txt` and `llms-full.txt`.

`llms.txt` is a convention for handing a language model a curated, plain-Markdown map of a
project instead of leaving it to scrape rendered HTML: an H1 with the project name, a
one-sentence blockquote summary, then H2 sections of `[name](url): description` links.
`llms-full.txt` is its companion — the whole corpus in one file, so an agent can read
everything in a single fetch with no navigation at all.

Both are written here rather than by an extension, and the reason is what goes *into* them.
The maintained extension builds its full text by concatenating `_sources`, which is the raw
MyST input: the API reference comes out as the literal text of an `automodule` directive
rather than the module it stands for, which is the requirement inverted. `sphinx-build -b
markdown` renders the *resolved* doctree, so every signature and every docstring is already
expanded — and reading that output is also what buys control of page **order**, which is the
other thing the extension cannot give. Concepts belong before the API reference; alphabetical
is not a reading order.

Because the repository is private, the documentation ships as release assets and there is no
site to link to. Link targets therefore name **sibling assets on the same release**:
`llms-full.txt` plus a fragment for the prose, and the HTML archive for anyone who would
rather read a rendered page. Nothing here points at a URL that does not exist.

Run after `sphinx-build -b markdown docs dist/docs/markdown` — `pixi run docs-llms` does both.
"""

from __future__ import annotations

import re
import sys
from importlib import metadata
from pathlib import Path
from typing import Final, NamedTuple

ROOT: Final = Path(__file__).resolve().parent.parent
"""Repository root, derived from this file so the script runs from any working directory."""

MARKDOWN_DIR: Final = ROOT / "dist" / "docs" / "markdown"
"""Where `sphinx-build -b markdown` leaves the rendered doctree."""

OUTPUT_DIR: Final = ROOT / "dist" / "docs"
"""Where both files land, alongside the PDF and the HTML archive they are released with."""

MAX_HEADING_LEVEL: Final = 6
"""Markdown's deepest heading. Demotion clamps here rather than emitting `#######`, which is
not a heading at all."""

SUMMARY_LIMIT: Final = 220
"""Longest link description in `llms.txt`, in characters. Descriptions are lifted from each
page's opening sentence, and a page occasionally opens with a long one."""

FALLBACK_SUMMARY: Final = (
    "Lightweight, framework-agnostic authorization for Python web frameworks and agent "
    "tooling, built on AWS Cedar."
)
"""Blockquote summary used when the installed distribution carries no metadata to read it
from — which happens only outside an installed environment."""


class Page(NamedTuple):
    """One page of the corpus, in the order it should be read.

    Attributes:
        name: Path of the rendered Markdown file, relative to `MARKDOWN_DIR`.
        section: The `llms.txt` H2 this page is listed under.
        must_contain: A string that has to appear in the rendered page. Present only for the
            generated API pages, where it is the check that the markdown builder really
            expanded the directives instead of copying them through.
    """

    name: str
    section: str
    must_contain: str = ""


PAGES: Final[tuple[Page, ...]] = (
    Page("index.md", "Guide"),
    Page("quickstart.md", "Guide"),
    Page("concepts.md", "Guide"),
    Page("web-frameworks.md", "Guide"),
    Page("agents.md", "Guide"),
    Page("policies.md", "Guide"),
    Page("audit.md", "Guide"),
    Page("plugins.md", "Guide"),
    Page("api/index.md", "API reference"),
    Page("api/sentrykit.md", "API reference", "sentrykit.__all__"),
    Page("api/core.md", "API reference", "sentrykit.decorator.protect"),
    Page("api/policy.md", "API reference", "sentrykit.policy.loader.PackPolicySource"),
    Page("api/stores.md", "API reference", "sentrykit.stores.jsonl.JsonlAuditSink"),
    Page("api/integrations.md", "API reference", "sentrykit.integrations.fastapi"),
)
"""The corpus, in reading order: the prose first, then the generated reference. Someone
implementing against sentrykit from `llms-full.txt` alone meets the concepts before the
signatures, and this tuple is the only place that order is decided."""

FENCE: Final = re.compile(r"^\s*(?:```|~~~)")
"""Opening or closing line of a fenced code block. Nothing inside one is rewritten: the code
in these pages is asserted against by the test suite."""

HEADING: Final = re.compile(r"^(#{1,6})(\s+.*)$")
"""An ATX heading, split into its hashes and the rest of the line."""

DOC_LINK: Final = re.compile(r"\]\((?:\.\./)?([\w./-]+)\.md(#[\w.-]+)?\)")
"""A link to another page of this corpus, with an optional fragment. In one flat file these
become fragment-only links, so nothing points at a file that is no longer separate."""

INLINE_ANCHOR: Final = re.compile(r'<a\s+id="[^"]*"\s*></a>\s*')
"""An anchor the Markdown writer can emit ahead of a heading. Invisible when rendered, pure
noise in a file meant to be read as text."""

LINK_TEXT: Final = re.compile(r"\[([^\]]+)\]\([^)]*\)")
"""A Markdown link, used to reduce one to its text when building a plain description."""

KEYWORD_ONLY_MARKER: Final = re.compile(r"\(, ")
"""A parameter list that opens with a comma — a ``*`` the Markdown writer dropped.

Unambiguous: nothing valid opens a parameter list with a comma, and every occurrence in this
corpus is in a signature heading."""

POSITIONAL_ONLY_MARKER: Final = re.compile(r",\)(\s*→)")
"""A parameter list that ends with a comma immediately before the return arrow — a ``/``.

Deliberately narrower than the rule above. A trailing ``,)`` is a one-element tuple far more
often than a dropped marker (the pack's ``PATTERNS`` default is full of them), so this matches
only where the comma *terminates the parameter list*, which a tuple literal never does."""


def slug(title: str) -> str:
    """Turn a heading into the fragment a Markdown renderer would give it.

    Args:
        title: Heading text, without the leading hashes.

    Returns:
        A lowercase, hyphen-separated fragment, without the leading `#`.
    """
    cleaned = LINK_TEXT.sub(r"\1", title).replace("`", "")
    return re.sub(r"[^a-z0-9]+", "-", cleaned.lower()).strip("-")


def read_pages() -> dict[str, str]:
    """Read every expected page, failing loudly when one is missing or unexpanded.

    A missing page is not a degraded output to be shipped with a note — it is a corpus that
    no longer answers the questions it exists to answer, and it must stop the release.

    Returns:
        Page name to file contents.

    Raises:
        SystemExit: If a page is absent, empty, or does not contain the marker that proves
            the markdown builder expanded its directives.
    """
    if not MARKDOWN_DIR.is_dir():
        sys.exit(f"build_llms_txt: {MARKDOWN_DIR} is missing; run `sphinx-build -b markdown` first")

    contents: dict[str, str] = {}
    problems: list[str] = []
    for page in PAGES:
        path = MARKDOWN_DIR / page.name
        if not path.is_file():
            problems.append(f"{page.name}: missing from the markdown build")
            continue
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            problems.append(f"{page.name}: rendered empty")
            continue
        if page.must_contain and page.must_contain not in text:
            problems.append(
                f"{page.name}: {page.must_contain!r} is absent — the API reference did not "
                f"expand, so llms-full.txt would not be implementable from"
            )
            continue
        contents[page.name] = text

    if problems:
        sys.exit("build_llms_txt: the corpus is incomplete\n  " + "\n  ".join(problems))
    return contents


def title_of(text: str) -> str:
    """Read a page's H1.

    Args:
        text: The page's full Markdown.

    Returns:
        The H1 text, or the empty string when the page has none.
    """
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return ""


def description_of(text: str) -> str:
    """Lift a one-sentence description from a page's opening paragraph.

    Taken from the page rather than written here so that a rewritten page describes itself,
    instead of drifting away from a summary nobody remembers to update.

    Args:
        text: The page's full Markdown.

    Returns:
        A single plain sentence, or the empty string when the page opens with something other
        than a paragraph.
    """
    paragraph: list[str] = []
    for line in text.splitlines()[1:]:
        stripped = line.strip()
        if not stripped:
            if paragraph:
                break
            continue
        if stripped.startswith(("#", "|", "```", "*", "-", ">")):
            if paragraph:
                break
            continue
        paragraph.append(stripped)

    if not paragraph:
        return ""

    prose = LINK_TEXT.sub(r"\1", " ".join(paragraph)).replace("`", "")
    prose = re.sub(r"\s+", " ", prose).strip()
    sentence = re.split(r"(?<=[.?!])\s", prose, maxsplit=1)[0]
    if len(sentence) > SUMMARY_LIMIT:
        sentence = sentence[:SUMMARY_LIMIT].rsplit(" ", 1)[0] + "…"
    # A sentence introducing a list or a code block ends in a colon, and the thing it
    # introduces is not coming: the description stands alone here.
    return sentence.removesuffix(":") + "." if sentence.endswith(":") else sentence


def restore_signature_markers(heading: str) -> str:
    """Put back the ``*`` and ``/`` the Markdown writer drops from a signature.

    Sphinx renders a keyword-only or positional-only marker as its own node, and the Markdown
    writer emits nothing for it — so ``protect(*, action=...)`` arrives as
    ``protect(, action=...)`` and ``protect(fn, /)`` as ``protect(fn,)``. Both are worse than
    cosmetic in this file: it is meant to be sufficient to implement against, and a signature
    that lost its marker no longer says the arguments are keyword-only, while one that kept
    the marker's orphaned comma is not valid Python at all. Eighteen of the shipped
    signatures are affected, including ``protect`` itself.

    The restored ``*`` is escaped, because the writer escapes every other literal asterisk in
    the corpus and an unescaped one in a heading that already contains ``*class*`` would pair
    with it and italicise half the signature.

    Args:
        heading: One heading line.

    Returns:
        The heading, with any dropped marker restored.
    """
    heading = KEYWORD_ONLY_MARKER.sub(r"(\\*, ", heading)
    return POSITIONAL_ONLY_MARKER.sub(r", /)\1", heading)


def clean(text: str, *, demote: int, anchors: dict[str, str]) -> str:
    """Normalise one rendered page for concatenation.

    Demotes every heading so the page sits under the corpus title, rewrites links to sibling
    pages into fragments of the flattened file, drops the writer's invisible anchors and
    collapses the blank lines it leaves behind. Fenced code is copied through untouched.

    Args:
        text: The page's Markdown, as the builder wrote it.
        demote: How many levels to push every heading down.
        anchors: Page name without its suffix, to the fragment that page's title now has.

    Returns:
        The cleaned Markdown, without a trailing newline.
    """

    def relink(match: re.Match[str]) -> str:
        target, fragment = match.group(1), match.group(2)
        if fragment:
            return f"]({fragment})"
        return f"](#{anchors.get(target, slug(target))})"

    out: list[str] = []
    in_fence = False
    for raw in text.splitlines():
        if FENCE.match(raw):
            in_fence = not in_fence
            out.append(raw.rstrip())
            continue
        if in_fence:
            out.append(raw.rstrip())
            continue

        line = INLINE_ANCHOR.sub("", raw).rstrip()
        heading = HEADING.match(line)
        if heading:
            level = min(len(heading.group(1)) + demote, MAX_HEADING_LEVEL)
            line = "#" * level + restore_signature_markers(heading.group(2))
        line = DOC_LINK.sub(relink, line)

        if not line and out and not out[-1]:
            continue
        out.append(line)

    return "\n".join(out).strip()


def build_full(contents: dict[str, str], titles: dict[str, str], version: str) -> str:
    """Assemble `llms-full.txt`.

    Args:
        contents: Page name to Markdown, from :func:`read_pages`.
        titles: Page name to H1 text.
        version: The version being documented.

    Returns:
        The complete file contents.
    """
    anchors = {page.name.removesuffix(".md"): slug(titles[page.name]) for page in PAGES}
    header = "\n".join(
        (
            f"# sentrykit {version} — complete documentation",
            "",
            f"> {summary()}",
            "",
            "Every page of the sentrykit documentation, in reading order: the guide first, then "
            "the API reference generated from the library's own docstrings. This is the whole "
            "corpus — there is nothing else to fetch.",
        )
    )
    body = (clean(contents[page.name], demote=1, anchors=anchors) for page in PAGES)
    return "\n\n".join((header, *body)) + "\n"


def summary() -> str:
    """The one-sentence project summary, read from the installed distribution.

    Returns:
        The distribution's `Summary` field, or :data:`FALLBACK_SUMMARY` when the package is
        not installed.
    """
    try:
        described = metadata.metadata("sentrykit").get("Summary")
    except metadata.PackageNotFoundError:
        return FALLBACK_SUMMARY
    return described or FALLBACK_SUMMARY


def build_index(contents: dict[str, str], titles: dict[str, str], version: str) -> str:
    """Assemble `llms.txt`.

    Args:
        contents: Page name to Markdown, from :func:`read_pages`.
        titles: Page name to H1 text.
        version: The version being documented.

    Returns:
        The complete file contents.
    """
    archive = f"sentrykit-docs-html-{version}.zip"
    lines = [
        "# sentrykit",
        "",
        f"> {summary()}",
        "",
        "sentrykit sits at the action layer: one `@protect` decorator decides, per call, "
        "whether a principal may invoke a callable, which arguments they may pass and which "
        "defaults to inject, with every decision written to a masked, hash-chained audit "
        "trail. The caller proposes; the Cedar policy decides.",
        "",
        "This project is developed in a private repository, so its documentation is published "
        "as release assets rather than on a website. Every link below names a **sibling asset "
        "of this file on the same release**: the guide and reference entries point into "
        "`llms-full.txt`, which carries the complete text; the entries under Optional name "
        f"the rendered HTML archive (`{archive}`, paths given after the archive name) and the "
        "PDF.",
    ]

    for section in dict.fromkeys(page.section for page in PAGES):
        lines.extend(("", f"## {section}", ""))
        for page in PAGES:
            if page.section != section:
                continue
            title = titles[page.name]
            fragment = slug(title)
            described = description_of(contents[page.name])
            entry = f"- [{title}](llms-full.txt#{fragment})"
            lines.append(f"{entry}: {described}" if described else entry)

    lines.extend(
        (
            "",
            "## Optional",
            "",
            f"- [Rendered HTML]({archive}/index.html): The same documentation as a browsable "
            "site, for a human reader.",
            "- [PDF](sentrykit.pdf): The same documentation as one printable file.",
            "- [Full text](llms-full.txt): Every page above concatenated, which is what the "
            "links in this file point into.",
        )
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    """Write both files and report their sizes.

    Returns:
        `0` on success. Failures exit through :func:`sys.exit` with a message instead.
    """
    contents = read_pages()
    titles = {name: title_of(text) or name for name, text in contents.items()}
    version = metadata.version("sentrykit")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    written: list[tuple[Path, int]] = []
    for filename, text in (
        ("llms.txt", build_index(contents, titles, version)),
        ("llms-full.txt", build_full(contents, titles, version)),
    ):
        path = OUTPUT_DIR / filename
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append((path, len(text.encode("utf-8"))))

    for path, size in written:
        print(f"build_llms_txt: wrote {path.relative_to(ROOT).as_posix()} ({size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
