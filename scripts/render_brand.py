"""Render the brand cards in `brand/` to PNG, baking their text into outlines on the way.

Run it with `pixi run -e art brand`. The `art` environment exists because this is the only
thing in the repository that needs a cairo stack and a typeface, and nothing in CI runs it:
the outputs are chosen by eye, which is not a thing a gate can do.

**Text becomes `<path>` data before anything is rasterised.** A text element renders in
whatever font the rasteriser happens to find, so a PNG built from one is a property of the
machine that built it rather than of the file — and these files are served to every crawler
that reads the documentation site. So a card declares its text:

    <g class="sk-text" data-text="sentry|kit" data-fills="#1e293b #4f46e5"
       data-font="Ubuntu-B" data-size="112" data-at="485 262"/>

and this script fills that group with one path per glyph, taken from the font's own outlines,
then writes the result back into the source file. The committed SVG therefore holds real
paths, opens standalone in a browser, and still records what it was generated from — so
changing a line of copy means editing `data-text` and running the task again. The font is
pinned by `pixi.lock`, so the outlines are identical wherever that lock is used, and no
system font is ever consulted.

Four checks run before anything is rasterised, each because the alternative is a file that
looks fine and is not:

* **Every colour appears in `brand/palette.toml`.** An SVG cannot read a config file, so the
  hexes are restated inline. Restating is forced; drifting is not. It is the same bargain
  `tests/unit/test_release_version.py` makes for the version, for the same reason.
* **No file contains a text element**, for the reason above. Forbidding the element is what
  stops the decision being quietly undone by someone who just needs a tagline.
* **The canvas is exactly 1280x640** — GitHub's social-preview size and a good enough Open
  Graph size, so one file serves both. A viewBox disagreeing with the width and height still
  renders, scaled, and silently.
* **No bare `--` inside a comment**, which XML forbids. The repository's usual ASCII stand-in
  for an em dash is illegal in these files, and the parser's own message for it is a column
  number, which says where it gave up rather than what is wrong.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from functools import lru_cache
from pathlib import Path

import cairosvg
from defusedxml.ElementTree import ParseError, fromstring
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont
from PIL import Image, ImageDraw, ImageFont

REPO_ROOT = Path(__file__).resolve().parents[1]
BRAND_DIR = REPO_ROOT / "brand"
PALETTE_FILE = BRAND_DIR / "palette.toml"
OUTPUT_DIR = REPO_ROOT / "dist" / "brand"
OG_TARGET = REPO_ROOT / "docs" / "_static" / "og-image.png"

WIDTH, HEIGHT = 1280, 640

#: The card published as the site's Open Graph image, and the one to upload as the repository's
#: social preview. One line, so that the choice lives in one place rather than in a flag.
OG_VARIANT = "card-light"

#: Anything that would make a render depend on installed fonts.
FORBIDDEN = ("<text", "<tspan", "font-family", "font-size", "@font-face", "textPath")

_HEX = re.compile(r"#[0-9a-fA-F]{3,8}\b")
#: Comments are stripped before the font scan and not before the colour scan. A text element
#: inside a comment renders nothing, so forbidding it there only forbids explaining why it is
#: forbidden. A *colour* in a comment is usually one somebody commented out and will uncomment.
_COMMENT = re.compile(r"<!--.*?-->", re.S)
#: A declared text run, with or without the glyphs a previous run of this script put into it.
_RUN = re.compile(r'<g class="sk-text"([^>]*?)(?:/>|>.*?</g>)', re.S)
_ATTR = re.compile(r'([a-zA-Z-]+)="([^"]*)"')


@lru_cache(maxsize=8)
def font_file(stem: str) -> Path:
    """Locate a font inside this environment, never on the system."""
    root = Path(sys.prefix)
    for candidate in sorted(root.rglob(f"{stem}.ttf")):
        return candidate
    sys.exit(f"no font {stem}.ttf under {root}; is the `art` environment installed?")


@lru_cache(maxsize=8)
def _font(stem: str) -> tuple[TTFont, int, dict[int, str], dict[tuple[str, str], int]]:
    """The font, its em size, its character map, and whatever kerning it declares."""
    font = TTFont(str(font_file(stem)))
    pairs: dict[tuple[str, str], int] = {}
    if "kern" in font:
        for table in font["kern"].kernTables:
            pairs.update(table.kernTable)
    return font, font["head"].unitsPerEm, font.getBestCmap(), pairs


def glyph_runs(string: str, stem: str, tracking: float) -> tuple[list[tuple[float, str]], float]:
    """One path per glyph, in font units, plus the advance the string consumed.

    Kerning comes from the font's own `kern` table where it has one. `tracking` is in
    thousandths of an em, the usual unit for letterspacing, so one value reads the same at
    every size.
    """
    font, upem, cmap, pairs = _font(stem)
    glyphs = font.getGlyphSet()
    out: list[tuple[float, str]] = []
    pen_x = 0.0
    previous: str | None = None
    for character in string:
        name = cmap.get(ord(character))
        if name is None:
            sys.exit(f"{stem} has no glyph for {character!r} (U+{ord(character):04X})")
        if previous is not None:
            pen_x += pairs.get((previous, name), 0)
        pen = SVGPathPen(glyphs)
        glyphs[name].draw(pen)
        commands = pen.getCommands()
        if commands:
            out.append((pen_x, commands))
        pen_x += glyphs[name].width + tracking * upem / 1000
        previous = name
    return out, pen_x


def render_run(attributes: dict[str, str]) -> str:
    """Rebuild one declared text run as positioned outlines.

    The group keeps its `data-` attributes, so the file still says what it was generated from
    and running the task again regenerates the same thing.
    """
    segments = attributes["data-text"].split("|")
    fills = attributes["data-fills"].split()
    if len(fills) != len(segments):
        sys.exit(f"data-text has {len(segments)} segment(s) but data-fills has {len(fills)}")

    stem = attributes["data-font"]
    size = float(attributes["data-size"])
    tracking = float(attributes.get("data-tracking", "0"))
    at_x, at_y = (float(value) for value in attributes["data-at"].split())
    _, upem, _, _ = _font(stem)
    scale = size / upem

    # One flat list of paths, each carrying its own fill, and no nested group. Deliberate:
    # `_RUN` ends at the first closing tag it meets, so a nested group would make the second
    # bake of an already-baked file produce unparseable XML. Flattening removes the nesting
    # instead of making the pattern cleverer, which is the fix that cannot come apart later.
    body: list[str] = []
    cursor = 0.0
    for segment, fill in zip(segments, fills, strict=True):
        runs, advance = glyph_runs(segment, stem, tracking)
        body.extend(
            f'<path fill="{fill}" transform="translate({cursor + x:.0f} 0)" d="{d}"/>'
            for x, d in runs
        )
        cursor += advance

    declared = " ".join(
        f'{key}="{value}"' for key, value in attributes.items() if key.startswith("data-")
    )
    transform = f"translate({at_x:g} {at_y:g}) scale({scale:.6f} -{scale:.6f})"
    # `data-opacity` is how a run is muted without introducing a colour the palette does not
    # list: a seventh grey for one line of small print is a seventh grey to keep in step.
    faded = attributes.get("data-opacity")
    opacity = f' opacity="{faded}"' if faded else ""
    return f'<g class="sk-text" {declared} transform="{transform}"{opacity}>{"".join(body)}</g>'


def bake(text: str) -> tuple[str, int]:
    """Replace every declared text run in a file with its outlines."""
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return render_run(dict(_ATTR.findall(match.group(1))))

    return _RUN.sub(replace, text), count


def load_palette() -> tuple[set[str], list[str]]:
    """Return every colour the brand may use, and the six that carry meaning."""
    if not PALETTE_FILE.is_file():
        sys.exit(f"{PALETTE_FILE} is missing; it is the palette's only definition")
    data = tomllib.loads(PALETTE_FILE.read_text(encoding="utf-8"))

    brand: list[str] = []
    for role in ("structure", "allowed", "refused"):
        entry = data.get("role", {}).get(role)
        if not entry:
            sys.exit(f"{PALETTE_FILE} declares no [role.{role}]")
        for surface in ("light", "dark"):
            if surface not in entry:
                sys.exit(f"{PALETTE_FILE}: [role.{role}] has no {surface} value")
            brand.append(entry[surface].lower())

    allowed = set(brand)
    for surface, entry in data.get("neutral", {}).items():
        for key, value in entry.items():
            if not isinstance(value, str):
                sys.exit(f"{PALETTE_FILE}: [neutral.{surface}].{key} is not a colour")
            allowed.add(value.lower())
    return allowed, brand


def check(text: str, allowed: set[str]) -> list[str]:
    """Every reason this file must not be rendered."""
    problems: list[str] = []

    renderable = _COMMENT.sub("", text)
    for token in FORBIDDEN:
        if token in renderable:
            problems.append(
                f"contains {token!r}; text makes the PNG depend on the renderer's fonts, so "
                f"these files carry baked outlines instead"
            )

    for attribute, expected in (("width", str(WIDTH)), ("height", str(HEIGHT))):
        if f'{attribute}="{expected}"' not in text:
            problems.append(f'has no {attribute}="{expected}"; the canvas must be exact')
    if f'viewBox="0 0 {WIDTH} {HEIGHT}"' not in text:
        problems.append(f'viewBox is not "0 0 {WIDTH} {HEIGHT}"')

    used = {match.group(0).lower() for match in _HEX.finditer(text)}
    for colour in sorted(used - allowed):
        problems.append(f"uses {colour}, which {PALETTE_FILE.name} does not list")

    for number, line in enumerate(text.splitlines(), 1):
        if "--" in line.replace("<!--", "").replace("-->", ""):
            problems.append(
                f"line {number} has a bare `--`, which XML forbids inside a comment; "
                f"write an em dash instead"
            )

    try:
        fromstring(text)
    except ParseError as error:
        problems.append(f"is not well-formed XML: {error}")

    return problems


def contact_sheet(panels: list[tuple[str, Path]], surface: str, ink: str) -> Image.Image:
    """Lay the rendered cards out in a grid, labelled, for comparing side by side.

    The one place a font is allowed, because the sheet is a working aid and not a deliverable:
    the labels use the font bundled inside Pillow, so they depend on nothing installed either.
    """
    columns, pad, label = 2, 28, 44
    panel_w, panel_h = 600, 300
    rows = (len(panels) + columns - 1) // columns

    sheet = Image.new(
        "RGB",
        (pad * (columns + 1) + panel_w * columns, pad * (rows + 1) + (panel_h + label) * rows),
        surface,
    )
    draw = ImageDraw.Draw(sheet)
    try:
        font = ImageFont.load_default(size=22)
    except TypeError:  # Pillow older than 10.1 has no sized default
        font = ImageFont.load_default()

    for index, (name, png) in enumerate(panels):
        column, row = index % columns, index // columns
        x = pad + column * (panel_w + pad)
        y = pad + row * (panel_h + label + pad)
        draw.text((x, y), f"{index + 1}   {name}", fill=ink, font=font)
        with Image.open(png) as rendered:
            scaled = rendered.convert("RGB").resize((panel_w, panel_h), Image.LANCZOS)
            sheet.paste(scaled, (x, y + label))
        draw.rectangle((x, y + label, x + panel_w - 1, y + label + panel_h - 1), outline=ink)

    return sheet


def main() -> int:
    """Bake, check, render, and lay out. Returns 0, or exits with a message."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-og", action="store_true", help=f"skip refreshing {OG_TARGET.name}")
    arguments = parser.parse_args()

    allowed, brand = load_palette()
    print(f"palette: {len(brand)} brand colours, {len(allowed)} allowed in total")

    sources = sorted(BRAND_DIR.glob("*.svg"))
    if not sources:
        sys.exit(f"no SVG files in {BRAND_DIR}")

    texts: dict[Path, str] = {}
    for source in sources:
        original = source.read_text(encoding="utf-8")
        baked, runs = bake(original)
        # Baking what was just baked must change nothing. Asserted rather than assumed: the
        # pattern that finds a declared run again used to stop at the first closing tag it
        # met, so a second bake quietly produced unparseable XML. That is the kind of failure
        # that only shows up on the edit after the one that caused it.
        rebaked, _ = bake(baked)
        if rebaked != baked:
            sys.exit(f"{source.name}: baking is not idempotent; the run pattern is wrong")
        if baked != original:
            source.write_text(baked, encoding="utf-8")
        texts[source] = baked
        print(f"  {source.stem:14s} {runs} text run(s) baked to outlines")

    failures = [
        f"{source.name}: {problem}"
        for source in sources
        for problem in check(texts[source], allowed)
    ]
    if failures:
        sys.exit("\n".join(["refusing to render:", *(f"  {line}" for line in failures)]))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    panels: list[tuple[str, Path]] = []
    for source in sources:
        png = OUTPUT_DIR / f"{source.stem}.png"
        cairosvg.svg2png(
            bytestring=texts[source].encode("utf-8"),
            write_to=str(png),
            output_width=WIDTH,
            output_height=HEIGHT,
        )
        panels.append((source.stem, png))
        size = png.stat().st_size
        print(f"  {source.stem:14s} -> {png.relative_to(REPO_ROOT)}  {size:,} bytes")

    data = tomllib.loads(PALETTE_FILE.read_text(encoding="utf-8"))
    light = data["neutral"]["light"]
    sheet_path = OUTPUT_DIR / "contact-sheet.png"
    contact_sheet(panels, light["surface"], light["ink"]).save(sheet_path)
    sheet_size = sheet_path.stat().st_size
    print(f"  contact sheet  -> {sheet_path.relative_to(REPO_ROOT)}  {sheet_size:,} bytes")

    if not arguments.no_og:
        chosen = OUTPUT_DIR / f"{OG_VARIANT}.png"
        if not chosen.is_file():
            sys.exit(f"OG_VARIANT is {OG_VARIANT!r}, which rendered nothing")
        OG_TARGET.write_bytes(chosen.read_bytes())
        print(f"  og:image       -> {OG_TARGET.relative_to(REPO_ROOT)}  (from {OG_VARIANT})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
