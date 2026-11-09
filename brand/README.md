# brand

The social-preview cards, hand-authored as SVG, and the palette they all draw from.

```bash
pixi run -e art brand
```

That bakes each card's text into outlines, validates every file, rasterises each to
`dist/brand/<name>.png` at 1280×640, writes `dist/brand/contact-sheet.png` for comparing them,
and refreshes `docs/_static/og-image.png` from whichever card `OG_VARIANT` in
`scripts/render_brand.py` names. `dist/` is gitignored, so the PNGs are rebuilt rather than
committed — except the Open Graph image, which a crawler has to fetch from a fixed URL.

`art` is a dev-only pixi environment holding python, `cairosvg`, `fonttools` and the Ubuntu
typeface, and nothing else. It is deliberately not part of `dev`, which sixteen environments
carry: twelve of them are the CI matrix, and not one of them draws a logo.

## Text is declared, not set

A card writes its copy like this:

```xml
<g class="sk-text" data-text="sentry|kit" data-fills="#1e293b #4f46e5"
   data-font="Ubuntu-B" data-size="112" data-at="485 262"/>
```

and the task fills that group with one `<path>` per glyph, taken from the font's own outlines,
writing the result back into the file. So the committed SVG holds real paths, opens standalone
in a browser, and still records what it was generated from. To change a line, edit its
`data-text` and run the task again — baking an already-baked file is idempotent and produces
the same bytes.

The point is that **nothing reads a system font at render time**. A `<text>` element renders in
whatever font the rasteriser happens to find, which would make the published PNG a property of
the machine that built it. The font here is pinned by `pixi.lock`, so the outlines are the same
wherever that lock is used.

`data-text` splits on `|` into segments, one per entry in `data-fills`, which is how the
wordmark is two-tone. `data-tracking` is letterspacing in thousandths of an em; `data-opacity`
mutes a run without introducing a seventh grey the palette would then have to carry. Kerning
comes from the font's own `kern` table.

## What the renderer refuses

It refuses rather than rendering something wrong, because each of these produces a file that
looks fine and is not:

- **A colour that `palette.toml` does not list.** An SVG cannot read a config file, so the
  hexes are restated inline. Restating is forced; drifting is not.
- **A text element anywhere.** Forbidding it is what stops the decision above being quietly
  undone by someone who just needs a tagline.
- **A canvas that is not exactly 1280×640.** GitHub's social-preview size, and a good enough
  Open Graph size, so one file serves both. A viewBox disagreeing with width and height still
  renders, scaled, and silently.
- **A bare `--` inside a comment**, which XML forbids. The repository's usual ASCII stand-in for
  an em dash is illegal in these files; the check names it, because the parser's own message is
  a column number.

## The cards

| file | what it is |
| --- | --- |
| `card-light` | The default, and what `og-image.png` is built from. Dark tile on a light surface, with the refill mark: two values pass the gate, a third stops short, and a replacement leaves the gate level with the other two. |
| `card-dark` | The same inverted — every colour swapped to its counterpart, including inside the tile, which now carries the light triad. |
| `card-light-gate` | The light card with the simpler mark: the gate and the refusal, without the replacement. Four strokes rather than six, which matters at favicon size and costs the half of the sentence that says the call carries on. |

Both triads are in use on every card, because the tile's surface is the opposite of the page's.
That is what the two triads in `palette.toml` are for, and why there is not one theme-aware file
instead.
