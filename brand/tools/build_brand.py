"""Build the SecureLens AI brand assets from exact geometry.

The mark ("Concept 3", chosen by the product owner) is constructed, not drawn:

* S ribbon — two identical annular bands ("hooks") with 180° rotational
  symmetry. The upper hook sweeps from a slanted terminal at the upper right,
  over the top and down the left; the lower hook mirrors it. Together they read
  as an S — SecureLens — and as a flow path (learn → fix → verify).
* Lens — a disc at the centre of the S, separated from the ribbon by a thin
  gap, holding ``</>``: the code SecureLens looks into.

The wordmark is Manrope (SIL Open Font License 1.1) converted to outlines, so
no font is needed at runtime. The TypeScript export feeds the dashboard's
<Logo> and the 3D animated mark, so every rendering shares one geometry.

    python build_brand.py --font-dir path/to/@fontsource/manrope/files --out .. \\
        --ts-out ../../frontend/src/components/brand-paths.ts
"""

from __future__ import annotations

import argparse
import math
from dataclasses import dataclass
from pathlib import Path

NAVY = "#0B1B36"
LIGHT = "#E8EEF9"
BLUE = "#2563EB"
RING = "#5CC8FF"
GLYPH = "#E8F4FF"
# Ribbon gradients: upper hook blue, lower hook blue → violet.
UPPER = ("#4F8CFF", "#2F5BEA")
LOWER = ("#4B5BF0", "#7B5CF5")


@dataclass(frozen=True)
class MarkGeometry:
    """All numbers are in a 64 × 64 box centred on (32, 32)."""

    offset: float = 11.0  # vertical distance of each hook's centre from the middle
    inner: float = 6.8  # inner radius of a hook
    outer: float = 15.8  # outer radius of a hook
    start: float = -38.0  # angle of the upper terminal (degrees, clockwise from +x)
    sweep: float = 232.0  # how far each hook travels
    cut: float = 16.0  # slant of the terminals (degrees the outer edge overhangs)
    lens: float = 10.6  # lens radius
    gap: float = 1.7  # gap between lens and ribbon
    ring: float = 1.2  # lens ring stroke width
    glyph: float = 2.2  # stroke width of </>


def _point(cx: float, cy: float, r: float, angle: float) -> tuple[float, float]:
    t = math.radians(angle)
    return cx + r * math.cos(t), cy + r * math.sin(t)


def _fmt(p: tuple[float, float]) -> str:
    return f"{p[0]:.3f} {p[1]:.3f}"


def hook(cx: float, cy: float, g: MarkGeometry, start: float) -> str:
    """One annular band travelling counter-clockwise from ``start`` for ``g.sweep`` degrees."""
    end = start - g.sweep
    large = 1 if g.sweep > 180 else 0
    o0 = _point(cx, cy, g.outer, start + g.cut)  # the outer edge overhangs: a slanted terminal
    o1 = _point(cx, cy, g.outer, end)
    i1 = _point(cx, cy, g.inner, end)
    i0 = _point(cx, cy, g.inner, start)
    return (f"M{_fmt(o0)}A{g.outer} {g.outer} 0 {large} 0 {_fmt(o1)}"
            f"L{_fmt(i1)}A{g.inner} {g.inner} 0 {large} 1 {_fmt(i0)}Z")


def ribbon(g: MarkGeometry) -> tuple[str, str]:
    upper = hook(32, 32 - g.offset, g, g.start)
    lower = hook(32, 32 + g.offset, g, g.start + 180)
    return upper, lower


def glyph_paths(g: MarkGeometry) -> list[str]:
    """``<``, ``/`` and ``>`` inside the lens."""
    c, r = 32.0, g.lens
    h, w, bx = r * 0.34, r * 0.26, r * 0.66
    return [
        f"M{c - bx + w:.3f} {c - h:.3f}L{c - bx:.3f} {c:.3f}L{c - bx + w:.3f} {c + h:.3f}",
        f"M{c + r * 0.14:.3f} {c - r * 0.40:.3f}L{c - r * 0.14:.3f} {c + r * 0.40:.3f}",
        f"M{c + bx - w:.3f} {c - h:.3f}L{c + bx:.3f} {c:.3f}L{c + bx - w:.3f} {c + h:.3f}",
    ]


def mark_body(g: MarkGeometry, uid: str, *, flat: str | None = None, lens_fill: str = NAVY) -> str:
    """The mark's SVG body. ``flat`` paints the ribbon one colour (monochrome uses)."""
    upper, lower = ribbon(g)
    glyphs = "".join(f'<path d="{d}"/>' for d in glyph_paths(g))
    defs = (f'<defs><mask id="{uid}m"><rect width="64" height="64" fill="#fff"/>'
            f'<circle cx="32" cy="32" r="{g.lens + g.gap}" fill="#000"/></mask>')
    if flat is None:
        defs += (f'<linearGradient id="{uid}u" x1="0" y1="0" x2="1" y2="1">'
                 f'<stop offset="0" stop-color="{UPPER[0]}"/><stop offset="1" stop-color="{UPPER[1]}"/>'
                 f'</linearGradient>'
                 f'<linearGradient id="{uid}l" x1="0" y1="0" x2="1" y2="1">'
                 f'<stop offset="0" stop-color="{LOWER[0]}"/><stop offset="1" stop-color="{LOWER[1]}"/>'
                 f'</linearGradient>')
    defs += "</defs>"
    up_fill = flat or f"url(#{uid}u)"
    lo_fill = flat or f"url(#{uid}l)"
    return (defs
            + f'<g mask="url(#{uid}m)"><path d="{lower}" fill="{lo_fill}"/><path d="{upper}" fill="{up_fill}"/></g>'
            + f'<circle cx="32" cy="32" r="{g.lens}" fill="{lens_fill}"/>'
            + f'<circle cx="32" cy="32" r="{g.lens - g.ring}" fill="none" stroke="{RING}" '
              f'stroke-width="{g.ring}"/>'
            + f'<g fill="none" stroke="{GLYPH}" stroke-width="{g.glyph}" stroke-linecap="round" '
              f'stroke-linejoin="round">{glyphs}</g>')


def svg(width: float, height: float, body: str, title: str = "SecureLens AI") -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:g} {height:g}" width="{width:g}" '
            f'height="{height:g}" role="img" aria-label="{title}"><title>{title}</title>{body}</svg>\n')


def place(body: str, scale: float, dx: float, dy: float) -> str:
    return f'<g transform="translate({dx:.3f} {dy:.3f}) scale({scale:.5f})">{body}</g>'


# ------------------------------------------------------------------ wordmark

@dataclass
class Word:
    d: str
    width: float


def outline(font_path: Path, text: str, cap_height: float, tracking_em: float) -> Word:
    """Text → one SVG path, baseline at y=0, capitals ``cap_height`` tall."""
    from fontTools.pens.svgPathPen import SVGPathPen
    from fontTools.pens.transformPen import TransformPen
    from fontTools.ttLib import TTFont

    font = TTFont(str(font_path))
    glyph_set = font.getGlyphSet()
    cmap = font.getBestCmap()
    units_cap = font["OS/2"].sCapHeight or font["head"].unitsPerEm * 0.7
    scale = cap_height / units_cap
    tracking = tracking_em * font["head"].unitsPerEm
    pen = SVGPathPen(glyph_set, ntos=lambda v: f"{v:.2f}".rstrip("0").rstrip("."))
    x = 0.0
    for i, char in enumerate(text):
        name = cmap[ord(char)]
        glyph_set[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x * scale, 0)))
        x += glyph_set[name].width + (tracking if i < len(text) - 1 else 0)
    return Word(d=pen.getCommands(), width=x * scale)


def build(font_dir: Path, out: Path, ts_out: Path | None = None) -> None:
    g = MarkGeometry()
    out.mkdir(parents=True, exist_ok=True)

    (out / "securelens-mark.svg").write_text(svg(64, 64, mark_body(g, "a")), "utf-8")
    (out / "securelens-mark-flat.svg").write_text(svg(64, 64, mark_body(g, "b", flat=BLUE)), "utf-8")
    (out / "securelens-mark-mono-light.svg").write_text(
        svg(64, 64, mark_body(g, "c", flat=LIGHT, lens_fill=NAVY)), "utf-8")
    icon = f'<rect width="64" height="64" rx="14" fill="{NAVY}"/>' + place(mark_body(g, "d"), 0.9, 3.2, 3.2)
    (out / "securelens-app-icon.svg").write_text(svg(64, 64, icon), "utf-8")

    # Horizontal lockup: SECURELENS dominant, AI as a lighter descriptor after a hairline.
    cap = 24.0
    name = outline(font_dir / "manrope-latin-700-normal.woff", "SECURELENS", cap, 0.045)
    ai = outline(font_dir / "manrope-latin-500-normal.woff", "AI", cap, 0.06)
    mark_dx = -10.0  # the S is narrower than its 64 box: shift it so the ribbon starts near x=6
    text_x = 64 + mark_dx + 12.0
    rule_gap = 13.0
    baseline = 32 + cap / 2
    rule_x = text_x + name.width + rule_gap
    ai_x = rule_x + rule_gap
    width = ai_x + ai.width + 2

    def lockup(ink: str, accent: str, rule: str, uid: str) -> str:
        return (place(mark_body(g, uid), 1.0, mark_dx, 0)
                + f'<path d="{name.d}" fill="{ink}" transform="translate({text_x:.3f} {baseline:.3f})"/>'
                + f'<rect x="{rule_x:.3f}" y="{baseline - cap - 1:.3f}" width="1.6" height="{cap + 2:.3f}" '
                  f'fill="{rule}"/>'
                + f'<path d="{ai.d}" fill="{accent}" transform="translate({ai_x:.3f} {baseline:.3f})"/>')

    (out / "securelens-logo.svg").write_text(svg(width, 64, lockup(NAVY, BLUE, "#C9D3E3", "e")), "utf-8")
    (out / "securelens-logo-inverse.svg").write_text(
        svg(width, 64, lockup(LIGHT, "#6FA0FF", "#33476B", "f")), "utf-8")

    # Stacked lockup.
    s_cap = 20.0
    s_name = outline(font_dir / "manrope-latin-700-normal.woff", "SECURELENS", s_cap, 0.06)
    s_ai = outline(font_dir / "manrope-latin-500-normal.woff", "AI", s_cap * 0.8, 0.12)
    s_width = s_name.width + 8
    mark_scale = 1.6
    mark_x = (s_width - 64 * mark_scale) / 2
    name_y = 64 * mark_scale + 10 + s_cap
    ai_y = name_y + 12 + s_cap * 0.8
    s_height = ai_y + 6

    def stacked(ink: str, accent: str, uid: str) -> str:
        return (place(mark_body(g, uid), mark_scale, mark_x, 0)
                + f'<path d="{s_name.d}" fill="{ink}" '
                  f'transform="translate({(s_width - s_name.width) / 2:.3f} {name_y:.3f})"/>'
                + f'<path d="{s_ai.d}" fill="{accent}" '
                  f'transform="translate({(s_width - s_ai.width) / 2:.3f} {ai_y:.3f})"/>')

    (out / "securelens-logo-stacked.svg").write_text(svg(s_width, s_height, stacked(NAVY, BLUE, "g")), "utf-8")
    (out / "securelens-logo-stacked-inverse.svg").write_text(
        svg(s_width, s_height, stacked(LIGHT, "#6FA0FF", "h")), "utf-8")

    if ts_out is not None:
        upper, lower = ribbon(g)
        glyphs = ", ".join(f'"{d}"' for d in glyph_paths(g))
        ts_out.write_text(
            "// Generated by securelens-ai/brand/tools/build_brand.py. Do not edit by hand.\n"
            "// Geometry of the SecureLens mark and the outlined wordmark (Manrope, SIL OFL 1.1).\n\n"
            "export const MARK = {\n"
            f'  upper: "{upper}",\n  lower: "{lower}",\n'
            f"  lens: {{ cx: 32, cy: 32, r: {g.lens}, gap: {g.gap}, ring: {g.ring} }},\n"
            f"  glyphs: [{glyphs}],\n  glyph: {g.glyph},\n"
            f'  colors: {{ upper: ["{UPPER[0]}", "{UPPER[1]}"], lower: ["{LOWER[0]}", "{LOWER[1]}"], '
            f'lens: "{NAVY}", ring: "{RING}", glyph: "{GLYPH}" }},\n'
            "} as const;\n\n"
            f"export const WORDMARK = {{\n  width: {width:.3f},\n  height: 64,\n  markDx: {mark_dx},\n"
            f'  name: {{ d: "{name.d}", x: {text_x:.3f}, y: {baseline:.3f} }},\n'
            f"  rule: {{ x: {rule_x:.3f}, y: {baseline - cap - 1:.3f}, width: 1.6, height: {cap + 2:.3f} }},\n"
            f'  ai: {{ d: "{ai.d}", x: {ai_x:.3f}, y: {baseline:.3f} }},\n}} as const;\n',
            "utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--font-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--ts-out", type=Path, default=None,
                        help="also write the geometry as a TypeScript module for the dashboard")
    args = parser.parse_args()
    build(args.font_dir, args.out, args.ts_out)


if __name__ == "__main__":
    main()
