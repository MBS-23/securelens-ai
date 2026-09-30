"""Build the SecureLens AI brand assets from exact geometry.

The mark ("Concept 3", final identity) is constructed, not drawn:

* S ribbon — two identical annular bands ("hooks") with 180° rotational
  symmetry and tapered, blade-like terminals. Together they read as an S —
  SecureLens — and as the continuous Learn → Build → Analyze → Fix → Retest →
  Verify cycle. One cyan → electric blue → violet gradient runs through the
  ribbon; a radial shade darkens each band's inner edge and a thin highlight
  lights its outer edge, so the flat SVG reads as a ribbon with depth.
* Lens — a near-black disc at the centre with a cyan ring, separated from the
  ribbon by a gap, holding ``</>``: the code SecureLens analyses.

Small sizes (≤ 32 px) use the flat variant (no shade, no glow); dark versions
may add a subtle glow around the lens ring. The wordmark "SecureLens AI" and
the taglines are Manrope (SIL Open Font License 1.1) converted to outlines, so
no font is needed at runtime. The TypeScript export feeds the dashboard.

    python build_brand.py --font-dir path/to/@fontsource/manrope/files --out .. \\
        --ts-out ../../frontend/src/components/brand-paths.ts
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass
from pathlib import Path

# Palette (final identity).
CYAN = "#00D1FF"  # primary
BLUE = "#2563FF"  # secondary
VIOLET = "#8B5CF6"  # accent
NAVY = "#0B1220"  # dark navy
SLATE = "#1E293B"
MUTED = "#334155"
WHITE = "#FFFFFF"
LIGHT = "#E2E8F0"
GLYPH = "#EAFBFF"

PRIMARY_TAGLINE = ["CODE", "ANALYZE", "REMEDIATE", "VERIFY"]
SECONDARY_TAGLINE = ["SEE", "UNDERSTAND", "FIX", "SECURE"]


@dataclass(frozen=True)
class MarkGeometry:
    """All numbers are in a 64 × 64 box centred on (32, 32)."""

    offset: float = 11.2  # vertical distance of each hook's centre from the middle
    inner: float = 6.2  # inner radius of a hook
    outer: float = 16.6  # outer radius of a hook
    start: float = -34.0  # angle of the upper terminal (degrees, clockwise from +x)
    sweep: float = 238.0  # how far each hook travels
    cut: float = 24.0  # the outer edge overhangs the terminal by this many degrees…
    taper: float = 10.0  # …and the inner edge starts this much later: a blade-like tip
    lens: float = 10.4  # lens radius
    gap: float = 1.8  # gap between lens and ribbon
    ring: float = 1.1  # lens ring stroke width
    glyph: float = 2.1  # stroke width of </>


def _point(cx: float, cy: float, r: float, angle: float) -> tuple[float, float]:
    t = math.radians(angle)
    return cx + r * math.cos(t), cy + r * math.sin(t)


def _fmt(p: tuple[float, float]) -> str:
    return f"{p[0]:.3f} {p[1]:.3f}"


def hook(cx: float, cy: float, g: MarkGeometry, start: float) -> str:
    """One band travelling counter-clockwise from ``start`` for ``g.sweep`` degrees."""
    end = start - g.sweep
    large = 1 if g.sweep > 180 else 0
    o0 = _point(cx, cy, g.outer, start + g.cut)
    o1 = _point(cx, cy, g.outer, end)
    i1 = _point(cx, cy, g.inner, end)
    i0 = _point(cx, cy, g.inner, start - g.taper)
    return (f"M{_fmt(o0)}A{g.outer} {g.outer} 0 {large} 0 {_fmt(o1)}"
            f"L{_fmt(i1)}A{g.inner} {g.inner} 0 {large} 1 {_fmt(i0)}Z")


def ribbon(g: MarkGeometry) -> tuple[str, str]:
    return hook(32, 32 - g.offset, g, g.start), hook(32, 32 + g.offset, g, g.start + 180)


def glyph_paths(g: MarkGeometry) -> list[str]:
    """``<``, ``/`` and ``>`` inside the lens."""
    c, r = 32.0, g.lens
    h, w, bx = r * 0.34, r * 0.26, r * 0.64
    return [
        f"M{c - bx + w:.3f} {c - h:.3f}L{c - bx:.3f} {c:.3f}L{c - bx + w:.3f} {c + h:.3f}",
        f"M{c + r * 0.13:.3f} {c - r * 0.40:.3f}L{c - r * 0.13:.3f} {c + r * 0.40:.3f}",
        f"M{c + bx - w:.3f} {c - h:.3f}L{c + bx:.3f} {c:.3f}L{c + bx - w:.3f} {c + h:.3f}",
    ]


def shade_stops(g: MarkGeometry) -> list[tuple[float, str, float]]:
    """Radial shading across a band: dark inner edge, clear middle, thin light outer edge."""
    inner = g.inner / g.outer
    return [(inner, NAVY, 0.62), ((inner + 1) / 2, NAVY, 0.0), (0.9, WHITE, 0.0), (0.975, WHITE, 0.38),
            (1.0, WHITE, 0.05)]


def mark_body(g: MarkGeometry, uid: str, *, style: str = "color", glow: bool = False,
              mono: str | None = None) -> str:
    """SVG body of the mark. style: "color" (shaded), "flat" (small sizes) or "mono" (one colour)."""
    upper, lower = ribbon(g)
    glyphs = "".join(f'<path d="{d}"/>' for d in glyph_paths(g))
    defs = [f'<mask id="{uid}m" maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64">'
            f'<rect width="64" height="64" fill="#fff"/>'
            f'<circle cx="32" cy="32" r="{g.lens + g.gap}" fill="#000"/></mask>']
    if style != "mono":
        defs.append(f'<linearGradient id="{uid}g" gradientUnits="userSpaceOnUse" x1="48" y1="6" x2="16" y2="58">'
                    f'<stop offset="0" stop-color="{CYAN}"/><stop offset=".48" stop-color="{BLUE}"/>'
                    f'<stop offset="1" stop-color="{VIOLET}"/></linearGradient>')
    if style == "color":
        for name, cy in (("u", 32 - g.offset), ("l", 32 + g.offset)):
            stops = "".join(f'<stop offset="{o:.3f}" stop-color="{c}" stop-opacity="{a}"/>' for o, c, a in shade_stops(g))
            defs.append(f'<radialGradient id="{uid}s{name}" gradientUnits="userSpaceOnUse" cx="32" cy="{cy}" '
                        f'r="{g.outer}">{stops}</radialGradient>')
    if glow:
        defs.append(f'<filter id="{uid}f" x="-50%" y="-50%" width="200%" height="200%">'
                    f'<feGaussianBlur stdDeviation="1.6"/></filter>')
    fill = mono or f"url(#{uid}g)"
    body = f'<defs>{"".join(defs)}</defs><g mask="url(#{uid}m)"><path d="{lower}" fill="{fill}"/><path d="{upper}" fill="{fill}"/>'
    if style == "color":
        body += f'<path d="{lower}" fill="url(#{uid}sl)"/><path d="{upper}" fill="url(#{uid}su)"/>'
    body += "</g>"
    if glow:
        body += (f'<circle cx="32" cy="32" r="{g.lens - 0.9}" fill="none" stroke="{CYAN}" stroke-width="2.2" '
                 f'opacity=".55" filter="url(#{uid}f)"/>')
    if style == "mono":
        body += (f'<circle cx="32" cy="32" r="{g.lens - g.ring / 2}" fill="none" stroke="{mono}" '
                 f'stroke-width="{g.ring * 1.4}"/>'
                 f'<g fill="none" stroke="{mono}" stroke-width="{g.glyph}" stroke-linecap="round" '
                 f'stroke-linejoin="round">{glyphs}</g>')
    else:
        body += (f'<circle cx="32" cy="32" r="{g.lens}" fill="{NAVY}"/>'
                 f'<circle cx="32" cy="32" r="{g.lens - g.ring}" fill="none" stroke="{CYAN}" stroke-width="{g.ring}"/>'
                 f'<g fill="none" stroke="{GLYPH}" stroke-width="{g.glyph}" stroke-linecap="round" '
                 f'stroke-linejoin="round">{glyphs}</g>')
    return body


def svg(width: float, height: float, body: str, title: str = "SecureLens AI") -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:g} {height:g}" width="{width:g}" '
            f'height="{height:g}" role="img" aria-label="{title}"><title>{title}</title>{body}</svg>\n')


def place(body: str, scale: float, dx: float, dy: float) -> str:
    return f'<g transform="translate({dx:.3f} {dy:.3f}) scale({scale:.5f})">{body}</g>'


# ------------------------------------------------------------------ type

@dataclass
class Word:
    d: str
    width: float


class Typesetter:
    """Manrope → SVG outlines (baseline y=0, capitals ``cap`` tall)."""

    def __init__(self, font_dir: Path):
        from fontTools.ttLib import TTFont

        self._fonts = {w: TTFont(str(font_dir / f"manrope-latin-{w}-normal.woff")) for w in (500, 600, 700, 800)}

    def outline(self, text: str, cap: float, weight: int = 700, tracking_em: float = 0.0) -> Word:
        from fontTools.pens.svgPathPen import SVGPathPen
        from fontTools.pens.transformPen import TransformPen

        font = self._fonts[weight]
        glyph_set = font.getGlyphSet()
        cmap = font.getBestCmap()
        units_cap = font["OS/2"].sCapHeight or font["head"].unitsPerEm * 0.7
        scale = cap / units_cap
        tracking = tracking_em * font["head"].unitsPerEm
        pen = SVGPathPen(glyph_set, ntos=lambda v: f"{v:.2f}".rstrip("0").rstrip("."))
        x = 0.0
        for i, char in enumerate(text):
            name = cmap[ord(char)]
            glyph_set[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x * scale, 0)))
            x += glyph_set[name].width + (tracking if i < len(text) - 1 else 0)
        return Word(d=pen.getCommands(), width=x * scale)

    def tagline(self, words: list[str], cap: float, gap: float) -> tuple[str, float, list[float]]:
        """Words set in tracked capitals, separated by thin bars; returns (path, width, bar x positions)."""
        parts, bars, x = [], [], 0.0
        for i, word in enumerate(words):
            w = self.outline(word, cap, 600, 0.28)
            parts.append(f'<path d="{w.d}" transform="translate({x:.3f} 0)"/>')
            x += w.width
            if i < len(words) - 1:
                bars.append(x + gap)
                x += 2 * gap
        return "".join(parts), x, bars


# ------------------------------------------------------------------ assets

@dataclass
class Lockup:
    width: float
    height: float
    body: str


def horizontal(g: MarkGeometry, ts: Typesetter, uid: str, *, dark: bool, mono: str | None = None,
               tagline: bool = True) -> Lockup:
    """Mark left; 'SecureLens AI' and the primary tagline right."""
    cap = 26.0
    name = ts.outline("SecureLens", cap, 800, -0.01)
    ai = ts.outline("AI", cap, 800, 0.0)
    ink = mono or (WHITE if dark else NAVY)
    ai_fill = mono or f"url(#{uid}t)"
    text_x = 70.0
    base = 34.0 if tagline else 32 + cap / 2
    ai_x = text_x + name.width + cap * 0.32
    width = ai_x + ai.width + 4
    defs = (f'<defs><linearGradient id="{uid}t" x1="0" y1="0" x2="1" y2="0">'
            f'<stop offset="0" stop-color="{CYAN}"/><stop offset="1" stop-color="{BLUE}"/></linearGradient></defs>')
    style = "mono" if mono else "color"
    body = defs + place(mark_body(g, uid, style=style, glow=dark and not mono, mono=mono), 1.0, -2, 0)
    body += (f'<path d="{name.d}" fill="{ink}" transform="translate({text_x:.3f} {base:.3f})"/>'
             f'<path d="{ai.d}" fill="{ai_fill}" transform="translate({ai_x:.3f} {base:.3f})"/>')
    if tagline:
        t_cap = 6.4
        path, t_width, bars = ts.tagline(PRIMARY_TAGLINE, t_cap, 7.0)
        scale = min(1.0, (width - text_x - 4) / t_width)
        muted = mono or ("#9FB0C8" if dark else "#475569")
        bar_fill = mono or ("#334155" if dark else "#CBD5E1")
        body += f'<g fill="{muted}" transform="translate({text_x + 1:.3f} {base + 17:.3f}) scale({scale:.4f})">{path}'
        body += "".join(f'<rect x="{b - 0.5:.3f}" y="{-t_cap - 1:.3f}" width="1" height="{t_cap + 2:.3f}" '
                        f'fill="{bar_fill}"/>' for b in bars)
        body += "</g>"
    return Lockup(width, 64, body)


def stacked(g: MarkGeometry, ts: Typesetter, uid: str, *, dark: bool, mono: str | None = None) -> Lockup:
    """Mark on top, wordmark, tagline — for square and hero placements."""
    cap = 30.0
    name = ts.outline("SecureLens", cap, 800, -0.01)
    ai = ts.outline("AI", cap, 800, 0.0)
    t_cap = 7.0
    path, t_width, bars = ts.tagline(PRIMARY_TAGLINE, t_cap, 8.0)
    word_w = name.width + cap * 0.32 + ai.width
    width = max(word_w, t_width) + 24
    mark_size = 112.0
    ink = mono or (WHITE if dark else NAVY)
    muted = mono or ("#9FB0C8" if dark else "#475569")
    bar_fill = mono or ("#334155" if dark else "#CBD5E1")
    style = "mono" if mono else "color"
    defs = (f'<defs><linearGradient id="{uid}t" x1="0" y1="0" x2="1" y2="0">'
            f'<stop offset="0" stop-color="{CYAN}"/><stop offset="1" stop-color="{BLUE}"/></linearGradient></defs>')
    body = defs + place(mark_body(g, uid, style=style, glow=dark and not mono, mono=mono), mark_size / 64,
                        (width - mark_size) / 2, 0)
    base = mark_size + 16 + cap
    x0 = (width - word_w) / 2
    body += (f'<path d="{name.d}" fill="{ink}" transform="translate({x0:.3f} {base:.3f})"/>'
             f'<path d="{ai.d}" fill="{mono or f"url(#{uid}t)"}" '
             f'transform="translate({x0 + name.width + cap * 0.32:.3f} {base:.3f})"/>')
    t_base = base + 26
    body += f'<g fill="{muted}" transform="translate({(width - t_width) / 2:.3f} {t_base:.3f})">{path}'
    body += "".join(f'<rect x="{b - 0.5:.3f}" y="{-t_cap - 1:.3f}" width="1" height="{t_cap + 2:.3f}" fill="{bar_fill}"/>'
                    for b in bars)
    body += "</g>"
    return Lockup(width, t_base + 10, body)


def app_icon(g: MarkGeometry, uid: str, *, small: bool = False) -> str:
    """Rounded navy tile; small sizes use the flat mark, larger and with less padding."""
    glow = "" if small else (f'<defs><radialGradient id="{uid}bg" cx="50%" cy="42%" r="60%">'
                             f'<stop offset="0" stop-color="{BLUE}" stop-opacity=".28"/>'
                             f'<stop offset="1" stop-color="{BLUE}" stop-opacity="0"/></radialGradient></defs>')
    tile = f'<rect width="64" height="64" rx="14" fill="{NAVY}"/>'
    if not small:
        tile += f'<rect width="64" height="64" rx="14" fill="url(#{uid}bg)"/>'
    scale, pad = (1.0, 0.0) if small else (0.88, 3.84)
    return glow + tile + place(mark_body(g, uid, style="flat" if small else "color", glow=not small), scale, pad, pad)


def build(font_dir: Path, out: Path, ts_out: Path | None = None) -> None:
    g = MarkGeometry()
    ts = Typesetter(font_dir)
    out.mkdir(parents=True, exist_ok=True)
    for stale in ("securelens-mark-mono-light.svg",):
        (out / stale).unlink(missing_ok=True)

    files = {
        "securelens-mark.svg": svg(64, 64, mark_body(g, "a", style="color")),
        "securelens-mark-dark.svg": svg(64, 64, mark_body(g, "b", style="color", glow=True)),
        "securelens-mark-flat.svg": svg(64, 64, mark_body(g, "c", style="flat")),
        "securelens-mark-mono-white.svg": svg(64, 64, mark_body(g, "d", style="mono", mono=WHITE)),
        "securelens-mark-mono-navy.svg": svg(64, 64, mark_body(g, "e", style="mono", mono=NAVY)),
        "securelens-app-icon.svg": svg(64, 64, app_icon(g, "f")),
        "securelens-favicon.svg": svg(64, 64, app_icon(g, "h", small=True)),
    }
    for name, (dark, mono, uid) in {
        "securelens-logo-dark.svg": (True, None, "i"),
        "securelens-logo-light.svg": (False, None, "j"),
        "securelens-logo-mono-white.svg": (True, WHITE, "k"),
        "securelens-logo-mono-navy.svg": (False, NAVY, "l"),
    }.items():
        lk = horizontal(g, ts, uid, dark=dark, mono=mono)
        files[name] = svg(lk.width, lk.height, lk.body)
    for name, (dark, mono, uid) in {
        "securelens-logo-stacked-dark.svg": (True, None, "m"),
        "securelens-logo-stacked-light.svg": (False, None, "n"),
    }.items():
        lk = stacked(g, ts, uid, dark=dark, mono=mono)
        files[name] = svg(lk.width, lk.height, lk.body)
    for old in ("securelens-logo.svg", "securelens-logo-inverse.svg", "securelens-logo-stacked.svg",
                "securelens-logo-stacked-inverse.svg"):
        (out / old).unlink(missing_ok=True)
    for name, content in files.items():
        (out / name).write_text(content, "utf-8")

    if ts_out is not None:
        upper, lower = ribbon(g)
        glyphs = ", ".join(f'"{d}"' for d in glyph_paths(g))
        cap = 26.0
        name = ts.outline("SecureLens", cap, 800, -0.01)
        ai = ts.outline("AI", cap, 800, 0.0)
        text_x = 70.0
        base = 32 + cap / 2
        ai_x = text_x + name.width + cap * 0.32
        stops = ", ".join(f'[{o:.3f}, "{c}", {a}]' for o, c, a in shade_stops(g))
        ts_out.write_text(
            "// Generated by securelens-ai/brand/tools/build_brand.py. Do not edit by hand.\n"
            "// Geometry of the SecureLens mark and the outlined wordmark (Manrope, SIL OFL 1.1).\n\n"
            "export const BRAND = {\n"
            f'  cyan: "{CYAN}",\n  blue: "{BLUE}",\n  violet: "{VIOLET}",\n  navy: "{NAVY}",\n'
            f'  glyph: "{GLYPH}",\n'
            f"  taglines: {{ primary: {json.dumps(PRIMARY_TAGLINE)}, secondary: {json.dumps(SECONDARY_TAGLINE)} }},\n"
            "} as const;\n\n"
            "export const MARK = {\n"
            f'  upper: "{upper}",\n  lower: "{lower}",\n'
            f"  hookCenters: {{ upper: {32 - g.offset}, lower: {32 + g.offset} }},\n"
            f"  outer: {g.outer},\n  shade: [{stops}],\n"
            f"  lens: {{ cx: 32, cy: 32, r: {g.lens}, gap: {g.gap}, ring: {g.ring} }},\n"
            f"  glyphs: [{glyphs}],\n  glyph: {g.glyph},\n"
            "} as const;\n\n"
            f"export const WORDMARK = {{\n  width: {ai_x + ai.width + 4:.3f},\n  height: 64,\n  markDx: -2,\n"
            f'  name: {{ d: "{name.d}", x: {text_x}, y: {base} }},\n'
            f'  ai: {{ d: "{ai.d}", x: {ai_x:.3f}, y: {base} }},\n}} as const;\n',
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
