"""Build the SecureLens AI brand board (brand/board/index.html).

Every logo on the board is generated from the same geometry as the shipped
assets (build_brand.py). UI examples are real screenshots of the product
(brand/board/ui/), and the terminal panel shows real CLI output. Compositions
for things that do not exist yet (the public website header, the CI check and
the README badge) are labelled as design specifications.

    python build_board.py --font-dir path/to/@fontsource/manrope/files
Render it to PNG with tools/export_board.mjs.
"""

from __future__ import annotations

import argparse
import html
import itertools
from pathlib import Path

from build_brand import (
    BLUE,
    CYAN,
    LIGHT,
    MUTED,
    NAVY,
    PRIMARY_TAGLINE,
    SECONDARY_TAGLINE,
    SLATE,
    VIOLET,
    WHITE,
    MarkGeometry,
    Typesetter,
    app_icon,
    horizontal,
    mark_body,
    stacked,
)

_ids = itertools.count(1)
G = MarkGeometry()


def uid() -> str:
    return f"b{next(_ids)}"


def inline(body: str, w: float, h: float, css: str = "", label: str | None = "SecureLens AI") -> str:
    aria = f'role="img" aria-label="{label}"' if label else 'aria-hidden="true"'
    return f'<svg viewBox="0 0 {w:g} {h:g}" style="{css}" {aria}>{body}</svg>'


def mark(style: str = "color", glow: bool = False, mono: str | None = None, css: str = "") -> str:
    return inline(mark_body(G, uid(), style=style, glow=glow, mono=mono), 64, 64, css)


def lockup(kind: str, ts: Typesetter, css: str, **kw) -> str:
    fn = horizontal if kind == "h" else stacked
    lk = fn(G, ts, uid(), **kw)
    return inline(lk.body, lk.width, lk.height, css)


def icon(css: str, small: bool = False) -> str:
    return inline(app_icon(G, uid(), small=small), 64, 64, css)


def tagline(words: list[str]) -> str:
    return ' <span class="bar">|</span> '.join(words)


def construction() -> str:
    """The mark with its construction geometry drawn over it."""
    u, lo = 32 - G.offset, 32 + G.offset
    guide = 'fill="none" stroke="#00D1FF" stroke-width=".22" stroke-dasharray="1 .8" opacity=".75"'
    body = f'<g opacity=".5">{mark_body(G, uid(), style="flat")}</g>'
    body += (f'<line x1="0" y1="32" x2="64" y2="32" stroke="#334155" stroke-width=".15"/>'
             f'<line x1="32" y1="0" x2="32" y2="64" stroke="#334155" stroke-width=".15"/>')
    for cy in (u, lo):
        body += (f'<circle cx="32" cy="{cy}" r="{G.outer}" {guide}/><circle cx="32" cy="{cy}" r="{G.inner}" {guide}/>'
                 f'<circle cx="32" cy="{cy}" r=".6" fill="#00D1FF"/>')
    body += (f'<circle cx="32" cy="32" r="{G.lens}" fill="none" stroke="#8B5CF6" stroke-width=".25"/>'
             f'<circle cx="32" cy="32" r="{G.lens + G.gap}" fill="none" stroke="#8B5CF6" stroke-width=".2" '
             f'stroke-dasharray=".8 .6"/>')
    return inline(body, 64, 64, "width:100%;height:100%", label="Construction of the SecureLens mark")


FONTS = """
@font-face { font-family: Manrope; font-weight: 600; src: url(fonts/manrope-latin-600-normal.woff2) format("woff2"); }
@font-face { font-family: Manrope; font-weight: 700; src: url(fonts/manrope-latin-700-normal.woff2) format("woff2"); }
@font-face { font-family: Manrope; font-weight: 800; src: url(fonts/manrope-latin-800-normal.woff2) format("woff2"); }
@font-face { font-family: Inter; font-weight: 100 900; src: url(fonts/inter-latin-wght-normal.woff2) format("woff2"); }
@font-face { font-family: "JetBrains Mono"; font-weight: 400; src: url(fonts/jetbrains-mono-latin-400-normal.woff2) format("woff2"); }
@font-face { font-family: "JetBrains Mono"; font-weight: 500; src: url(fonts/jetbrains-mono-latin-500-normal.woff2) format("woff2"); }
"""

CSS = """
* { box-sizing: border-box; }
body { margin: 0; background: #060A13; color: #E2E8F0; font: 14px/1.5 Inter, system-ui, sans-serif; }
.board { width: 1600px; margin: 0 auto; padding: 36px; display: grid; gap: 18px; }
.panel { background: #0B1220; border: 1px solid #1E293B; border-radius: 10px; padding: 26px; position: relative; overflow: hidden; }
.label { font: 700 12px/1 Manrope, sans-serif; letter-spacing: .22em; text-transform: uppercase; color: #7DD3FC; margin: 0 0 18px; }
.label small { color: #64748B; letter-spacing: .12em; margin-left: 10px; font-weight: 600; }
.grid { display: grid; gap: 18px; }
.cols-2 { grid-template-columns: 1fr 1fr; } .cols-3 { grid-template-columns: repeat(3, 1fr); }
.cols-4 { grid-template-columns: repeat(4, 1fr); } .cols-5-7 { grid-template-columns: 5fr 7fr; } .cols-7-5 { grid-template-columns: 7fr 5fr; }
.tile { border-radius: 8px; border: 1px solid #1E293B; padding: 22px; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; min-height: 200px; }
.tile .cap { font: 600 12px Inter, sans-serif; color: #94A3B8; }
.tile.light { background: #fff; border-color: #E2E8F0; } .tile.light .cap { color: #475569; }
.tile.navy { background: #0B1220; } .tile.slate { background: #111A2C; }
.hero { display: grid; grid-template-columns: 1.15fr 1fr; align-items: center; min-height: 460px;
  background: radial-gradient(ellipse at 28% 46%, rgba(37,99,255,.22), transparent 55%), radial-gradient(ellipse at 34% 60%, rgba(139,92,246,.14), transparent 50%), #0B1220; }
.hero h1 { font: 800 15px/1 Manrope, sans-serif; letter-spacing: .3em; text-transform: uppercase; color: #7DD3FC; margin: 0 0 22px; }
.hero p { color: #94A3B8; max-width: 520px; font-size: 16px; margin: 0 0 14px; }
.hero .meta { font: 500 12px "JetBrains Mono", monospace; color: #64748B; }
.tag { font: 600 13px Manrope, sans-serif; letter-spacing: .28em; color: #CBD5E1; }
.tag .bar { color: #334155; margin: 0 .35em; }
.swatches { display: grid; grid-template-columns: repeat(8, 1fr); gap: 12px; }
.sw { border-radius: 8px; overflow: hidden; border: 1px solid #1E293B; background: #0F172A; }
.sw .chip { height: 96px; } .sw .info { padding: 10px 12px; font-size: 12px; color: #94A3B8; }
.sw .info b { display: block; color: #F1F5F9; font: 700 13px Manrope, sans-serif; }
.sw .hex { font: 500 12px "JetBrains Mono", monospace; color: #E2E8F0; }
.gradient { height: 18px; border-radius: 9px; background: linear-gradient(90deg, #00D1FF, #2563FF 48%, #8B5CF6); margin-top: 16px; }
.type-row { display: grid; grid-template-columns: 180px 1fr; gap: 20px; align-items: baseline; padding: 14px 0; border-top: 1px solid #1E293B; }
.type-row:first-of-type { border-top: 0; }
.type-row .who { font: 600 12px Inter, sans-serif; color: #94A3B8; } .type-row .who b { display: block; color: #F1F5F9; font: 700 15px Manrope; }
.meaning { display: grid; gap: 14px; } .meaning div { padding-left: 14px; border-left: 2px solid #2563FF; }
.meaning b { display: block; color: #F1F5F9; font: 700 15px Manrope, sans-serif; } .meaning span { color: #94A3B8; font-size: 13px; }
.do, .dont { position: relative; }
.badge { position: absolute; top: 10px; left: 10px; font: 700 11px Inter, sans-serif; letter-spacing: .08em; padding: 3px 8px; border-radius: 4px; }
.do .badge { background: rgba(52,211,153,.15); color: #34D399; } .dont .badge { background: rgba(255,93,93,.15); color: #FF7A7A; }
.shot { border-radius: 8px; border: 1px solid #1E293B; overflow: hidden; background: #0B1220; }
.shot img { display: block; width: 100%; }
.shot.crop img { height: 520px; object-fit: cover; object-position: top; } .shot .cap { padding: 10px 14px; font-size: 12px; color: #94A3B8; border-top: 1px solid #1E293B; }
.site { border-radius: 8px; border: 1px solid #1E293B; background: #0B1220; }
.site nav { display: flex; align-items: center; gap: 28px; padding: 16px 22px; border-bottom: 1px solid #1E293B; }
.site nav a { color: #CBD5E1; font: 500 14px Inter; text-decoration: none; }
.site .cta { margin-left: auto; display: flex; gap: 10px; }
.btn { font: 600 13px Inter; padding: 8px 14px; border-radius: 6px; border: 1px solid #334155; color: #E2E8F0; }
.btn.primary { background: #2563FF; border-color: #2563FF; color: #fff; }
.site .heroline { padding: 34px 22px 30px; } .site .heroline h2 { font: 800 34px/1.1 Manrope; margin: 0 0 10px; color: #fff; }
.site .heroline h2 span { background: linear-gradient(90deg, #00D1FF, #2563FF); -webkit-background-clip: text; background-clip: text; color: transparent; }
.phone { width: 230px; height: 430px; border-radius: 36px; border: 8px solid #1E293B; background: linear-gradient(160deg, #1e2a4a, #0b1220 60%); padding: 44px 20px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px 10px; align-content: start; margin: 0 auto; }
.phone .app { display: flex; flex-direction: column; align-items: center; gap: 6px; font: 500 10px Inter; color: #CBD5E1; }
.phone .blank { width: 44px; height: 44px; border-radius: 11px; background: #25324d; }
.report { aspect-ratio: 1 / 1.414; background: #0B1220; border: 1px solid #1E293B; border-radius: 6px; padding: 34px; display: flex; flex-direction: column; background-image: radial-gradient(ellipse at 90% 0%, rgba(37,99,255,.25), transparent 50%); }
.report h3 { font: 800 30px/1.1 Manrope; color: #fff; margin: 36px 0 8px; } .report .sub { color: #94A3B8; }
.report dl { display: grid; grid-template-columns: 110px 1fr; gap: 6px 12px; margin: 28px 0 0; font-size: 13px; }
.report dt { color: #64748B; } .report dd { margin: 0; color: #E2E8F0; }
.report .foot { margin-top: auto; border-top: 1px solid #1E293B; padding-top: 14px; font-size: 11px; color: #64748B; }
.term { background: #050A14; border: 1px solid #1E293B; border-radius: 8px; font: 12px/1.6 "JetBrains Mono", monospace; color: #CBD5E1; overflow: hidden; }
.term .bar3 { display: flex; gap: 6px; padding: 10px 12px; border-bottom: 1px solid #1E293B; } .term .bar3 i { width: 10px; height: 10px; border-radius: 50%; background: #334155; }
.term pre { margin: 0; padding: 14px 16px; white-space: pre; } .term .c { color: #FF7A7A; } .term .ok { color: #34D399; } .term .dim { color: #64748B; } .term .hl { color: #7DD3FC; }
.check { display: flex; align-items: center; gap: 12px; padding: 12px 14px; border: 1px solid #1E293B; border-radius: 8px; background: #0F172A; font-size: 13px; }
.check .x { color: #FF7A7A; font-weight: 700; } .check .v { color: #34D399; font-weight: 700; }
.shield { display: inline-flex; border-radius: 4px; overflow: hidden; font: 600 12px Inter; }
.shield span { padding: 4px 8px; display: inline-flex; align-items: center; gap: 6px; } .shield .l { background: #1E293B; color: #fff; } .shield .r { background: #16a34a; color: #fff; }
.note { font-size: 12px; color: #64748B; margin-top: 10px; }
"""


def build(font_dir: Path, out: Path) -> None:
    ts = Typesetter(font_dir)
    L = lambda kind, css, **kw: lockup(kind, ts, css, **kw)  # noqa: E731
    swatches = [
        ("Cyan", CYAN, "Primary · highlights, lens ring, focus"),
        ("Electric blue", BLUE, "Secondary · actions, links"),
        ("Violet", VIOLET, "Accent · gradient end, sparing accents"),
        ("Dark navy", NAVY, "Backgrounds, lens"),
        ("Slate", SLATE, "Surfaces, panels"),
        ("Muted", MUTED, "Borders, dividers"),
        ("White", WHITE, "Type on dark"),
        ("Light gray", LIGHT, "Light surfaces, borders"),
    ]
    sw_html = "".join(
        f'<div class="sw"><div class="chip" style="background:{hx}"></div><div class="info"><b>{name}</b>'
        f'<span class="hex">{hx}</span><br>{role}</div></div>' for name, hx, role in swatches)
    cli = html.escape("""$ securelens scan examples/vulnerable-shop
SecureLens AI 1.0.0 — scanned vulnerable-shop
13 of 13 files · 352 lines · c, cpp, csharp, go, java, javascript, php, python, tsx · 1.1s
Scanners: SecureLens SAST ✓ · secret detection ✓ · dependency inventory ✓ · Known-vulnerability lookup – (failed)

ID         SEVERITY  CONFIDENCE LOCATION               FINDING
SL-001     CRITICAL  HIGH       jsapp/db.js:6          SQL query built from untrusted input
SL-002     CRITICAL  HIGH       jsapp/server.js:19     OS command built from untrusted input
SL-003     CRITICAL  HIGH       phpapp/db.php:7        SQL query built from untrusted input""")
    cli = (cli.replace("CRITICAL", '<span class="c">CRITICAL</span>').replace("✓", '<span class="ok">✓</span>')
           .replace("SecureLens AI 1.0.0", '<span class="hl">SecureLens AI 1.0.0</span>')
           .replace("$ securelens", '<span class="dim">$</span> securelens'))

    donts = [
        ("Don't stretch", 'transform:scaleX(1.45)'),
        ("Don't recolour", 'filter:hue-rotate(150deg) saturate(1.6)'),
        ("Don't rotate", 'transform:rotate(-24deg)'),
        ("Don't add heavy effects", 'filter:drop-shadow(0 0 12px #00D1FF) drop-shadow(0 0 22px #8B5CF6)'),
    ]
    dont_html = "".join(
        f'<div class="tile navy dont"><span class="badge">✕ AVOID</span>{mark(css=f"width:92px;height:92px;{css}")}'
        f'<span class="cap">{text}</span></div>' for text, css in donts)
    busy = ('<div class="tile dont" style="background:repeating-linear-gradient(45deg,#f97316 0 12px,#22c55e 12px 24px,#a855f7 24px 36px)">'
            f'<span class="badge">✕ AVOID</span>{mark(css="width:92px;height:92px")}<span class="cap" style="color:#111">'
            "Don't place on busy backgrounds</span></div>")
    rearranged = ('<div class="tile navy dont"><span class="badge">✕ AVOID</span>'
                  '<div style="display:flex;align-items:center;gap:10px"><span style="font:800 26px Manrope;color:#fff">'
                  f'AI SecureLens</span>{mark(css="width:52px;height:52px")}</div>'
                  '<span class="cap">Don\'t rearrange or retype the wordmark</span></div>')

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=1600">
<title>SecureLens AI — Brand board</title><style>{FONTS}{CSS}</style></head>
<body><main class="board">

<section class="panel hero">
  <div style="display:flex;justify-content:center">{L("s", "width:560px", dark=True)}</div>
  <div>
    <h1>Brand identity · v1</h1>
    <p>An S-shaped ribbon wraps a lens that holds <b style="color:#E2E8F0">&lt;/&gt;</b>. The S is SecureLens and the
       continuous cycle <b style="color:#E2E8F0">Learn → Build → Analyze → Fix → Retest → Verify</b>; the lens is visibility,
       analysis and understanding; the code symbol is developers, programming and secure code review.</p>
    <p class="tag">{tagline(PRIMARY_TAGLINE)}</p>
    <p class="tag" style="color:#94A3B8">{tagline(SECONDARY_TAGLINE)}</p>
    <p class="meta">Generated from geometry by brand/tools/build_brand.py · wordmark Manrope (SIL OFL 1.1)</p>
  </div>
</section>

<section class="panel"><p class="label">Logo variations</p>
  <div class="grid cols-4">
    <div class="tile navy">{L("h", "width:300px", dark=True)}<span class="cap">Primary · dark</span></div>
    <div class="tile light">{L("h", "width:300px", dark=False)}<span class="cap">Primary · light</span></div>
    <div class="tile navy" style="gap:18px">{L("h", "width:300px", dark=True, mono=WHITE)}
      <span class="cap">Monochrome · white</span></div>
    <div class="tile light" style="gap:18px">{L("h", "width:300px", dark=False, mono=NAVY)}
      <span class="cap">Monochrome · navy</span></div>
  </div>
  <div class="grid cols-4" style="margin-top:18px">
    <div class="tile navy">{mark(glow=True, css="width:120px;height:120px")}<span class="cap">Icon-only mark · dark</span></div>
    <div class="tile light">{mark(css="width:120px;height:120px")}<span class="cap">Icon-only mark · light</span></div>
    <div class="tile navy">{L("s", "width:220px", dark=True)}<span class="cap">Stacked · dark</span></div>
    <div class="tile light">{L("s", "width:220px", dark=False)}<span class="cap">Stacked · light</span></div>
  </div>
</section>

<div class="grid cols-7-5">
<section class="panel"><p class="label">App icons &amp; favicon</p>
  <div style="display:flex;align-items:flex-end;justify-content:space-around;gap:24px;padding:10px 0">
    <div class="tile slate" style="min-height:0;border:0">{icon("width:256px;height:256px")}<span class="cap">256 × 256 app icon</span></div>
    <div class="tile slate" style="min-height:0;border:0">{icon("width:64px;height:64px")}<span class="cap">64 × 64</span></div>
    <div class="tile slate" style="min-height:0;border:0">{icon("width:32px;height:32px", small=True)}<span class="cap">32 × 32</span></div>
    <div class="tile slate" style="min-height:0;border:0">{icon("width:16px;height:16px", small=True)}<span class="cap">16 × 16</span></div>
  </div>
  <p class="note">Up to 32 px the flat mark is used (no shading, no glow) so edges stay crisp; the tile is dark navy.</p>
</section>
<section class="panel"><p class="label">Mobile app icon</p>
  <div class="phone">
    {"".join('<div class="app"><div class="blank"></div>&nbsp;</div>' for _ in range(5))}
    <div class="app">{icon("width:44px;height:44px")}SecureLens</div>
    {"".join('<div class="app"><div class="blank"></div>&nbsp;</div>' for _ in range(6))}
  </div>
</section>
</div>

<div class="grid cols-5-7">
<section class="panel"><p class="label">Construction</p>
  <div style="width:100%;aspect-ratio:1;max-width:420px;margin:0 auto">{construction()}</div>
  <p class="note">Two identical annular hooks (R {G.outer}, r {G.inner}) centred {G.offset} above and below the
    middle, 180° rotational symmetry, {G.sweep:g}° sweep, blade terminals ({G.cut:g}° / {G.taper:g}°). Lens r {G.lens}
    with a {G.gap} gap. 64-unit grid.</p>
</section>
<section class="panel"><p class="label">Meaning</p>
  <div class="meaning">
    <div><b>S ribbon — SecureLens and the cycle</b><span>One continuous path: Learn → Build → Analyze → Fix → Retest →
      Verify. It never closes; security is a loop, not a checkbox.</span></div>
    <div><b>Lens — visibility, analysis, understanding</b><span>SecureLens looks into code and shows why something is
      a problem: evidence and data flow, not guesses.</span></div>
    <div><b>&lt;/&gt; — developers first</b><span>The subject is code: programming, secure coding and code review.</span></div>
    <div><b>Cyan → blue → violet</b><span>From seeing to understanding to securing. Used on the mark and brand moments
      only; interfaces stay calm.</span></div>
    <div><b>What it is not</b><span>No shields, padlocks, hooded figures, robots, brains, binary rain, eyes, skulls or
      gaming aesthetics.</span></div>
  </div>
</section>
</div>

<section class="panel"><p class="label">Colour palette</p>
  <div class="swatches">{sw_html}</div>
  <div class="gradient"></div>
  <p class="note">Brand gradient: cyan → electric blue → violet (mark and brand moments). Severity colours are a separate
    set and always pair a shape and a word with the colour. Text pairs used in the product meet WCAG 2.2 AA.</p>
</section>

<div class="grid cols-2">
<section class="panel"><p class="label">Typography</p>
  <div class="type-row"><div class="who"><b>Manrope</b>Display · wordmark · 600–800</div>
    <div style="font:800 44px/1 Manrope;color:#fff">SecureLens <span style="background:linear-gradient(90deg,#00D1FF,#2563FF);-webkit-background-clip:text;background-clip:text;color:transparent">AI</span></div></div>
  <div class="type-row"><div class="who"><b>Inter</b>Interface · 400–700</div>
    <div><div style="font:600 22px Inter;color:#fff">Static analysis identified a data-flow path.</div>
    <div style="font:400 14px Inter;color:#94A3B8">Untrusted data from HTTP request data (server.js:14) reaches argument 1 of connection.query().</div></div></div>
  <div class="type-row"><div class="who"><b>JetBrains Mono</b>Code · evidence · 400–500</div>
    <div style="font:500 14px 'JetBrains Mono';color:#7DD3FC">cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))</div></div>
</section>
<section class="panel"><p class="label">Taglines</p>
  <p class="tag" style="font-size:18px">{tagline(PRIMARY_TAGLINE)}</p>
  <p class="note" style="margin:4px 0 22px">Primary — lockups, website hero, report covers, product surfaces.</p>
  <p class="tag" style="font-size:18px">{tagline(SECONDARY_TAGLINE)}</p>
  <p class="note" style="margin:4px 0 22px">Secondary — learning surfaces, onboarding, campaigns.</p>
  <p class="label" style="margin-top:28px">Clear space &amp; minimum size</p>
  <div style="display:flex;align-items:center;gap:26px">
    <div style="padding:20px;border:1px dashed #00D1FF;border-radius:4px;position:relative">
      {L("h", "width:280px;display:block", dark=True, tagline=False)}
      <span style="position:absolute;top:2px;left:6px;font:500 10px 'JetBrains Mono';color:#7DD3FC">x</span></div>
    <div class="note" style="margin:0">Clear space <b style="color:#E2E8F0">x</b> = the lens radius on every side.<br>
      Minimum: mark 16 px · horizontal lockup 120 px wide.<br>{mark(style="flat", css="width:16px;height:16px;vertical-align:middle")}
      16 px &nbsp; {mark(style="flat", css="width:24px;height:24px;vertical-align:middle")} 24 px</div>
  </div>
</section>
</div>

<section class="panel"><p class="label">Correct &amp; incorrect usage</p>
  <div class="grid cols-4">
    <div class="tile navy do"><span class="badge">✓ USE</span>{L("h", "width:260px", dark=True)}<span class="cap">Primary on dark navy</span></div>
    <div class="tile light do"><span class="badge">✓ USE</span>{L("h", "width:260px", dark=False)}<span class="cap">Primary on white</span></div>
    <div class="tile do" style="background:#2563FF;border-color:#2563FF"><span class="badge" style="background:rgba(255,255,255,.2);color:#fff">✓ USE</span>
      {L("h", "width:260px", dark=True, mono=WHITE)}<span class="cap" style="color:#fff">Monochrome on a solid brand colour</span></div>
    <div class="tile navy do"><span class="badge">✓ USE</span>{mark(style="flat", css="width:64px;height:64px")}<span class="cap">Flat mark at small sizes</span></div>
    {dont_html}{busy}{rearranged}
    <div class="tile navy dont"><span class="badge">✕ AVOID</span>
      <div style="display:flex;align-items:center;gap:8px"><svg viewBox="0 0 24 24" width="46" height="46" aria-hidden="true">
      <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z" fill="none" stroke="#94A3B8" stroke-width="1.6"/></svg>
      {mark(css="width:52px;height:52px")}</div><span class="cap">Don't add shields, padlocks or other symbols</span></div>
  </div>
</section>

<section class="panel"><p class="label">Product UI <small>live screenshots · dark and light</small></p>
  <div class="grid cols-2">
    <div class="shot"><img src="ui/dashboard-dark.png" alt="Security dashboard, dark theme"><div class="cap">Security dashboard · dark</div></div>
    <div class="shot"><img src="ui/finding-light.png" alt="Finding detail, light theme"><div class="cap">Finding evidence and data flow · light</div></div>
  </div>
  <div class="grid" style="grid-template-columns:260px 260px 1fr 250px;margin-top:18px;align-items:start">
    <div class="shot crop"><img src="ui/sidebar-dark.png" alt="Application sidebar, dark"><div class="cap">Application sidebar · dark</div></div>
    <div class="shot crop"><img src="ui/sidebar-light.png" alt="Application sidebar, light"><div class="cap">Application sidebar · light</div></div>
    <div class="shot"><img src="ui/auth-dark.png" alt="Sign-in with the 3D mark"><div class="cap">Setup and sign-in · interactive 3D mark</div></div>
    <div class="shot crop"><img src="ui/mobile-dark.png" alt="Mobile layout"><div class="cap">Mobile · scan result</div></div>
  </div>
</section>

<section class="panel"><p class="label">Website header <small>design specification · the public website is not built yet</small></p>
  <div class="site"><nav>{L("h", "height:38px", dark=True, tagline=False)}<a>Product</a><a>Learn</a><a>Labs</a><a>Docs</a><a>GitHub</a>
    <div class="cta"><span class="btn">Sign in</span><span class="btn primary">Get started</span></div></nav>
    <div class="heroline"><h2>Learn. Build. Secure.<br><span>With real understanding.</span></h2>
    <p class="tag" style="font-size:12px">{tagline(SECONDARY_TAGLINE)}</p></div></div>
</section>

<div class="grid" style="grid-template-columns:420px 1fr">
<section class="panel"><p class="label">Security report cover</p>
  <div class="report">
    {L("h", "width:250px", dark=True, tagline=False)}
    <h3>Security Assessment Report</h3>
    <div class="sub">vulnerable-shop · source code analysis</div>
    <dl><dt>Date</dt><dd>30 September 2026</dd><dt>Scope</dt><dd>13 files · 352 lines · 9 languages</dd>
      <dt>Open findings</dt><dd>85 — 28 critical · 40 high · 17 medium</dd><dt>Security gate</dt><dd>Failed</dd>
      <dt>Classification</dt><dd>Confidential</dd></dl>
    <div class="foot"><p class="tag" style="font-size:9px;margin:0 0 8px">{tagline(PRIMARY_TAGLINE)}</p>
      This report is evidence for review, not a guarantee of security. Runtime testing was not performed.</div>
  </div>
</section>
<section class="panel"><p class="label">Developer-tool branding</p>
  <div class="term"><div class="bar3"><i></i><i></i><i></i></div><pre>{cli}</pre></div>
  <p class="note">Real output of the securelens CLI (the advisory lookup is blocked by this environment's network policy and is reported as failed).</p>
  <div class="grid cols-2" style="margin-top:16px">
    <div class="check">{mark(style="flat", css="width:22px;height:22px")}<div><b>SecureLens AI / security gate</b><br>
      <span class="x">✕</span> <span style="color:#94A3B8">Failed — 28 critical findings (policy: fail on critical)</span></div></div>
    <div class="check">{mark(style="flat", css="width:22px;height:22px")}<div><b>SecureLens AI / retest</b><br>
      <span class="v">✓</span> <span style="color:#94A3B8">Passed — 13 of 14 findings resolved, no regressions</span></div></div>
  </div>
  <div style="display:flex;gap:16px;align-items:center;margin-top:16px">
    <span class="shield"><span class="l">{mark(style="flat", css="width:14px;height:14px")} SecureLens</span><span class="r">gate passed</span></span>
    <span class="shield"><span class="l">{mark(style="flat", css="width:14px;height:14px")} SecureLens</span><span class="r" style="background:#dc2626">gate failed</span></span>
    <span class="note" style="margin:0">CI check and README badge — design specifications for the existing CI integration.</span>
  </div>
</section>
</div>

</main></body></html>
"""
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(page, "utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--font-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "board")
    args = parser.parse_args()
    build(args.font_dir, args.out)


if __name__ == "__main__":
    main()
