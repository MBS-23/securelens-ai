# SecureLens AI — Brand identity

Status: v1 (final identity) · 2026-09-30 · Board: [`board/securelens-brand-board.png`](board/securelens-brand-board.png)
(source: [`board/index.html`](board/index.html))

## Concept

**An S-shaped ribbon wraps a lens that holds `</>`.**

| Element | Meaning |
|---|---|
| S ribbon | SecureLens, and the continuous Learn → Build → Analyze → Fix → Retest → Verify cycle |
| Lens | Visibility, analysis, understanding — SecureLens looks *into* code and shows why |
| `</>` | Developers first: programming, secure coding, code review |
| Cyan → blue → violet | From seeing to understanding to securing |

Security is implied, never shouted. The identity never uses shields, padlocks,
hooded figures, robots, brains, binary rain, Matrix effects, generic eyes,
skulls or gaming aesthetics.

## Taglines

* **Primary** — `CODE | ANALYZE | REMEDIATE | VERIFY` (lockups, website hero, report covers, product surfaces)
* **Secondary** — `SEE | UNDERSTAND | FIX | SECURE` (learning surfaces, onboarding, campaigns)

Set in Manrope SemiBold, uppercase, tracking +0.28 em, with thin separators.

## Construction

Generated from geometry by `tools/build_brand.py` (64-unit grid, centre 32, 32):

* two identical annular hooks — outer radius 16.6, inner radius 6.2 — centred
  11.2 above and below the middle, 180° rotational symmetry, 238° sweep,
  blade terminals (outer edge overhangs 24°, inner edge starts 10° later);
* one linear gradient through the ribbon (cyan `#00D1FF` → electric blue
  `#2563FF` at 48% → violet `#8B5CF6`), a radial shade darkening each band's
  inner edge and a thin highlight on its outer edge;
* a lens of radius 10.4 in dark navy with a 1.1 cyan ring and `</>` at 2.1,
  separated from the ribbon by a 1.8 gap;
* optional glow (dark backgrounds only): a blurred cyan ring behind the lens.

Never redraw, stretch, rotate, recolour, rearrange, outline or add effects.
Change the geometry in the script and regenerate every asset.

## Assets

| File | Use |
|---|---|
| `securelens-logo-dark.svg` · `securelens-logo-light.svg` | Primary horizontal lockup with tagline (dark / light backgrounds) |
| `securelens-logo-stacked-dark.svg` · `-light.svg` | Stacked lockup (hero, square placements) |
| `securelens-logo-mono-white.svg` · `-mono-navy.svg` | One-colour lockups |
| `securelens-mark.svg` · `-mark-dark.svg` | Icon-only mark (shaded; `-dark` adds the glow) |
| `securelens-mark-flat.svg` | Flat mark for small sizes |
| `securelens-mark-mono-white.svg` · `-mono-navy.svg` | One-colour mark |
| `securelens-app-icon.svg` · `png/securelens-app-icon-{180,256,512}.png` | App icon (navy tile, soft blue glow) |
| `securelens-favicon.svg` · `png/securelens-favicon-32.png` | Favicon (flat mark, ≤ 32 px) |
| `png/securelens-logo-{light,dark}-1200.png` · `png/securelens-logo-stacked-dark-900.png` | Documents and previews |

`tools/export_png.mjs` renders the PNGs and installs the favicon, touch and PWA
icons in `frontend/public/`. `tools/build_board.py` + `tools/export_board.mjs`
rebuild the board.

## Wordmark and typography

The wordmark is **SecureLens AI** — Manrope ExtraBold, tracking −0.01 em; "AI"
carries the cyan → blue gradient so it reads as a descriptor, not the product.
It is converted to outlines (no font needed at runtime).

| Role | Family | Licence |
|---|---|---|
| Display, wordmark, taglines | Manrope 600–800 | SIL OFL 1.1 |
| Interface | Inter (variable) | SIL OFL 1.1 |
| Code, evidence | JetBrains Mono 400–500 | SIL OFL 1.1 |

All fonts are bundled locally (no third-party font CDN). Licences:
`board/fonts/LICENSE-*.txt`.

## Colour

| Name | Hex | Role |
|---|---|---|
| Cyan | `#00D1FF` | Primary — highlights, lens ring, focus |
| Electric blue | `#2563FF` | Secondary — primary actions, links |
| Violet | `#8B5CF6` | Accent — gradient end, sparing accents |
| Dark navy | `#0B1220` | Backgrounds, lens |
| Slate | `#1E293B` | Surfaces, panels |
| Muted | `#334155` | Borders, dividers |
| White | `#FFFFFF` | Type on dark |
| Light gray | `#E2E8F0` | Light surfaces, borders |

The gradient belongs to the mark and brand moments; product surfaces stay calm
and flat. Brand colours never communicate severity or status — severity has its
own set and always pairs shape, word and colour. Every text pair used in the
product meets WCAG 2.2 AA (checked: dark and light themes).

## Clear space and minimum size

Clear space on every side: **x = the lens radius**. Minimum sizes: mark 16 px
(use the flat mark up to 32 px), horizontal lockup 120 px wide.

## Motion and 3D

The dashboard renders the mark as a 3D scene (`frontend/src/components/BrandMark3D.tsx`):
ribbon and lens planes with extruded edges in darker gradient tones, and a
controlled cyan glow on the lens in the dark theme.

| State | Where | Behaviour |
|---|---|---|
| Assemble → loading | Every page change | Hooks fly in, the lens pops, `</>` draws, the ring scans while the page loads |
| Open | When the page is ready | Hooks part, the lens widens; the page is revealed through it |
| Idle + pointer tilt | Setup and sign-in | Slow float; leans towards the pointer |
| Still | Reduced motion (device or user setting) | Static mark; pages appear immediately |

Motion never delays content beyond real loading plus 240 ms; the reveal lasts
420 ms; only transform and opacity animate. The device's reduced-motion setting
always wins, and users can turn motion off in Account → Appearance.
