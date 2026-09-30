# SecureLens AI — Brand

Status: v1 · 2026-09-30 · Mark: "Concept 3", chosen by the product owner

## Concept

**An S-shaped ribbon wrapped around a lens that holds `</>`.**

* **S ribbon** — SecureLens, and a flow path: learn → fix → verify.
* **Lens** — visibility and understanding: SecureLens looks *into* code.
* **`</>`** — developer-first; the thing being examined is code.

The identity reads *Lens → Visibility → Understanding → Security →
Verification*. Security is implied, never shouted: no padlocks, generic shields,
hooded figures, binary rain, robot heads, circuit brains or crossed-out bugs.

## Construction

Generated from geometry by `tools/build_brand.py`, so every export is identical
(64 × 64 design box):

* two identical annular bands (inner radius 6.8, outer 15.8) centred 11 units
  above and below the middle, each sweeping 232° from a terminal slanted by 16°,
  arranged with 180° rotational symmetry;
* a lens of radius 10.6 at the centre, separated from the ribbon by a 1.7 gap,
  with a 1.2 ring and `</>` drawn at 2.2.

Never redraw, stretch, rotate, recolour per page, or add effects to the SVGs.
Regenerate them with the script instead.

## Assets

| File | Use |
|---|---|
| `securelens-mark.svg` | The mark, full colour (light or dark backgrounds) |
| `securelens-mark-flat.svg` · `securelens-mark-mono-light.svg` | One-colour ribbon for print, embroidery, monochrome |
| `securelens-app-icon.svg` · `png/securelens-app-icon-*.png` | App icon, favicon, touch and PWA icons |
| `securelens-logo.svg` · `-inverse.svg` | Horizontal lockup for light / dark backgrounds |
| `securelens-logo-stacked.svg` · `-inverse.svg` | Stacked lockup for square placements |
| `png/securelens-logo-1200.png` · `-inverse-1200.png` | Documents and social previews |

`tools/export_png.mjs` renders the PNGs and copies the favicon set into
`frontend/public/`.

## Wordmark

**SECURELENS** is dominant (Manrope Bold, uppercase, +0.045 em); **AI** is a
secondary descriptor (Manrope Medium, brand blue) after a hairline rule, so the
product never reads as "another AI startup". The wordmark is converted to
outlines — no font needed at runtime. Manrope is licensed under the SIL Open Font
License 1.1. Product UI text uses IBM Plex (see `docs/DESIGN_SYSTEM.md`).

## Colour

| Role | Value |
|---|---|
| Navy (lens, ink on light) | `#0B1B36` |
| Upper ribbon | `#4F8CFF` → `#2F5BEA` |
| Lower ribbon | `#4B5BF0` → `#7B5CF5` |
| Lens ring | `#5CC8FF` |
| `</>` | `#E8F4FF` |
| Brand blue (AI, flat mark) | `#2563EB` on light · `#6FA0FF` on dark |
| Light ink (on navy) | `#E8EEF9` |

The mark is the one place in the product with tonal depth; interface surfaces
stay flat. Brand colours never communicate severity or status.

## Clear space and minimum size

Clear space on every side: the lens radius (one sixth of the mark's height).
Minimum sizes: mark 16 px (the lens detail fades, the S silhouette remains);
horizontal lockup 120 px wide.

## Motion and 3D

The dashboard renders the mark as a 3D scene (`frontend/src/components/BrandMark3D.tsx`):
ribbon and lens planes with extruded slices, lit by their gradients.

| State | Where | Behaviour |
|---|---|---|
| Assemble → loading | Every page change | The hooks fly in, the lens pops, `</>` draws, the ring scans while the page loads |
| Open | When the page is ready | The hooks part, the lens widens, and the page is revealed through it |
| Idle + pointer tilt | Sign-in and setup | Slow float; leans towards the pointer |
| Still | Reduced motion (device or user setting) | Static mark; pages appear immediately |

Rules: motion never delays content beyond real loading plus a 240 ms minimum;
the reveal lasts 420 ms; animations use transform and opacity only; the device's
reduced-motion setting always wins, and users can turn motion off in Account →
Appearance.
