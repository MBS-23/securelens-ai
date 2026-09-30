# SecureLens AI — Design System (Phase 4)

Status: v1 · 2026-09-30

SecureLens should read like a precise engineering instrument with the clarity
of a good technical book — not a template dashboard. Hierarchy comes from
typography, spacing and alignment; colour carries meaning, not decoration.

## 1. Principles

1. **Evidence first.** The most important thing on a finding page is the
   evidence; on a lesson page, the explanation. Chrome stays quiet.
2. **Typography over boxes.** Sections are separated by whitespace and hairline
   rules. Panels are used only where grouping aids comprehension (code, forms,
   diffs). No card grids for their own sake.
3. **Density with rhythm.** Tables are compact and scannable; prose has
   generous line height and a comfortable measure (~72 characters).
4. **Meaning is never colour-only.** Severity, status and verdicts always pair a
   shape and a word with the colour.
5. **Honest states.** Every screen designs its loading, empty, error, partial
   and success states; empty states say what to do next.
6. **Purposeful motion only.** Short transitions for focus and disclosure;
   `prefers-reduced-motion` removes transitions. The one deliberate exception
   is the brand: the 3D SecureLens mark assembles during page loads and opens
   into the page (see `brand/BRAND.md` → Motion and 3D). It never delays content
   beyond real loading plus 240 ms, and users can switch it off. Other 3D is used
   only when it teaches something.

Explicitly avoided: gradients, glassmorphism, neon, glowing borders, heavy
shadows, oversized radii, decorative illustrations in work surfaces. (The brand
mark keeps its own tonal depth; it is not a surface style.)

Brand: `brand/BRAND.md` (mark, lockups, colours, motion). Target flows:
`UX_REFERENCE.md` (the product owner's mockup, reference only).

## 2. Typography

Bundled locally (SIL Open Font License), three voices — see `brand/BRAND.md`:

| Role | Family | Use |
|---|---|---|
| Interface | Inter (variable) 400–700 | Navigation, body, tables, forms |
| Display | Manrope 600–800 | Page titles, wordmark, taglines, marketing headings |
| Code & data | JetBrains Mono 400–500 | Code, paths, IDs, evidence |

Scale (px): 12 · 13 · 14 · 16 · 18 · 22 · 28 · 36. Headings use tight leading
(1.15–1.25) and slight negative tracking; body text 1.55–1.65. Numbers in
metrics and tables use tabular figures. Eyebrow labels are 11–12 px, uppercase,
+0.06em tracking.

## 3. Colour

Semantic tokens (CSS custom properties in `frontend/src/index.css`) built on the
brand palette, with a dark (default) and a light theme:

| Token | Dark | Light | Purpose |
|---|---|---|---|
| `--bg` | `#0B1220` | `#F8FAFC` | Page |
| `--surface`, `--surface-2`, `--surface-3` | `#0F172A` · `#131D33` · `#1E293B` | `#FFFFFF` · `#F1F5F9` · `#E2E8F0` | Raised areas, wells |
| `--line`, `--line-strong` | `#1F2A3D` · `#334155` | `#E2E8F0` · `#CBD5E1` | Rules, borders |
| `--ink`, `--ink-2`, `--muted` | `#F1F5F9` · `#CBD5E1` · `#94A3B8` | `#0B1220` · `#334155` · `#64748B` | Text |
| `--accent` | `#6E9BFF` | `#2563FF` | Links, focus, interactive text (contrast-safe on the page) |
| `--accent-bg` / `--accent-ink` | `#2563FF` / `#FFFFFF` | `#2563FF` / `#FFFFFF` | Primary control fill and its text |
| `--accent-2` | `#00D1FF` | `#0E7490` | Highlight |
| `--crit`, `--high`, `--med`, `--low`, `--info` | — | — | Severity (separate from brand colours) |
| `--pass`, `--fail` | — | — | Verdicts and statuses |

Text contrast meets WCAG 2.2 AA (4.5:1 body) in both themes; the pairs were
checked when the palette was introduced.

## 4. Meaning encodings

| Meaning | Shape | Word | Colour |
|---|---|---|---|
| Critical | ◆ filled diamond | CRITICAL | `--crit` |
| High | ▲ triangle | HIGH | `--high` |
| Medium | ■ square | MEDIUM | `--med` |
| Low | ● circle | LOW | `--low` |
| Info | ○ ring | INFO | `--info` |
| Pass | ✓ | PASS | `--pass` |
| Partial | ◐ | PARTIAL | `--partial` |
| Fail | ✕ | FAIL | `--fail` |
| Inconclusive / not tested | ? / – | INCONCLUSIVE / NOT TESTED | `--unknown` |

Evidence classes are shown as small outlined tags with their full name
(e.g., *Static analysis finding*, *Deterministically verified*,
*AI-assisted analysis*), never abbreviated to an icon.

## 5. Layout

* **Shell** — left navigation rail on wide screens (Dashboard, Learn, Practice,
  Build, Scan, Findings, Projects, AI Security, Reports, Progress, Settings —
  only features that exist); top bar with breadcrumb ("where am I"), mode
  switch (Learning / Professional), theme and account. On small screens the rail
  becomes a full-screen menu opened from the top bar.
* **Content** — max width 1200 px; reading columns 72ch; a sticky "on this page"
  outline on long pages (findings, lessons) that becomes a horizontal chip row on
  mobile.
* **Grid** — 4 px base; spacing steps 4 · 8 · 12 · 16 · 24 · 32 · 48 · 64.
* **Radius** — 3 px controls, 4 px panels, full for pills only.

## 6. Components

| Component | Notes |
|---|---|
| Page header | Eyebrow (context), title, one-line meta, primary actions right-aligned |
| Section | Title + hairline rule + content; optional aside for metadata |
| Data table | Compact rows, sticky header, full-row link, keyboard focusable rows; stacks into a list on mobile |
| Key–value list | Two columns; wraps on mobile |
| Severity / status / verdict marks | Shape + word + colour (§4) |
| Evidence-class tag | Outlined, full wording |
| Flow (data flow) | Horizontal nodes on desktop, vertical on mobile; each node is a button opening the source line |
| Code block / viewer / diff | Plex Mono, line numbers, finding gutter marks; Monaco for viewer and diff (bundled locally) |
| Buttons | Primary (solid accent), secondary (outline), quiet (text), danger (solid red, confirmation required) |
| Inputs | Visible labels (never placeholder-only), inline validation messages, error text linked by `aria-describedby` |
| Notices | Info, warning, error, success — icon + text; errors say what happened and what to do |
| Empty state | What this area is for + the next action |
| Loading | Skeleton lines matching the final layout; live-region announcement for long jobs |
| Progress | Bar + numeric value + what it measures ("Learning progress, not competence") |

## 7. Accessibility

Semantic landmarks and headings; a "skip to content" link; every interactive
element reachable and operable by keyboard with a visible 2 px focus ring;
ARIA only where HTML lacks semantics; `aria-live` for scan and run progress;
labels for all form controls; no information conveyed by colour alone;
reduced-motion support; zoom to 200% without loss of content.

## 8. Responsive behaviour

Designed at 360, 768, 1024 and 1440 px. The coding environment prioritises
desktop (editor + output side by side) and stacks editor → controls → results on
small screens rather than shrinking. Tables become lists; the flow graph becomes
vertical; the outline becomes chips.
