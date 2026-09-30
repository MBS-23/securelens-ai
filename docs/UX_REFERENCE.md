# SecureLens AI — UX Reference (product owner's mockup)

Status: reference only · received 2026-09-30 · image: [`reference/ux-reference-mockup.webp`](reference/ux-reference-mockup.webp)

> **This is a sample, not the product.** The mockup shows the *flow and layout* the
> product owner wants SecureLens to reach. Nothing in it is implemented just
> because it appears there, and its numbers (for example "500+ interactive labs",
> "100+ real projects", "44 findings", "86% fixed") are placeholders that must
> never be shown as facts. Every screen is built for real, one vertical slice at a
> time, and is marked below as implemented, partial or planned. Visual styling
> follows `DESIGN_SYSTEM.md`; the mockup's glow and gradients are not adopted in
> the work surfaces.

## Screen-by-screen

| # | Screen (mockup) | Flow it describes | Today | Phase |
|---|---|---|---|---|
| 1 | Landing page | Value proposition ("Learn. Build. Secure."), four capability callouts (write code, find vulnerabilities, AI code review, fix & verify), calls to action, a stats strip | Planned. Stats must be real counts from the platform or omitted | 3 |
| 2 | Onboarding: choose your path | Profile → Goals → Skills → Complete; eight starting levels from absolute beginner to security engineer | Planned | 2 |
| 3 | Dashboard: personalised hub | Continue learning, active project, latest scan, tutor; the journey Learn → Practice → Build → Break safely → Fix → Verify → Secure; progress per language/track; recent activity | **Partial**: the security dashboard exists (real open findings, trends, Risk Index, recent scans); the learning hub parts are planned | 3, 5 |
| 4 | Programming learning | Track outline; lesson tabs Concept · Example · Visualise · Practice · Common mistakes · Secure version; runnable code with output; memory visualisation | Planned | 5–6 |
| 5 | Coding practice (DSA problem) | Problem, examples, editor, Submit/Reset, test cases with pass/fail and timings, hints 1–2, solution gated | Planned (needs the isolated runner) | 6–7 |
| 6 | DSA visual explanation | Topic list; Concept · Visualisation · Implementation · Practice · Problems; step-through array visualisation with code and complexity | Planned | 7 |
| 7 | Project builder | Levels; project cards with stack and security tags; starter / guided / independent / security-review modes | Planned | 4, 18 |
| 8 | Web Security Academy lab | Learning path by topic; lab with target app frame and request/response panel; difficulty labels | Planned. Original content; targets are sandboxed lab apps only | 14 |
| 9 | Secure coding: insecure vs secure | Side-by-side code, data-flow strip (HTTP input → function → string → SQL sink), linked finding with View evidence / View fix / Run retest | **Partial**: findings already show the traced data flow and evidence; the side-by-side lesson view is planned | 8, 12 |
| 10 | AI Security lab (prompt injection) | Overview · Lab · Examples · Mitigation · Practice; chat against a lab assistant; analysis of the prompt path; secure-implementation checklist | Planned. Mock/sandbox targets only; a refusal is never treated as proof of security | 16 |
| 11 | Scan results | Severity counts, tabs (findings, data flow, dependencies, evidence, report), findings table | **Implemented** (scan detail, findings, dependencies, files, reports) | done |
| 12 | Finding detail | Evidence, data flow, explanation, fix, retest, references | **Implemented** for evidence, data flow, guidance and triage; AI explanation (evidence-bound, labelled AI-assisted) and "Apply fix" (diff → review → retest) are planned | 12, 17 |
| 13 | Retest after fix | Previous vs current scan, resolved / still open / new / regressions, security gate | **Implemented** (automatic comparison per repository, gate) | done |
| 14 | Project security report | Risk Index, open findings, severity breakdown, status, download/share | **Partial**: HTML, SARIF, JSON and Markdown reports exist; PDF export and sharing are planned | 19 |

The mockup's navigation (Dashboard · Learn · Practice · Projects · Labs · Scan ·
Findings · AI Tutor · Progress · Certificates · Community) matches the planned
information architecture in `PRODUCT_SPEC.md`; items appear in the product only
when the feature behind them exists.

## Where the mockup and the rules meet

| Mockup element | How SecureLens builds it |
|---|---|
| Placeholder counts and percentages | Only real, current values; "13 of 14 previous findings resolved" rather than an unexplained percentage |
| Day streak, level, certificates | Measured only from verified work (completed labs, fixes proven by retest); never presented as professional competence; no vanity metrics |
| "AI explanation", "Ask anything" | Evidence-bound, schema-validated, labelled AI-assisted; repository content is treated as untrusted data |
| "Apply fix" | A reviewable diff; never applied silently; the finding resolves only after a retest scan |
| Burp-style request/response lab | Sandboxed, intentionally vulnerable lab services; no real-world targets |
| Glowing, gradient visual style | Layout and flow adopted; styling per `DESIGN_SYSTEM.md` (the brand mark is the one place with depth) |
