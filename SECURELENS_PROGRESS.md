# SecureLens AI — Progress and Continuation Record

Last updated: 2026-09-30 · Branch: `claude/keen-brahmagupta-n4am7q` · Last commit audited: `afc5425`

**Start every session here.** Read, in order: `SECURELENS_MASTER_SPEC.md` (what to build, verbatim),
`SECURELENS_EXECUTION_PROTOCOL.md` (how to work), this file (where things stand), `README.md`,
then `docs/ARCHITECTURE.md` and `docs/THREAT_MODEL.md` for the subsystem you are touching.

---

## 1. Project Status Report (audit of 2026-09-30)

Method: I inspected the committed code (the uncommitted taxonomy work was set aside with `git stash` first),
ran the full backend suite, type-checked the frontend, statically compared every frontend API call with
the backend routes, searched for placeholder or fake behaviour, and listed database tables that no code uses.

### CURRENT ARCHITECTURE

```
securelens-ai/                 independent product (no code shared with any other project)
├── backend/                   Python 3.11 package `securelens` (~16k lines, 1.7k lines of tests)
│   ├── api/                   FastAPI routers under /api/v1 (53 endpoints)
│   ├── services/              business logic (identity, projects, scans, findings, metrics, reports, integrations)
│   ├── models/ schemas/       SQLAlchemy 2.1 models (28 tables) · Pydantic 2 schemas
│   ├── migrations/            Alembic, one revision (0001_initial_schema); SQLite + PostgreSQL 16 verified
│   ├── worker/                DB-backed job queue consumer + analysis sandbox (subprocess + rlimits)
│   ├── scanners/              inventory, SAST (tree-sitter → IR → inter-procedural taint), secrets,
│   │                          dependencies (+ OSV lookup), external adapters (Bandit, Semgrep, Gitleaks)
│   ├── findings/              unified model, catalog, correlation, fingerprints, risk index, gate, retest
│   ├── reporting/             JSON · SARIF 2.1.0 · HTML (self-contained, CSP) · Markdown
│   ├── cli/                   `securelens` command (init, scan, findings, report, retest, push, version)
│   └── ai/                    provider abstraction only (none / OpenAI-compatible / Anthropic)
├── frontend/                  React 19 · React Router 7 · TanStack Query 5 · Tailwind 4 · Vite 7 · Monaco
│                              22 pages against the real API (not yet committed; does not build — see below)
├── docs/                      RESEARCH, PRODUCT_SPEC, ARCHITECTURE, THREAT_MODEL, DESIGN_SYSTEM
└── examples/                  vulnerable-shop (Python/JS/PHP/services), retest-demo (before/after)
```

* **Frontend:** React SPA, same-origin cookie session + CSRF header; Monaco bundled locally.
* **Backend:** FastAPI + SQLAlchemy + Pydantic; a separate worker process consumes jobs from PostgreSQL.
* **Database:** PostgreSQL 16 (production target, verified); SQLite for development and tests.
* **Authentication:** first-run bootstrap (creates organization + owner) → login → opaque session cookie
  (HttpOnly, SameSite=Strict, Secure in production) + HMAC CSRF token; API keys (`slk_…`, hashed,
  role-capped, project-scoped for low roles); Argon2id; lockout + per-IP rate limit; password change
  revokes sessions. Members are added by an admin (email + role, admin-chosen initial password for new
  accounts).
* **Authorization:** roles OWNER, ADMIN, SECURITY_ANALYST, DEVELOPER, VIEWER per organization; org-wide
  project access for the top three, explicit project membership for the others; tenant checks return 404.
* **Scanner:** see tree above; findings carry evidence (data-flow steps, patterns, masked secrets,
  advisories), a verification axis (DETECTED / AI_SUGGESTED / CONFIRMED / FALSE_POSITIVE / NOT_TESTED) and
  exploitability (PROVEN_DATAFLOW / LIKELY / POSSIBLE / THEORETICAL).
* **AI:** provider selection and a status endpoint. No feature calls a model yet.
* **Learning modules:** none implemented.
* **Projects:** projects, repositories (git URL or upload), project members, snapshots, scans, findings,
  retests, metrics.
* **Deployment:** configuration through `SECURELENS_*` environment variables with production guards.
  No Dockerfile, Compose file, nginx configuration or CI workflow exists yet.

### CURRENT FEATURES — COMPLETED (real backend, tested)

| Feature | Evidence |
|---|---|
| Organizations, users, memberships, sessions, API keys, RBAC, audit log | `tests/test_auth_rbac.py` |
| Upload ingestion (archives, single files) with Zip Slip / bomb / symlink / size defences; hardened git clone | `tests/test_ingest.py` |
| Scan pipeline: API → job → worker → sandboxed analysis → dependency lookup → persistence | `tests/test_scan_api.py` (SQLite; PostgreSQL 16 verified earlier) |
| SAST, 8 language families (Python, JS/TS, PHP, Java, C#, Go, C/C++) with a regression corpus | `tests/test_corpus.py`, `tests/corpus/cases.yml` |
| Secret detection with masking (full values never stored or shown) | `tests/test_secrets.py` |
| Dependency inventory and OSV advisory matching (unknown data marked NOT VERIFIED) | `tests/test_dependencies.py` |
| Correlation, fingerprints, triage (status + verification with reasons), risk index, security gate | `tests/test_finding_engine.py` |
| Retest comparison: RESOLVED only when the file was re-analysed by the same scanner | `tests/test_finding_engine.py`, `tests/test_scan_api.py` |
| Reports: JSON, SARIF 2.1.0, HTML (no scripts, CSP), Markdown (escaped) | `tests/test_reporting.py` |
| CLI with `.securelens.yml`, baseline mode, CI templates, `push` to the server | `tests/test_cli.py` |
| Dashboard metrics and organization settings (risk weights, gate policy) | `tests/test_dashboard.py` |
| Analysis sandbox limits (memory, CPU, file size, open files, wall-clock kill) | `tests/test_sandbox.py` |

### PARTIALLY COMPLETED FEATURES

| Feature | What exists | What is missing |
|---|---|---|
| Web dashboard | 22 pages wired to real endpoints (projects, scans, code view, findings, retests, settings) | Build fails (2 missing pages); no tests; styling predates `docs/DESIGN_SYSTEM.md`; not committed |
| Taxonomy mapping | Every class carries CWE and OWASP labels | Labels are OWASP 2021 / LLM 2025 strings shown as if current; several disagree with the official CWE lists (e.g. `insecure_tls` → A02:2021, but CWE-295 is listed under A07); no edition metadata. *Fix in progress (stashed, §3).* |
| Evidence model | Verification + exploitability axes; evidence items | Spec evidence classes, INCONCLUSIVE status / retest result, per-finding language, tool version, limitations. *In progress (stashed).* |
| Scan coverage | Each scanner run recorded as ran / skipped / unavailable / failed; report scope table | Spec coverage vocabulary (COMPLETE / SKIPPED / NOT PERFORMED / NOT ASSESSED / REQUIRED) in API, UI and reports |
| Remediation | `remediations` table; scan completion updates a linked remediation after retest | No API or UI to propose, review or apply a fix, so the path is unreachable |
| Integrations | Secret-reference resolver (`env:SECURELENS_INTEGRATION_*`) used for private git tokens | No API/UI to manage integrations |
| Roles | 5 roles | LEARNER |

### BROKEN FEATURES

1. **Frontend build** — `tsc -b` fails: `src/App.tsx` imports `./pages/Account` and `./pages/NotFound`, which do not exist.
2. **Frontend unit tests** — `vite.config.ts` references `tests/setup.ts`, which does not exist; `tests/` and `e2e/` are empty.
3. **Publishing** — six commits exist only locally: `git push` is refused with HTTP 403 (the GitHub App lacks access to the repository). Code is fine; access must be granted by the owner.

### PLACEHOLDER FEATURES

No "coming soon", mock results, fake scores or hard-coded findings were found in product code. Schema exists
without behaviour (no service, API or UI uses it, and nothing presents it as working):
`ai_targets`, `security_tests`, `test_runs`, `test_results` (AI security evaluation), `ai_analyses`,
`reports`; job kinds `TEST_RUN`, `AI_ANALYSIS`, `REMEDIATION`, `PR_COMMENT` have no worker handler.
Decision D6 below: keep them (they match planned phases) and never surface them until implemented.

### SECURITY RISKS (highest first)

1. **Analysis sandbox is resource-limited but not isolated.** The analysis child has rlimits, its own
   process group and a secret-free environment, but no network, filesystem or user namespace. A parser
   exploit (tree-sitter grammars are C) could read files or open connections as the worker user.
   Mitigation plan: run the worker in a container with no egress and read-only mounts; add a network
   namespace (bubblewrap/unshare) when available; document in System status.
2. **No MFA and no self-service account recovery.** Admin-chosen initial passwords for new members; no
   invitation or password-reset flow. (Phase 2.)
3. **Rate limiting is in-process**, so it is per API instance (acceptable for profiles A–C, not D).
4. **No deployment artifacts** — the SPA's CSP and security headers, non-root containers, read-only root
   filesystems and the runner network boundary exist only as documentation.
5. **Content integrity** — mislabelled OWASP categories are wrong security teaching (fix in progress).
6. **Imported CLI results** (`POST …/scans/import`) are schema-validated, but evidence classes must be
   recomputed server-side and non-static evidence kinds refused (part of the stashed evidence work).
7. **Dependency hygiene of SecureLens itself** — no `pip-audit` / `npm audit` / self-scan in CI yet.
8. **AI features** will need prompt-injection defences before any ships; none exists yet, so no current
   exposure.

### TECHNICAL DEBT

* Frontend is a large uncommitted change; commit it as soon as it builds.
* Duplicated ordering tables (`_RESULT_ORDER` in `api/retests.py` and `cli/main.py`).
* Placeholder-only form inputs (search and filter fields) violate the design system's labelling rule.
* No CI for SecureLens (lint, tests, typecheck, build, self-scan).
* One Alembic revision; the next schema changes need `0002`.
* Starlette test client deprecation warning (httpx) in tests.
* Unused tables (see Placeholder features) must stay clearly labelled as schema-only.

### MISSING FEATURES (against the master specification)

Registration, password reset, email verification, MFA, invitations, LEARNER role · the whole learning
platform (content engine with quality gates, programming tracks, DSA, isolated code runner, Secure Coding
Academy with fix-the-code grading, Web/API/AI Security academies, labs and mystery assessments, tutor,
progress analytics) · project builder (templates, milestones, modes, portfolio) · remediation workflow ·
evidence-bound AI explanations, AI code review, LLM security evaluation · additional report types ·
deployment profiles (Compose, nginx, runner service) and CI · design-system implementation, mobile
navigation and end-to-end tests.

### RECOMMENDED IMPLEMENTATION ORDER

Following the protocol's priority list, applied to what exists:

1. **Phase 1 — Stabilisation (next).** Make the frontend build and add its test setup; commit it.
   Finish the stashed correctness work (versioned taxonomy from official CWE lists, evidence classes,
   limitations, INCONCLUSIVE) because current output mislabels taxonomy editions. Add a CI workflow.
2. **Phase 2 — Authentication and authorization.** Self-registration with personal workspace, LEARNER,
   invitations, password reset (console/SMTP mail backend), optional email verification, TOTP MFA with
   recovery codes, Alembic `0002`, UI pages, tests.
3. **Phase 3 — Core design system.** Implement `docs/DESIGN_SYSTEM.md` (tokens, IBM Plex, shell and rail
   navigation, mobile menu, shape+word+colour marks) and migrate existing pages incrementally.
4. **Phase 4 — Project management** (largely exists; close gaps found against the spec).
5. **Phases 5–8 — Learning and execution.** Content engine and first programming track → isolated runner
   service (threat-modelled first) → DSA → Secure Coding Academy with fix-the-code grading.
6. **Phases 9–13 — Security engine to spec.** Coverage table, data-flow graph UI, remediation workflow
   (edit → diff → review → apply → PATCH snapshot → retest), retest integration.
7. **Phases 14–21** — academies (web, API, AI), AI code review, project security, report types, CLI/CI
   completion, self-hardening and production audit.

The MVP vertical slice (register → project → code → scan → finding → evidence → data flow → understand →
fix → retest) is complete after Phases 1–3 plus the remediation workflow; everything after it builds on
that loop.

---

## 2. Decisions

| ID | Decision | Reason |
|---|---|---|
| D1 | Keep the existing backend architecture (FastAPI, SQLAlchemy, PostgreSQL job queue, subprocess analysis sandbox); improve it incrementally | It works (292 passing tests) and matches the spec's component model |
| D2 | OWASP Top 10 categories are derived from each finding's CWEs using the official per-category CWE lists (2025 current, 2021 historical); API 2023 and LLM 2026 mappings are curated per class, with LLM 2025 derived through the 2026 edition's published lineage | Verifiable, versioned, no reliance on memory; spec rule "never silently mix editions" |
| D3 | Evidence classes are computed server-side from what the evidence is, never taken from client-supplied labels | Imported results must not be able to claim test or AI verdicts |
| D4 | LEARNER is the lowest-ranked role; every role can learn and practise | Learners should not see organization projects unless added to them |
| D5 | The product owner's spec and protocol are stored verbatim in the repository | Continuity across sessions without reinterpretation |
| D6 | Keep schema-only tables for planned features; never surface them until implemented | Avoids churn in migrations; no fake features |

## 3. In-progress work (not committed)

Stashed as `stash@{0}` "wip-taxonomy-registry" (backend only) before the audit:
`securelens/taxonomy/` (registry.yml with all 20 official OWASP Top 10 CWE lists for 2025 and 2021,
API 2023, LLM 2026 + 2025 lineage, verified CWE parents), `findings/annotate.py` (evidence classes,
limitations, taxonomy per finding), enum changes (EvidenceClass, LEARNER, INCONCLUSIVE), catalog
rewrite, precise rule-level CWEs. Resume with `git stash pop`, then finish: retest INCONCLUSIVE,
reports/CLI/SARIF output, DB columns + migration, tests.

## 4. Current database schema (28 tables, Alembic 0001)

Identity: `organizations`, `users`, `memberships`, `sessions`, `api_keys` ·
Projects: `projects`, `project_members`, `repositories`, `snapshots` ·
Scans: `scans`, `scan_files`, `dependencies` ·
Findings: `findings`, `finding_occurrences`, `evidence`, `secret_findings`, `ai_analyses`*, `remediations`,
`retests`, `retest_results` ·
AI security*: `ai_targets`, `security_tests`, `test_runs`, `test_results` ·
Operations: `jobs`, `reports`*, `integrations`, `audit_logs`.
(* schema only — no code path uses it yet.)

## 5. API contracts (`/api/v1`, 53 endpoints)

* System: `GET /healthz`, `GET /readyz`, `GET /system/status`
* Auth: `GET /auth/status`, `POST /auth/bootstrap`, `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`,
  `POST /auth/change-password`
* Organizations: `GET|POST /organizations`, `GET|POST /organizations/{id}/members`,
  `PATCH|DELETE /organizations/{id}/members/{membership_id}`, `GET|POST /organizations/{id}/api-keys`,
  `DELETE /organizations/{id}/api-keys/{key_id}`, `GET /organizations/{id}/audit-logs`,
  `GET|PATCH /organizations/{id}/settings`
* Projects: `GET|POST /projects`, `GET|PATCH|DELETE /projects/{id}`, `GET|POST /projects/{id}/members`,
  `DELETE /projects/{id}/members/{user_id}`, `GET|POST /projects/{id}/repositories`,
  `DELETE /projects/{id}/repositories/{repository_id}`, `GET /projects/{id}/metrics`
* Scans (under `/projects/{id}`): `POST /uploads`, `POST /retests/upload`, `POST /scans`, `POST /scans/import`,
  `GET /scans`, `GET /scans/{scan_id}`, `POST /scans/{scan_id}/cancel`, `POST /scans/{scan_id}/rescan`,
  `GET /scans/{scan_id}/files`, `GET /scans/{scan_id}/file?path=`, `GET /scans/{scan_id}/findings`,
  `GET /scans/{scan_id}/dependencies`, `GET /scans/{scan_id}/report?format=`
* Findings: `GET /projects/{id}/findings`, `GET /projects/{id}/findings/{finding_id}`,
  `PATCH …/{finding_id}/status`, `PATCH …/{finding_id}/verification`
* Retests: `GET /projects/{id}/retests`, `GET /projects/{id}/retests/{retest_id}`
* Dashboard: `GET /dashboard/summary`

All 56 frontend call sites (54 JSON calls, 1 upload, 1 report download link) target one of these paths
(static check; payload shapes are covered only by backend tests so far). Not yet used by the UI:
`POST /auth/change-password` (the Account page is missing), `POST …/retests/upload`, `POST …/scans/import`.

## 6. Tests performed in this audit

| Check | Result |
|---|---|
| Backend `pytest` at the audited commit (SQLite) | 292 passed, 1 deprecation warning |
| Frontend `tsc -b --noEmit` | 2 errors (missing `pages/Account`, `pages/NotFound`) |
| Frontend unit / E2E tests | none exist |
| Frontend ↔ backend route comparison | all 56 call sites match an existing route |
| Placeholder / fake-behaviour search | none found in product code |

## 7. Files changed in this phase

Added: `SECURELENS_MASTER_SPEC.md`, `SECURELENS_EXECUTION_PROTOCOL.md`, `SECURELENS_PROGRESS.md`,
`README.md` (all at `securelens-ai/`). No product code changed.

## 8. Next phase

Phase 1 — Stabilisation: frontend build + test setup + commit; resume and finish the stashed taxonomy and
evidence work; CI workflow. Then Phase 2 — authentication.
