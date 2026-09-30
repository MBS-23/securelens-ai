# SecureLens AI — Architecture (Phase 2)

Status: v1 · 2026-09-30. Parts marked *(planned)* are designed but not yet
implemented; everything else exists in this repository and is covered by tests.

## 1. Runtime components and trust boundaries

```
                 Browser (React SPA, same origin, no secrets)
                        │  HTTPS, session cookie (HttpOnly, SameSite=Strict) + CSRF header
                        ▼
┌──────────────────────────────── public zone ───────────────────────────────┐
│ web (nginx: static SPA + /api reverse proxy, CSP, security headers)        │
│ api (FastAPI): authn/authz, tenants, projects, scans, findings,            │
│      remediation, learning content, progress, tutor gateway               │
│      – never parses or executes untrusted code                            │
└──────────────┬───────────────────────────────┬─────────────────────────────┘
               │ SQL (least-privilege role)     │ HTTP (internal network only, shared token)
               ▼                                ▼
      PostgreSQL (data)                ┌──────────── isolated zone ────────────┐
      storage volume (uploads,         │ runner: executes learner code, runs   │
      snapshots)                       │ challenge/lab tests and grading SAST  │
               ▲                       │ – no DB credentials, no internet,     │
               │ SQL                   │   non-root, read-only rootfs, tmpfs,  │
┌──────────────┴──────────── worker zone ┐ CPU/mem/pids/time limits,           │
│ worker: job queue consumer             │ per-run process limits (+ bubblewrap│
│  – SCAN: safe extraction / hardened    │   namespaces when available)        │
│    git clone → analysis in a sandboxed │ └──────────────────────────────────────┘
│    child process (no secrets, rlimits) │
│  – dependency lookup (OSV, allowlisted)│
│  – AI analysis (provider allowlisted)  │
│  – PR comments (planned)               │
└────────────────────────────────────────┘
```

Boundaries that matter:

1. **Browser ↔ API** — all authorization server-side; objects outside the
   caller's tenant/project return 404.
2. **API ↔ untrusted code** — the API only stores uploads. Parsing happens in
   the worker's sandboxed child process; execution happens only in the runner.
3. **Worker ↔ analysis child** — the child gets no environment secrets, no DB
   access, CPU/memory/file-size/file-count limits and a wall-clock kill.
4. **Runner** — the most dangerous component. It receives code + tests over an
   internal link, has no credentials, no route to the database or the internet,
   and executes each submission in a fresh temporary directory with process
   limits. In profile A (local) the runner can run *embedded* (child processes
   of the API host); public profiles require the separate runner and the API
   refuses to start otherwise.
5. **AI provider** — receives only structured evidence; repository content is
   passed as delimited data with explicit instructions that it is untrusted.
   Outputs are schema-validated and rendered as text.

## 2. Python packages (backend)

| Package | Responsibility |
|---|---|
| `securelens.scanners` | Application Security Engine: inventory, SAST (language-neutral IR + inter-procedural taint for Python, JS/TS, PHP, Java, C#, Go, C/C++), secrets, dependencies, external tool adapters |
| `securelens.findings` | Unified finding model, fingerprints, correlation, catalog, deterministic explanations, risk index, gate, retest comparison |
| `securelens.taxonomy` | Versioned taxonomy registry (OWASP Top 10 2025/2021-historical, API 2023, LLM 2026/2025-historical, CWE references) |
| `securelens.reporting` | JSON, SARIF 2.1.0, HTML, Markdown renderers; report types; scope/methodology/coverage/limitations |
| `securelens.remediation` | Diff generation and application, templates, remediation lifecycle |
| `securelens.academy` | Content engine: versioned content packs, validation, quality gates, tracks/lessons/challenges/labs/projects |
| `securelens.runner` | Isolated execution: language toolchains, limits, harness protocol, capability detection |
| `securelens.ai` | Provider abstraction (none / OpenAI-compatible / Anthropic), evidence-bound prompts, schema validation, tutor |
| `securelens.evaluation` *(planned)* | LLM security evaluation: controlled targets, test library, detectors |
| `securelens.cli` | `securelens` command (scan, findings, report, retest, push, init) |
| `securelens.worker` | Job queue, runner, sandbox for analysis |
| `securelens.api`, `services`, `models`, `schemas`, `core` | Web layer, business services, SQLAlchemy models, Pydantic schemas, config/security/audit |

## 3. Data model (PostgreSQL; SQLite for development/tests)

* **Identity & tenancy** — organizations (personal workspaces and teams),
  users, memberships (role per organization), sessions (hashed tokens), API
  keys (hashed, role-capped, project-scoped for low roles), password-reset and
  email-verification tokens (hashed, single use), MFA secrets and recovery codes.
* **Code security** — projects → repositories → immutable snapshots → scans →
  scan files / dependencies; findings (project-level identity by scoped
  fingerprint) → occurrences (per scan) → evidence; secret findings (masked +
  keyed hash only); remediations (diffs, lifecycle); retests and results; AI
  analyses; reports; jobs; integrations (secret *references* only); audit log.
* **Learning** — content items synced from versioned packs (tracks, modules,
  lessons, challenges, labs, project templates, paths) with metadata and
  quality-gate status; per-user state: lesson progress, challenge attempts
  (code, per-check results, verdict), hint unlocks, lab attempts, project
  enrollments and milestone submissions, skill progress.
* **AI security** — targets (secret references only), test library, runs,
  results.

History is append-only where it is evidence: occurrences, evidence, retest
results, remediation records, challenge attempts and audit logs are never
deleted by normal operations.

## 4. Key flows

**Scan.** Upload/clone → snapshot (safe extraction) → job → worker → sandboxed
analysis → dependency lookup → correlation → persist findings with evidence →
retest comparison with the previous scan → gate + risk → coverage table.

**Fix and retest.** Finding → edit in the browser (or accept a template/AI
suggestion) → unified diff → review → apply → new PATCH snapshot → retest scan
with the original as baseline → remediation VERIFIED / NOT_VERIFIED from the
retest result.

**Practice.** Challenge → learner code → API → runner (functional tests,
security tests, SecureLens static analysis on the submission) → PASS / PARTIAL /
FAIL with per-check evidence (DETERMINISTICALLY_VERIFIED for tests,
STATIC_ANALYSIS_FINDING for scanner results) → progress.

**Tutor.** Context (lesson/challenge/finding, learner code, hint level) →
evidence-bound prompt → provider → schema validation → rendered as text; the
unreleased solution is never part of the context.

## 5. Deployment profiles

| Profile | Shape | Notes |
|---|---|---|
| A — Local | `docker compose up` (web, api, worker, runner, postgres) or bare processes with SQLite | Runner may be embedded; optional local model via an OpenAI-compatible endpoint |
| B — Free-tier demo | web + api on one small host; worker + runner on a separate host/container with no public ingress | AI off by default; reduced limits; seeded demo content |
| C — Small production | Separate api, worker, runner, managed/volume PostgreSQL, backups | Runner on its own host; secrets from the platform's secret store |
| D — Scalable | Horizontal api/worker/runner pools, object storage for snapshots, shared rate limiting | Same containers; queue stays in PostgreSQL until load requires otherwise |

No provider is hard-coded. Free-tier limits are checked and documented at
deployment time because they change.

## 6. Cross-cutting

* **API versioning** — `/api/v1`; breaking changes get a new version.
* **Structured logging** — JSON logs with request IDs; secrets never logged.
* **Configuration** — environment variables (`SECURELENS_*`); production
  guards refuse insecure defaults.
* **Testing** — pytest (unit, integration, API, corpus, runner), vitest
  (frontend units), Playwright (end-to-end vertical slice), content quality
  gates in CI.
