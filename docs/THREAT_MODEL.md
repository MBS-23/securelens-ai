# SecureLens AI — Threat Model

Status: v1 · 2026-09-30 · Method: assets → actors → trust boundaries → threats
(STRIDE per boundary) → mitigations → residual risk. Every mitigation is marked
**[implemented]** (exists and is tested) or **[planned]** (designed, tracked).
This document is reviewed whenever a boundary changes.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Customer source code and snapshots | Confidential IP; may contain secrets |
| Findings, evidence, reports | Reveal where an application is weak |
| Credentials: passwords, sessions, API keys, MFA secrets | Account takeover |
| Server secrets: `SECURELENS_SECRET_KEY`, DB credentials, AI keys, integration tokens | Full compromise / third-party abuse |
| Learner data: progress, attempts, submitted code | Privacy |
| Content integrity (lessons, challenges, solutions) | Wrong security teaching is itself a vulnerability |
| Availability of workers and runner | Denial of service for every tenant |

## 2. Actors

Anonymous internet users · registered learners · organisation members of each
role · malicious tenants · abusive API clients · a malicious repository/archive
author · a malicious code comment or README author targeting the AI reviewer ·
a compromised dependency · a compromised AI provider response · an insider with
administrative access.

## 3. Trust boundaries

See [ARCHITECTURE.md §1](ARCHITECTURE.md): browser↔API, API↔storage/DB,
API↔worker (via queue), worker↔analysis child, API/worker↔runner, worker↔external
services (OSV, git hosts, AI provider).

## 4. Threats and mitigations

### 4.1 Authentication and sessions
| Threat | Mitigation |
|---|---|
| Credential stuffing / brute force | Per-IP login rate limit, account lockout after failures [implemented]; MFA (TOTP + recovery codes) [planned, Phase 5] |
| Password database theft | Argon2id, rehash on parameter change [implemented] |
| Session theft | Opaque 256-bit tokens stored as SHA-256; HttpOnly, SameSite=Strict, Secure (enforced in production), idle and absolute expiry, revocation on password change [implemented] |
| CSRF | HMAC-bound double-submit token required on every state-changing cookie request [implemented] |
| Account enumeration | Uniform login errors and timing (dummy hash) [implemented]; reset request always returns the same response [planned] |
| Account recovery abuse | Single-use, hashed, short-lived reset tokens; sessions revoked on reset [planned] |

### 4.2 Authorization and tenancy
| Threat | Mitigation |
|---|---|
| IDOR/BOLA across tenants or projects | Every object loaded through a project/tenant check; inaccessible objects return 404 [implemented, tested] |
| Privilege escalation via roles | Role-rank checks; admins cannot grant OWNER/ADMIN; API keys cannot exceed the creator's role; low-role keys must be project-scoped [implemented, tested] |
| Security decisions by the wrong role | False positive / accepted risk / manual resolve require SECURITY_ANALYST+ with a reason; all audited [implemented, tested] |

### 4.3 Uploads, archives and repositories
| Threat | Mitigation |
|---|---|
| Zip Slip / path traversal | Member paths normalised; absolute, drive-letter and `..` paths rejected [implemented, tested] |
| Symlink / hard link / device entries | Skipped; symlinks removed after git clone [implemented, tested] |
| Decompression bombs, huge extraction, file-count exhaustion | Declared and actual byte limits, per-entry ratio check, entry-count limit [implemented, tested] |
| Oversized or unbounded uploads | Content-Length required and bounded before spooling; streaming size check; chunked bodies refused [implemented, tested] |
| Executable uploads | Binary/executable extensions rejected; extracted files written without execute bits [implemented] |
| Malicious git URLs | HTTPS + host allowlist, no credentials in URLs, hooks disabled, `file`/`ext` protocols disabled, no submodules, `core.symlinks=false`, branch name validation [implemented, tested] |
| Install/lifecycle scripts | Never run during analysis; the analyser parses files only [implemented] |
| Parser DoS / crafted source | Analysis in a child process with CPU, memory, file-size and open-file limits and a wall-clock kill; per-file size cap [implemented, tested] |

### 4.4 Untrusted code execution (runner)
| Threat | Mitigation |
|---|---|
| Code escapes to read secrets or the DB | Runner holds no credentials and has no route to the DB; children get an empty environment [planned, Phase 7] |
| Network abuse (SSRF, scanning, exfiltration) | Runner network has no internet egress; bubblewrap network namespace when available [planned, Phase 7] |
| Resource exhaustion (fork bomb, memory, disk, CPU) | RLIMIT_NPROC/AS/CPU/FSIZE/NOFILE, wall timeout with process-group kill, output caps, tmpfs quotas; container cpu/mem/pids limits [planned, Phase 7] |
| Container escape | Non-root user, read-only root filesystem, all capabilities dropped, no-new-privileges, default seccomp; separate host for public profiles [planned, Phase 26] |
| Solution leakage | Solutions and hidden tests stay server-side; never shipped to the browser; tutor never receives unreleased solutions [planned, Phase 11/15] |

### 4.5 Secrets
| Threat | Mitigation |
|---|---|
| Secrets in scanned code shown in UI/reports | Masked everywhere (`AKIA************MPLE`); only keyed hashes stored; file viewer re-redacts [implemented, tested] |
| Server secrets in the database | Integration config holds only `env:SECURELENS_INTEGRATION_*` references; AI keys from environment [implemented] |
| Secrets in logs | Validation errors never echo input; tokens masked in git errors [implemented] |

### 4.6 Web application
| Threat | Mitigation |
|---|---|
| XSS in the dashboard | React escaping; no `dangerouslySetInnerHTML` with data; code rendered as text in Monaco; links restricted to http(s) [implemented]; SPA CSP via nginx [planned, Phase 26] |
| XSS via reports | Jinja2 autoescape, no scripts, restrictive CSP meta and header, Markdown escaping for PR comments [implemented, tested] |
| Terminal escape injection via CLI output | Control characters and bidi overrides stripped [implemented, tested] |
| SSRF via AI targets / git / integrations | Host allowlists; AI target SSRF guard with DNS pinning [planned, Phase 16] |
| Clickjacking | `X-Frame-Options: DENY`, `frame-ancestors 'none'` [implemented] |

### 4.7 AI components
| Threat | Mitigation |
|---|---|
| Prompt injection from repository content (README, comments, strings) | Content passed as delimited data with explicit "data, not instructions" framing; model has no tools; outputs schema-validated [planned, Phase 15] |
| AI output injection (HTML/markdown/links in explanations) | Rendered as plain text; no raw HTML; links only from the reviewed catalog [planned, Phase 15] |
| AI invents evidence, CVEs or results | Structured evidence in, schema out; fields not grounded in supplied evidence are rejected; AI results labelled AI_ASSISTED_ANALYSIS and never auto-confirm [planned, Phase 15] |
| Cost exhaustion | AI disabled by default; per-user rate limits; token limits; caching by context hash [partly implemented: disable mode, token limit setting] |
| System instruction exposure | No secrets in prompts; tests for extraction attempts [planned, Phase 16] |

### 4.8 Availability and abuse
| Threat | Mitigation |
|---|---|
| Request floods | Per-IP rate limiting (in-process) [implemented]; shared limiter for multi-instance deployments [planned, profile D] |
| Queue flooding | Per-user scan and run limits [planned]; jobs have attempt limits and stale recovery [implemented] |

## 5. Residual risks (accepted for v1, documented)

* In-process rate limiting is per API instance; profile D needs a shared store.
* Profile A's embedded runner shares a host with the API; acceptable only for
  single-user local use and flagged in System status.
* Static analysis has false negatives and false positives by nature; the
  product says so in every report.
* Content correctness depends on human review, which is tracked per lesson.

## 6. Verification

Security tests live in `backend/tests` (auth/RBAC/tenancy, ingestion, sandbox,
scan API, reporting escaping, CLI escaping). The production audit (Phase 27)
re-runs SecureLens against itself, audits dependencies, scans for secrets and
reviews this model.
