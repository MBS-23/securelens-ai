# SecureLens AI — Product Specification

**SecureLens AI — Application Security, AI Security, Secure Coding & Developer Learning Platform**

> Learn software. Build software. Understand how software breaks. Secure it. Prove the fix. Build again.

Status: v1 specification (Phase 1) · 2026-09-30 · Companion documents:
[RESEARCH.md](RESEARCH.md) · [ARCHITECTURE.md](ARCHITECTURE.md) ·
[THREAT_MODEL.md](THREAT_MODEL.md) · [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md)

---

## 1. What SecureLens is — and is not

SecureLens teaches how software is built, how it becomes vulnerable, how to
recognise the vulnerability, how to fix it, how to verify the fix, and how to
build secure software yourself — and it provides the professional tooling
(analysis, evidence, remediation, retest, gates, reports) to do that on real
code.

It is **not** a generic vulnerability scanner, coding-puzzle site, security
course catalogue or chatbot. The scanner is an engine *underneath* the learning
and building experience, not the product itself.

**Boundary.** SecureLens is fully independent of ShadowPortX: no shared code,
architecture, database, APIs, branding or network/reconnaissance features.
SecureLens performs **no** port scanning, network reconnaissance, asset or
topology discovery, DNS reconnaissance, GeoIP mapping or external
attack-surface discovery.

## 2. The product loop

```
LEARN → UNDERSTAND → CODE → BUILD → BREAK SAFELY → DETECT → TRACE → EXPLAIN
      → FIX → VERIFY → RETEST → SECURITY GATE → SHIP → LEARN AGAIN
```

Every surface must reinforce this loop. Concretely, every finding links to the
lesson that explains it and to a practice challenge; every lesson ends in
practice that is verified by tests and a scan; every project milestone ends in
a scan, a fix and a retest.

## 3. Six connected pillars

| Pillar | What the learner gets | How it connects |
|---|---|---|
| 1 Programming foundation | From "what is a program" to modules, files, testing, HTTP, databases | Code examples later reused in security lessons |
| 2 DSA & problem solving | Patterns (not memorised answers), complexity, visual dry runs, judged practice | Same execution engine and editor as fix-the-code |
| 3 Software development | Real projects with requirements, architecture, milestones, tests | Milestones are scanned and gated |
| 4 Application & API security | Web and API security curricula, labs, secure coding academy | Lessons are linked from real findings |
| 5 AI / LLM security | LLM, RAG, agent and tool security; controlled evaluation labs | Static AI-code rules and dynamic evaluations produce findings |
| 6 Secure code review & security engineering | SAST, data flow, secrets, dependencies, remediation, retest, gates, reports, CLI/CI | The evidence engine behind everything |

Example connected path: *Python fundamentals → functions → files → web
development → API development → authentication → SQL → SQL injection → secure
database access → secure code review → build a secure project.*

## 4. Users and levels

| Level | Learner | Typical entry point |
|---|---|---|
| 0 | Absolute beginner | Programming foundation, first lesson |
| 1 | Beginner programmer | Language track, fundamentals practice |
| 2 | Intermediate developer | HTTP/APIs/databases, first project |
| 3 | Advanced developer | Concurrency, architecture, advanced projects |
| 4 | Security learner | Web security foundation, essential skills |
| 5 | AppSec learner | Server-/client-side topics, labs, code review |
| 6 | AI-security learner | AI security academy, LLM evaluations |
| 7 | Developer / security engineer | Professional mode, projects, CI/CD, reports |

Every lesson declares prerequisites; advanced material never assumes
programming knowledge that has not been established.

Organisation roles (server-enforced): OWNER, ADMIN, SECURITY_ANALYST,
DEVELOPER, LEARNER, VIEWER. Learning features (lessons, practice, labs,
progress, tutor) belong to the individual user and are available to every
signed-in account; organisation roles govern shared projects, scans and
findings.

## 5. Information architecture

Primary navigation (items appear only when the feature behind them works):

```
Dashboard · Learn · Practice · Build · Scan · Findings · Projects
· AI Security · Reports · Progress · Settings
```

Learn contains: Programming · DSA · Software development · Secure coding ·
Web security · API security · AI security · Code review · Labs.

**The dashboard answers**: What am I learning? What should I do next? What did
I build? What did I find? What did I fix? What remains? What should I learn
next? It shows no vanity numbers.

## 6. Core experiences

### 6.1 Concept lessons
`WHAT → WHY → HOW → EXAMPLE → VISUALISATION → PRACTICE → COMMON MISTAKE →
SECURE VERSION → REAL PROJECT → ASSESSMENT`

### 6.2 Security lessons (Secure Coding Academy)
`WHAT → WHY → INSECURE CODE → LINE-BY-LINE → DATA FLOW → ROOT CAUSE → IMPACT →
SECURE CODE → WHY THE FIX WORKS → COMMON MISTAKES → PRACTICE → AUTOMATED TEST →
REMEDIATION → RETEST → REFERENCE`, with switchable views **Insecure · Secure ·
Diff · Data flow · Explanation · Scanner result · Fix · Retest**.

### 6.3 Fix-the-code challenges
The learner receives vulnerable code and edits it. SecureLens runs, in isolation:
**functional tests + security tests + SecureLens static analysis**, and returns
**PASS** (all three pass), **PARTIAL** (some pass) or **FAIL**, listing each
check. Help is progressive: Hint 1 → Hint 2 → Hint 3 → Explanation → Solution.
Solutions live only on the server and are released after a pass or after the
attempt threshold.

### 6.4 Labs and mystery assessments
Lab flow: `LESSON → KNOWLEDGE CHECK → GUIDED DEMO → CONTROLLED LAB → HINT →
ATTEMPT → EVIDENCE → EXPLANATION → MITIGATION → RETEST → REFLECTION`. Labs are
original, controlled applications; their "exploit" checks run in the isolated
runner against the lab code, never against external systems. Difficulty:
FOUNDATION · APPRENTICE · PRACTITIONER · ADVANCED · EXPERT, reflecting
prerequisites, steps, ambiguity and reasoning. A **mystery assessment** hides
the category: observe → hypothesise → inspect → test → collect evidence →
identify root cause → remediate → verify.

### 6.5 Findings (professional and learning views)
Each finding page: **Overview · Understand · Evidence · Data flow · Source code
· Impact · Fix · Practice · Verify · Reference**. The data-flow graph
(`SOURCE → INPUT → FUNCTION → TRANSFORMATION → SINK`) is clickable and opens
the exact file and line. Learning mode leads with explanation and
secure/insecure examples; Professional mode leads with evidence, severity,
confidence, CWE, OWASP (versioned), remediation, retest and SARIF/CI data.

### 6.6 Remediation and retest
`Suggestion (template or AI) → Diff → Developer review → Apply → Tests →
Security scan → Retest`. Fixes are diff-based, reviewable, reversible and
testable. Applying a fix creates a new immutable snapshot and a retest scan; a
suggestion never resolves a finding. Retest outcomes: RESOLVED · STILL_OPEN ·
REGRESSION · NEW · NOT_REPRODUCED · NOT_TESTED · INCONCLUSIVE. History is never
deleted.

### 6.7 Projects (Build)
Beginner (CLI password manager, expense tracker, URL shortener, notes app, REST
API) · Intermediate (auth service, blog, e-commerce backend, task API, file
upload, chat) · Advanced (secure SaaS, multi-tenant API, payment-style mock,
document management, RAG app, AI agent, security dashboard). Each has
requirements, architecture, database design, API spec, starter repository,
milestones, tests, security requirements, deployment guide and a final security
review. Modes: STARTER · GUIDED · INDEPENDENT · SECURITY REVIEW. Every milestone:
`BUILD → TEST → SCAN → UNDERSTAND → FIX → RETEST → GATE`. Completed projects
produce an evidence-based **portfolio** page (what was built, found, fixed,
tested) that never inflates skill claims.

### 6.8 AI tutor
Knows the current course, lesson, language, code, challenge, finding and
milestone. "I don't understand" yields: simple explanation → analogy → tiny
example → visual flow → code → practice question. Hint-first in practice mode;
solutions are gated server-side (the model never receives an unreleased
solution). It never invents CVEs, documentation, API behaviour, test results or
source locations and says when verification is required.

### 6.9 Progress
Tracks lessons, labs, challenges, categories, secure fixes, retests, projects,
DSA patterns, languages and skills; shows skill maps labelled as *learning
progress, not professional competence*. Rewards understanding and verified
fixes, not grinding. Never "you are 87% secure"; instead "you remediated 18 of
21 findings in this project".

## 7. Evidence model (applies to scanner, UI, reports, AI and lessons)

| Evidence class | Meaning |
|---|---|
| DETERMINISTICALLY_VERIFIED | A reproducible test with an unambiguous expected result passed/failed (e.g., a challenge's security test) |
| STATIC_ANALYSIS_FINDING | A scanner matched a security-relevant pattern or traced a data flow in source code |
| DYNAMIC_TEST_RESULT | A controlled test produced observable behaviour (lab harness, LLM evaluation) |
| AI_ASSISTED_ANALYSIS | An AI model interpreted evidence; never confirmed automatically |
| USER_REPORTED | Supplied by a person |
| INCONCLUSIVE | Insufficient evidence either way |
| FALSE_POSITIVE | Reviewed and determined not to be the claimed issue |

**Static data flow is not observed exploitation.** "Static analysis identified
a data-flow path from HTTP input to `eval()`" never becomes "arbitrary code
execution was observed" unless a dynamic test observed it.

Finding statuses: OPEN · IN_PROGRESS · RESOLVED · REOPENED · FALSE_POSITIVE ·
ACCEPTED_RISK · INCONCLUSIVE.

**Precise language (phrasebook).** Allowed: "No matching issue detected by the
configured scanners." · "Static analysis identified a potential
vulnerability." · "Static analysis identified a data-flow path to a dangerous
operation." · "Dynamic testing produced observable evidence." · "Manual
verification is recommended." · "Runtime testing was not performed." · "The
analysed scope did not include infrastructure." · "Result is inconclusive."
Forbidden: "100% secure", "zero vulnerabilities", "unhackable", "guaranteed",
"complete security", or claiming language support that does not exist.

**Scan coverage** is printed with every scan and report, e.g.:

```
Source analysis        COMPLETE      SecureLens SAST        COMPLETE
Secret detection       COMPLETE      Dependency inventory   COMPLETE
Dependency lookup      SKIPPED       Runtime testing        NOT PERFORMED
External scanners      UNAVAILABLE   Infrastructure         NOT ASSESSED
Manual review          REQUIRED
```

**Risk index.** "The SecureLens Risk Index is a SecureLens-specific
prioritisation mechanism and is not CVSS." Its formula and weights are shown
wherever the number appears.

## 8. Language capability matrix

Capability levels: L1 syntax/execution · L2 learning content · L3 coding
challenges · L4 DSA · L5 project building · L6 security analysis · L7
secure-code (data-flow) analysis. The product computes the *available* levels
at runtime (e.g., execution requires the toolchain on the runner) and shows
them honestly. Target for v1:

| Language | L1 exec | L2 | L3 | L4 | L5 | L6 | L7 |
|---|---|---|---|---|---|---|---|
| Python | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| JavaScript | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| TypeScript | ✓ (type stripping) | ✓ | ✓ | ✓ | partial | ✓ | ✓ |
| Java | ✓ | ✓ | ✓ | ✓ | partial | ✓ | ✓ |
| C | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ (memory model) |
| C++ | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ (memory model) |
| C# | toolchain-dependent | ✓ | toolchain-dependent | toolchain-dependent | — | ✓ | ✓ |
| PHP | ✓ | ✓ | ✓ | ✓ | partial | ✓ | ✓ |
| Go | ✓ | ✓ | ✓ | ✓ | partial | ✓ | ✓ |
| Kotlin, Ruby, Rust, Swift, Dart, Scala | future | — | — | — | — | secrets only | — |

"✓" in this table is a target; the running product reports the actual state
per deployment (for example C# execution is unavailable when no .NET SDK is
installed on the runner).

## 9. Content evidence model and quality gates

Every lesson, lab and challenge carries metadata: `source`, `source_url`,
`taxonomy`, `taxonomy_version`, `review_date`, `technical_owner`,
`confidence`, `limitations`, `version`.

Quality gates:

| Gate | How it is checked |
|---|---|
| Code execution | Automated: every runnable example and solution runs in the runner in CI |
| Secure/insecure comparison | Automated: SecureLens detects the insecure example and does not flag the secure one |
| Challenge integrity | Automated: starter code fails the security tests; the reference solution passes all checks |
| Taxonomy/version | Automated: every mapping exists in the verified taxonomy registry |
| Source metadata | Automated: required fields and URLs present |
| Technical correctness, beginner readability, security review | Human review — shown as *pending* until a maintainer records it |

A lesson is never presented as reviewed merely because it was generated; the UI
shows each gate's status.

## 10. Security of SecureLens itself

SecureLens is a high-value target. Uploaded repositories, archives, code,
comments, README files, prompts and AI outputs are hostile data. See
[THREAT_MODEL.md](THREAT_MODEL.md). Non-negotiables: server-side authorization
with tenant isolation; no execution of untrusted code outside the isolated
runner; safe archive handling; no install/lifecycle scripts during analysis;
secrets never displayed or logged in full; repository content is **data, not
instructions** for any AI component; model API keys never reach browsers.

## 11. Deployment principles

Free-first and local-first: Docker Compose with PostgreSQL, a local scanner,
local labs and challenge execution, optional local AI. Profiles: A local ·
B free-tier public demo · C small production · D scalable. Dangerous execution
workers never share a host with the public API in B–D. Provider-agnostic; no
promise that any free tier remains free.

## 12. Build order and status

MVP vertical slice first:
`REGISTER → CREATE PROJECT → ADD CODE → SCAN → FINDING → EVIDENCE → DATA FLOW →
UNDERSTAND → FIX → RETEST → PASS / REMAINING ISSUE`, demonstrated on the
intentionally vulnerable **vulnerable-shop** example (never treated as a real
target). Then the curriculum expands phase by phase (phases 1–27, tracked in
the repository's task list and CHANGELOG).

## 13. Acceptance criteria

SecureLens is complete only when every item below is demonstrably true (each
maps to automated tests or a documented review): programming learning, DSA
learning, safe code execution, project building, vulnerable labs,
secure/insecure comparisons, web/API/AI security curricula, evidence-backed
findings, data-flow analysis, evidence-bound AI explanations, remediation,
retesting, security gates, reporting, authentication, authorization, tenant
isolation, safe handling of malicious uploads, isolated execution, CI/CD, CLI,
documentation, deployment, a security review of SecureLens itself, documented
limitations, versioned content, attributed research, no copied content, and no
false security claims.
