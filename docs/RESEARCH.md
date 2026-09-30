# SecureLens AI — Research Notes (Phase 1)

Status: living document · Last verified: 2026-09-30 · Owner: SecureLens maintainers

This file records what was checked, where, and when. It is the source of truth
for the taxonomy versions SecureLens encodes and for how external platforms
informed (but did not supply) SecureLens content.

**Originality rule.** External platforms are studied for *learning design*
(structure, progression, measurement). No lesson text, lab description,
solution, problem statement or diagram from any of them is reproduced.
SecureLens explanations, code, labs, challenges and diagrams are written
independently. Where a lesson relies on a standard (OWASP, CWE, language
documentation) the lesson's metadata cites it.

---

## 1. Verified security taxonomies

Each entry below was checked against the primary source on the date shown.
SecureLens stores the version with every mapping and never mixes editions
silently; older editions are shown only when labelled *historical*.

### 1.1 OWASP Top 10:2025 — current (web applications)

Source: <https://top10.owasp.org/2025/en/> (official release site), verified 2026-09-30.

| ID | Category |
|---|---|
| A01:2025 | Broken Access Control |
| A02:2025 | Security Misconfiguration |
| A03:2025 | Software Supply Chain Failures |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Software or Data Integrity Failures |
| A09:2025 | Security Logging and Alerting Failures |
| A10:2025 | Mishandling of Exceptional Conditions |

Notes from the official A10 page: "Mishandling of Exceptional Conditions is a new
category for 2025"; notable CWEs include CWE-209, CWE-234, CWE-274, CWE-476, CWE-636.

**Historical:** OWASP Top 10:2021 mappings remain in the catalog as
`owasp_top10_2021` and are labelled "historical" wherever shown.

### 1.2 OWASP Top 10 for LLM Applications 2026 — current (LLM applications)

Source: the official PDF "OWASP Top 10 for LLM Applications 2026, Version 2026,
August 4th, 2026", linked from <https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/>
(licensed CC BY-SA 4.0), table of contents and "What's New" table read 2026-09-30.

| ID | Entry | Change from 2025 |
|---|---|---|
| LLM01:2026 | Prompt Injection | unchanged |
| LLM02:2026 | Sensitive Information Disclosure | unchanged |
| LLM03:2026 | Excessive Agency | was LLM06:2025 |
| LLM04:2026 | Supply Chain | was LLM03:2025 |
| LLM05:2026 | Data and Model Poisoning | was LLM04:2025 |
| LLM06:2026 | Unbounded Consumption | was LLM10:2025 |
| LLM07:2026 | Misinformation | was LLM09:2025 |
| LLM08:2026 | Hidden Context Exposure | renamed and re-scoped from LLM07:2025 System Prompt Leakage |
| LLM09:2026 | Vector and Embedding Weaknesses | was LLM08:2025 |
| LLM10:2026 | Improper Output Handling | was LLM05:2025 |

The 2026 document's framework appendix references the OWASP Top 10 for Agentic
Applications (ASI, 2026, announced 2025-12-09), MITRE ATLAS v2026.06 and
CWE 4.20. SecureLens does not yet encode ASI identifiers; agentic topics map to
LLM03:2026 Excessive Agency until the ASI list is verified and added.

**Historical:** the 2025 edition (still shown on <https://genai.owasp.org/llm-top-10/>)
is kept as `owasp_llm_2025`. Secondary sources disagree about 2026 (one blog
mixes 2023 names), which is exactly why SecureLens pins the edition it cites.

### 1.3 OWASP API Security Top 10:2023 — current (APIs)

Source: <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>, verified 2026-09-30
(no newer edition published).

API1 Broken Object Level Authorization · API2 Broken Authentication ·
API3 Broken Object Property Level Authorization · API4 Unrestricted Resource Consumption ·
API5 Broken Function Level Authorization · API6 Unrestricted Access to Sensitive Business Flows ·
API7 Server Side Request Forgery · API8 Security Misconfiguration ·
API9 Improper Inventory Management · API10 Unsafe Consumption of APIs

### 1.4 CWE

Individual CWE identifiers are cited per rule and per lesson with a link to
`https://cwe.mitre.org/data/definitions/<id>.html`. The catalog references the
weakness name as published; SecureLens does not invent CWE IDs and leaves the
field empty when no CWE fits.

### 1.5 Mapping policy

* Every vulnerability class carries `owasp_top10_2025` (current) and, where it
  existed, `owasp_top10_2021` (historical).
* AI classes carry `owasp_llm_2026` (current) and `owasp_llm_2025` (historical).
* API classes carry `owasp_api_2023`.
* A mapping is omitted when no category fits (for example memory-safety classes
  have no OWASP Top 10 web category; CWE is the reference taxonomy there).
* Reports print the taxonomy editions they used.

---

## 2. Reference platforms studied (learning design only)

Observations are from public pages, general knowledge of each platform's
published format, and — for PortSwigger — the live topic index. They are not a
comprehensive review and are not endorsements.

### 2.1 PortSwigger Web Security Academy

Checked <https://portswigger.net/web-security/all-topics> on 2026-09-30.

* **Structure.** Topics grouped as *server-side* (SQL injection, authentication,
  path traversal, command injection, business logic, information disclosure,
  access control, file upload, race conditions, SSRF, XXE, NoSQL injection,
  API testing, web cache deception), *client-side* (XSS, CSRF, CORS,
  clickjacking, DOM-based, WebSockets) and *advanced* (insecure
  deserialization, Web LLM attacks, GraphQL, SSTI, web cache poisoning, Host
  header, request smuggling, OAuth, JWT, prototype pollution, essential skills).
* **Pedagogy.** Reading material first, then practical labs; server-side topics
  recommended for beginners; labs graded by level; learning paths for guided
  order; a *mystery lab* that hides the vulnerability category to test
  recognition rather than recall; an "essential skills" topic for transferable
  methodology.
* **What SecureLens adopts (as principles).** Teach → demonstrate → practice →
  test → reflect; server-side before client-side; graded difficulty that
  reflects real complexity; hidden-category assessments; a separate skills layer.
* **What SecureLens deliberately does differently.** Labs end with the learner
  *fixing* the code and proving the fix with tests and a rescan (PortSwigger
  labs are solved by exploiting). No leaderboard/Hall-of-Fame mechanics.

### 2.2 Hands-on security learning

* **TryHackMe** — guided "rooms" with in-browser machines and task questions;
  strong beginner onboarding and paths. Measures task completion.
* **Hack The Box Academy** — modules composed of sections with exercises and
  skills assessments; more depth, steeper. Measures module/section completion.
* **Hacker101 (HackerOne)** — free video lessons plus a CTF; oriented towards
  bug bounty hunting.
* **Videwan** (<https://videwan.com>) — describes itself as "a hands-on
  application security learning platform where learners practice, solve
  real-world labs, and build secure coding skills" (public privacy page).

Observed gap: these platforms train *attacking* or *recognising* flaws in
prepared environments. The step from "I exploited it in a lab" to "I found,
fixed and verified it in my own code" is left to the learner.

### 2.3 Developer secure-coding training

* **SecureCodingHub** (<https://www.securecodinghub.com/>) — organisation-focused
  developer training that ties assignments to compliance frameworks
  (e.g., ISO 27001 control evidence) with per-team completion and per-topic CWE
  coverage.
* **Secure Code Warrior, SecureFlag** — enterprise platforms with hands-on
  labs, learning paths, assessments and competitions.

Observed gap: training content is separate from the organisation's real code
and scan results; the loop from a real finding back to a lesson and forward to a
verified fix is rarely closed in one product.

### 2.4 Programming education and practice

* **GeeksforGeeks, TutorialsPoint, W3Schools, Scaler Topics** — tutorial
  articles with examples (W3Schools adds "Try it" editors). Broad coverage,
  quick reference; security is usually a separate section, not woven in.
* **LeetCode, CodeChef** — problem sets with online judges, test cases,
  submissions and contests. Excellent for practice volume; teaching of
  *patterns* and *why* is left to editorials and the community, and security is
  out of scope.

Observed gap: learners practise algorithms and syntax without ever seeing how
the same code becomes vulnerable, and security learners often lack the
programming foundation to understand why a fix works.

---

## 3. What SecureLens is for, given the landscape

No surveyed product connects all of: learning to program, practising
DSA, building a real project, finding vulnerabilities in *that* code with
evidence, understanding the data flow, fixing it, and proving the fix by
retest — for web, API and AI applications. That connection is the SecureLens
differentiator:

```
PROGRAMMING + DSA + SOFTWARE DEVELOPMENT + SECURE CODING + WEB/API SECURITY
+ AI SECURITY + REAL PROJECTS + EVIDENCE-BASED ANALYSIS + REMEDIATION + RETEST
```

## 4. Open research items

| Item | Status |
|---|---|
| OWASP Top 10 for Agentic Applications (ASI) 2026 identifiers | not yet verified — not encoded |
| OWASP ASVS 5.0 requirement mapping for project security requirements | planned |
| MITRE ATLAS technique references for AI labs | planned |
| Current free-tier limits of candidate hosting providers | to be checked at deployment time (limits change) |
