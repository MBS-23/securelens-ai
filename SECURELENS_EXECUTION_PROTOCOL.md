<!--
SECURELENS_EXECUTION_PROTOCOL.md — the product owner's execution rules, reproduced verbatim.
Received 2026-09-30. It governs HOW work on SecureLens AI is carried out in every session.
-->

SECURELENS AI — EXECUTION CONTROL PROTOCOL
The previous SecureLens AI Mega Master Prompt is the single source of truth.
Do not rewrite or reinterpret the product vision.
Do not reduce the scope simply because implementation is complex.
Do not attempt to build the entire platform in one response.
Work incrementally and preserve the architecture across sessions.
1. FIRST TASK — AUDIT BEFORE CODING
Before modifying code:

1. Inspect the complete existing repository.
2. Identify the current architecture.
3. Identify frontend technologies.
4. Identify backend technologies.
5. Identify database.
6. Identify authentication implementation.
7. Identify existing scanner implementation.
8. Identify existing AI implementation.
9. Identify existing learning modules.
10. Identify existing project functionality.
11. Identify incomplete features.
12. Identify duplicated functionality.
13. Identify security weaknesses.
14. Identify architectural debt.
15. Identify placeholder/mock functionality.
16. Identify dead routes/components.
17. Identify broken API contracts.
18. Identify incomplete database models.
19. Identify missing tests.
20. Identify deployment assumptions.

Do not immediately rewrite existing working functionality.
First understand what already exists.
2. CREATE A PROJECT STATUS REPORT
Before making major changes, produce:

```text
CURRENT ARCHITECTURE
CURRENT FEATURES
COMPLETED FEATURES
PARTIALLY COMPLETED FEATURES
BROKEN FEATURES
PLACEHOLDER FEATURES
SECURITY RISKS
TECHNICAL DEBT
MISSING FEATURES
RECOMMENDED IMPLEMENTATION ORDER

```

Then create a concise implementation roadmap.
3. PRESERVE EXISTING WORK
Do not destroy working features merely to make the architecture cleaner.
Before changing an existing subsystem:

1. Understand it.
2. Identify dependencies.
3. Determine whether it satisfies the master specification.
4. Improve it incrementally where practical.

Only perform major rewrites when there is a clear architectural reason.
4. IMPLEMENT ONE VERTICAL SLICE AT A TIME
Each implementation phase must produce a working result.
Preferred pattern:

```text
DATABASE
 ↓
BACKEND
 ↓
API
 ↓
FRONTEND
 ↓
TEST
 ↓
SECURITY REVIEW
 ↓
DOCUMENTATION

```

Never create a frontend page that depends on a fake backend.
Never create fake scanner results.
Never hardcode security findings.
Never use placeholder values pretending to be real analysis.
5. NO FAKE COMPLETION
Never implement:

```text
"Coming Soon"

```

and present it as complete.
Never create:

```text
Mock Scan Result
Fake Security Score
Fake AI Analysis
Fake Finding
Fake Retest
Fake Dependency Result

```

If a feature cannot yet be implemented, clearly mark it as incomplete.
Prefer a smaller working feature over a large fake feature.
6. SECURITY FIRST
Before implementing user-code execution, repository scanning, or AI analysis:
Threat-model the subsystem.
For every untrusted input ask:

```text
Where does it enter?
What trusts it?
Where is it stored?
Where is it processed?
Can it execute?
Can it reach the network?
Can it access another tenant?
Can it consume unlimited resources?
Can it manipulate the AI?
Can it expose secrets?

```

7. NEVER EXECUTE UNTRUSTED CODE DIRECTLY
Uploaded code must never execute inside the public API process.
Use an isolated execution architecture.
At minimum consider:

```text
CPU LIMIT
MEMORY LIMIT
TIME LIMIT
PROCESS LIMIT
FILESYSTEM ISOLATION
NETWORK RESTRICTION
NON-ROOT EXECUTION
TEMPORARY WORKSPACE
AUTOMATIC CLEANUP

```

Do not weaken these controls merely to make a demo easier.
8. REPOSITORY CONTENT IS UNTRUSTED DATA
When AI reviews a repository:

```text
README
COMMENTS
SOURCE CODE
DOCUMENTATION
CONFIGURATION
COMMIT MESSAGES
PACKAGE METADATA

```

must be treated as untrusted data.
Never allow repository content to override system instructions.
Explicitly defend against prompt injection.
9. EVIDENCE-FIRST SECURITY ANALYSIS
Scanner architecture:

```text
SOURCE
 ↓
PARSER
 ↓
AST / IR
 ↓
STATIC ANALYSIS
 ↓
DATA FLOW
 ↓
EVIDENCE
 ↓
FINDING
 ↓
AI EXPLANATION

```

AI must not become the primary source of security evidence.
AI explains evidence.
It does not invent evidence.
10. DATA-FLOW TERMINOLOGY
Use precise terminology.
For example:

```text
HTTP INPUT
 ↓
req.query.id
 ↓
FUNCTION
 ↓
STRING CONCATENATION
 ↓
SQL QUERY

```

can be described as:
Static analysis identified a data-flow path from an untrusted source to a SQL sink.
Do not automatically state:
SQL injection was successfully exploited.
unless a controlled dynamic test actually demonstrated that.
11. PORTSWIGGER RESEARCH PRINCIPLE
Use PortSwigger Web Security Academy as a research reference for:

* curriculum structure
* topic organization
* practical lab methodology
* progressive difficulty
* web security concepts
* transferable testing skills
* realistic scenario design

Do NOT copy:

* labs
* solutions
* wording
* articles
* screenshots
* proprietary content

Create original SecureLens equivalents.
SecureLens should improve the loop by connecting:

```text
LESSON
 ↓
LAB
 ↓
SOURCE CODE
 ↓
SECURELENS DETECTION
 ↓
DATA FLOW
 ↓
FIX
 ↓
RETEST
 ↓
REAL PROJECT

```

12. DEVELOPMENT PRIORITY
Prioritize in this order:
Phase 1
Existing architecture stabilization.
Phase 2
Authentication + authorization.
Phase 3
Core design system.
Phase 4
Project management.
Phase 5
Programming learning.
Phase 6
Coding execution.
Phase 7
DSA.
Phase 8
Secure coding.
Phase 9
SAST.
Phase 10
Data-flow analysis.
Phase 11
Finding/evidence system.
Phase 12
Remediation.
Phase 13
Retesting.
Phase 14
Web Security Academy.
Phase 15
API Security.
Phase 16
AI Security.
Phase 17
AI code review.
Phase 18
Project security.
Phase 19
Reports.
Phase 20
CLI/CI/CD.
Phase 21
SecureLens self-hardening.
13. IMPLEMENTATION RULE
For every feature:

```text
DESIGN
 ↓
IMPLEMENT
 ↓
TEST
 ↓
SECURITY REVIEW
 ↓
FIX
 ↓
DOCUMENT

```

Do not move to the next major subsystem until the current subsystem has a working vertical slice.
14. TESTING REQUIREMENT
Every important feature needs:
Unit tests
Integration tests
End-to-end tests where appropriate
Security tests
Regression tests
Every vulnerability fixed should become a regression test where practical.
15. UI REQUIREMENT
Do not generate generic AI dashboards.
Do not fill every screen with cards.
Do not use excessive:

* gradients
* glassmorphism
* neon
* glowing borders
* decorative 3D
* giant empty dashboards

The UI must communicate:

```text
WHERE AM I?
WHAT AM I LEARNING?
WHAT AM I BUILDING?
WHAT IS WRONG?
WHY IS IT WRONG?
HOW DO I FIX IT?
HOW DO I VERIFY IT?
WHAT SHOULD I DO NEXT?

```

16. CONTENT REQUIREMENT
Every security lesson must contain:

```text
CONCEPT
PREREQUISITES
WHY IT MATTERS
INSECURE EXAMPLE
DATA FLOW
ROOT CAUSE
IMPACT
SECURE EXAMPLE
FIX EXPLANATION
PRACTICE
LAB
TEST
RETEST
REFERENCE
VERSION
LIMITATIONS

```

17. VERSIONED SECURITY KNOWLEDGE
Before adding or changing OWASP/security taxonomy content:
VERIFY THE CURRENT OFFICIAL VERSION.
Do not rely on model memory for current taxonomy names.
Store:

```text
taxonomy
version
category
source
verification_date

```

18. COST CONTROL
Because this project is being developed using limited cloud-session credits:
Do not repeatedly regenerate entire repositories.
Do not repeatedly inspect unchanged files.
Do not rewrite complete files when a small patch is sufficient.
Prefer:

```text
TARGETED INSPECTION
 ↓
TARGETED PATCH
 ↓
TARGETED TEST

```

over:

```text
REGENERATE ENTIRE PROJECT

```

Preserve context efficiently.
19. SESSION MEMORY
At the end of every major implementation phase, produce:

```text
SECURELENS_PROGRESS.md

```

containing:

* current architecture
* completed features
* current database schema
* API contracts
* active components
* known issues
* security issues
* next phase
* decisions made
* files changed
* tests performed

This file becomes the continuation point for future Claude sessions.
20. DO NOT LOSE ARCHITECTURAL CONTINUITY
Before starting a new session:
Read:

```text
SECURELENS_MASTER_SPEC.md
SECURELENS_PROGRESS.md
README.md
architecture documentation
relevant test documentation

```

Then continue from the current implementation state.
Do not redesign the product from scratch.
21. WHEN SOMETHING IS UNCLEAR
Do not silently invent an architecture decision.
For important decisions:

1. identify the ambiguity
2. explain the available options
3. select the option that best matches the master specification
4. document the decision
5. continue

Avoid unnecessary clarification questions for trivial implementation decisions.
22. DEFINITION OF DONE
A feature is DONE only when:

```text
IMPLEMENTED
+
CONNECTED TO REAL BACKEND
+
TESTED
+
SECURITY REVIEWED
+
ERROR HANDLED
+
DOCUMENTED

```

A UI mockup is not a completed feature.
A scanner rule without tests is not complete.
An AI explanation without evidence binding is not complete.
A fix without retesting is not complete.
23. FINAL DEVELOPMENT PRINCIPLE
Build SecureLens as a real engineering product.
Do not optimize for:
"How many features can we generate?"
Optimize for:
"How much real functionality can we make correct, secure, testable, explainable, and maintainable?"
The final product must demonstrate:

```text
LEARN
→ BUILD
→ SCAN
→ UNDERSTAND
→ FIX
→ RETEST
→ SECURE
→ SHIP

```

That loop has priority over every decorative feature.
Now inspect the existing repository and begin with the Project Status Report before making major changes.
