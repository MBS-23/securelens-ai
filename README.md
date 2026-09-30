# SecureLens AI

SecureLens AI is an independent platform for learning to build software securely and for finding,
understanding, fixing and re-testing vulnerabilities in real code:

```
LEARN → BUILD → SCAN → UNDERSTAND → FIX → RETEST → SECURE → SHIP
```

**Status:** early. The application-security engine, scan pipeline, findings, retests, reports, CLI and
API are implemented and tested. The web dashboard is being stabilised, and the learning platform, code
runner, remediation workflow and AI features are not built yet. `SECURELENS_PROGRESS.md` is the
authoritative, dated record of what works and what does not. SecureLens reports what its analysis found;
it never claims that code is completely secure.

## Documents

| File | Purpose |
|---|---|
| `SECURELENS_MASTER_SPEC.md` | The product specification, verbatim — what SecureLens must become |
| `SECURELENS_EXECUTION_PROTOCOL.md` | How the work is carried out (audit first, vertical slices, no fake features) |
| `SECURELENS_PROGRESS.md` | Current state, decisions, API contracts, schema, known issues, next phase |
| `LOCAL_DEVELOPMENT.md` | Continuing development on your own computer (setup, tests, resuming unfinished work) |
| `docs/ARCHITECTURE.md` · `docs/THREAT_MODEL.md` | Components, trust boundaries, threats and mitigations |
| `docs/PRODUCT_SPEC.md` · `docs/DESIGN_SYSTEM.md` · `docs/RESEARCH.md` | Condensed spec, UI rules, verified taxonomy sources |

## Layout

```
backend/    Python package `securelens`: API server, worker, scanners, findings, reports, CLI
frontend/   React web dashboard (talks only to the real API)
docs/       engineering documents
examples/   deliberately vulnerable demo code for scanning and retest demonstrations
```

## Quick start

```bash
git clone https://github.com/MBS-23/securelens-ai.git && cd securelens-ai
scripts/setup-local.sh      # once (macOS, Linux, or Windows via WSL2)
scripts/run-local.sh        # dashboard at http://localhost:5173
```

## Running it locally (manual steps)

Requirements: Python 3.11+, Node 20.19+ (dashboard), PostgreSQL 16 for a server deployment (SQLite works for
development).

```bash
# Backend and CLI
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -e ".[server,dev]"
securelens scan ../examples/vulnerable-shop       # exit code 1 when the security gate fails
securelens report --format html -o report.html

# API server + worker (development, SQLite)
export SECURELENS_DATABASE_URL=sqlite:///./securelens.db
export SECURELENS_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
securelens-manage migrate
uvicorn securelens.main:app --port 8000 &
securelens-worker &

# Dashboard (proxies /api to :8000)
cd ../frontend && npm install && npm run dev
```

Open the dashboard and complete the first-run setup, which creates the first organization and owner.

## Tests

```bash
cd backend && pytest            # set SECURELENS_TEST_DATABASE_URL to run against PostgreSQL
cd frontend && npm run typecheck
```

## Security notes

* Uploaded code is treated as untrusted data: it is parsed in a separate, resource-limited process and is
  never executed. Current isolation limits and planned hardening are listed in `SECURELENS_PROGRESS.md`
  and `docs/THREAT_MODEL.md`.
* Secrets come from environment variables only; detected secrets are masked everywhere.
* Report vulnerabilities in SecureLens itself privately to the repository owner rather than in a public
  issue.
