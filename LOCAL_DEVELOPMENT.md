# Continuing SecureLens AI locally

Use this when development moves from the cloud session to your own computer
(for example when cloud credits run out). Everything needed is in this
repository (`MBS-23/securelens-ai`); nothing depends on the cloud container.

## Quick start

```bash
git clone https://github.com/MBS-23/securelens-ai.git
cd securelens-ai
scripts/setup-local.sh        # once: venv, packages, private .env.local, database
scripts/run-local.sh          # API :8000, scan worker, dashboard http://localhost:5173
scripts/run-local.sh --test   # every test suite
```

The sections below explain each step.

## 1. Requirements

| Tool | Version | Notes |
|---|---|---|
| Git | any recent | |
| Python | 3.11+ | backend, CLI, worker |
| Node.js | 20.19+ | dashboard |
| PostgreSQL | 16 (optional) | SQLite works for development |
| OS | macOS or Linux; **Windows via WSL2** | the scan sandbox uses POSIX process limits (`resource`, `setsid`), so the backend does not run on native Windows |

## 2. Get the code

```bash
git clone https://github.com/MBS-23/securelens-ai.git
cd securelens-ai
```

## 3. Backend

```bash
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[server,dev]"
pytest                                   # 292 tests at the last cloud run
```

Run the API and worker (development, SQLite):

```bash
export SECURELENS_DATABASE_URL=sqlite:///./securelens.db
export SECURELENS_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
securelens-manage migrate
uvicorn securelens.main:app --port 8000 &
securelens-worker &
```

## 4. Dashboard

```bash
cd ../frontend
npm ci
npm run typecheck && npm test            # 29 unit tests
npx playwright install chromium          # once, for end-to-end tests
npm run e2e                              # 5 E2E tests; starts its own API + build
npm run dev                              # http://localhost:5173 (proxies /api to :8000)
```

The E2E config runs the backend with `SECURELENS_E2E_PYTHON` (default
`.venv/bin/python` inside `backend/`); set it if your virtual environment lives
elsewhere.

## 5. Resume the unfinished work

The taxonomy and evidence-class work was not finished in the cloud session. It
is saved as a patch (16 files, including the new `securelens/taxonomy/`
package) that applies cleanly to `main`:

```bash
git apply wip/taxonomy-evidence-wip.patch
```

What is left is listed in `SECURELENS_PROGRESS.md` §3 (retest INCONCLUSIVE,
report/CLI/SARIF output, database columns and Alembic `0002`, import
validation, tests). Delete `wip/` once the work is committed.

## 6. Continue with Claude Code on your computer

Open a terminal in the repository folder and start Claude Code there (`claude`),
or use the Claude Desktop app. To keep following along from the Claude app, run
`claude remote-control` in that folder instead. A good first message:

> Read SECURELENS_PROGRESS.md, SECURELENS_EXECUTION_PROTOCOL.md,
> SECURELENS_MASTER_SPEC.md and LOCAL_DEVELOPMENT.md, apply the WIP patch, and
> continue from the "Resume here" section of the progress file.

## 7. Optional: regenerate brand assets

Only needed if the logo geometry changes:

```bash
python3 -m venv /tmp/fontenv && /tmp/fontenv/bin/pip install fonttools
npm pack @fontsource/manrope@5 && tar -xzf fontsource-manrope-*.tgz
/tmp/fontenv/bin/python brand/tools/build_brand.py --font-dir package/files --out brand \
    --ts-out frontend/src/components/brand-paths.ts
node brand/tools/export_png.mjs
/tmp/fontenv/bin/python brand/tools/build_board.py --font-dir package/files && node brand/tools/export_board.mjs
```
