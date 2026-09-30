#!/usr/bin/env bash
# Record a narrated walkthrough of the running platform: video + screenshots.
# Uses a fresh, throwaway database and the real demo code in examples/; nothing
# touches your normal local data.   scripts/demo.sh [output-dir]   (default docs/demo)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/backend/.venv/bin/python"
[ -x "$PY" ] && [ -d "$ROOT/frontend/node_modules" ] || { echo "Run scripts/setup-local.sh first."; exit 1; }
OUT="$(mkdir -p "${1:-$ROOT/docs/demo}" && cd "${1:-$ROOT/docs/demo}" && pwd)"
WORK="$(mktemp -d)"
API_PORT=8790
WEB_PORT=4290
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

export SECURELENS_DATABASE_URL="sqlite:///$WORK/demo.db"
export SECURELENS_SECRET_KEY="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(48))')"
export SECURELENS_STORAGE_DIR="$WORK/storage"
mkdir -p "$SECURELENS_STORAGE_DIR"

echo "==> Demo code archives"
"$PY" - "$ROOT/examples" "$WORK" <<'EOF'
import pathlib, sys, zipfile
examples, work = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
for src, name in ((examples / "vulnerable-shop", "vulnerable-shop.zip"),
                  (examples / "retest-demo" / "before", "payments-api-v1.zip"),
                  (examples / "retest-demo" / "after", "payments-api-v2.zip")):
    with zipfile.ZipFile(work / name, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src.rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                z.write(p, p.relative_to(src))
EOF

echo "==> Starting a throwaway stack (API :$API_PORT, worker, dashboard :$WEB_PORT)"
(cd "$ROOT/backend" && "$PY" -m securelens.manage migrate >/dev/null)
(cd "$ROOT/backend" && exec "$PY" -m uvicorn securelens.main:app --host 127.0.0.1 --port "$API_PORT" --log-level warning) & pids+=($!)
(cd "$ROOT/backend" && exec "$PY" -m securelens.worker >"$WORK/worker.log" 2>&1) & pids+=($!)
(cd "$ROOT/frontend" && npm run build --silent >/dev/null && SECURELENS_API_URL="http://127.0.0.1:$API_PORT" \
  exec ./node_modules/.bin/vite preview --host 127.0.0.1 --port "$WEB_PORT" --strictPort >"$WORK/web.log" 2>&1) & pids+=($!)
for _ in $(seq 1 90); do
  curl -fsS "http://127.0.0.1:$WEB_PORT/" >/dev/null 2>&1 && curl -fsS "http://127.0.0.1:$API_PORT/api/v1/healthz" >/dev/null 2>&1 && break
  sleep 1
done

echo "==> Recording the walkthrough"
(cd "$ROOT/frontend" && npx playwright install chromium >/dev/null)
node "$ROOT/scripts/demo/walkthrough.mjs" "$WORK" "$OUT" "http://127.0.0.1:$WEB_PORT"
