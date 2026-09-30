#!/usr/bin/env bash
# Start SecureLens AI locally: API (:8000), scan worker and dashboard (:5173).
# Ctrl+C stops all three.   scripts/run-local.sh --test   runs every test suite instead.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$ROOT/.env.local" ] || { echo "Run scripts/setup-local.sh first."; exit 1; }
set -a; . "$ROOT/.env.local"; set +a
PY="$ROOT/backend/.venv/bin/python"

if [ "${1:-}" = "--test" ]; then
  (cd "$ROOT/backend" && "$PY" -m pytest -q)
  (cd "$ROOT/frontend" && npm run typecheck && npm test)
  (cd "$ROOT/frontend" && npx playwright install chromium >/dev/null && npm run e2e)
  exit 0
fi

(cd "$ROOT/backend" && "$PY" -m securelens.manage migrate)
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT INT TERM

(cd "$ROOT/backend" && exec "$PY" -m uvicorn securelens.main:app --host 127.0.0.1 --port 8000) & pids+=($!)
(cd "$ROOT/backend" && exec "$PY" -m securelens.worker) & pids+=($!)
(cd "$ROOT/frontend" && SECURELENS_API_URL=http://127.0.0.1:8000 exec npx vite --host 127.0.0.1 --port 5173) & pids+=($!)

echo
echo "SecureLens AI is starting:"
echo "  Dashboard  http://localhost:5173   (first visit: create the organization and owner)"
echo "  API        http://127.0.0.1:8000/api/v1/healthz"
echo "Press Ctrl+C to stop."
wait -n "${pids[@]}"
