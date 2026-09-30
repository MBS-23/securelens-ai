#!/usr/bin/env bash
# One-time local setup for SecureLens AI (macOS, Linux, or Windows via WSL2).
# Creates the backend virtual environment, installs the dashboard, writes a
# private .env.local (never committed) and prepares the local database.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || { echo "Python 3.11 or newer is required."; exit 1; }
node -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 20 || (a === 20 && b >= 19) ? 0 : 1)' \
  || { echo "Node.js 20.19 or newer is required."; exit 1; }
python3 -c 'import resource' 2>/dev/null \
  || { echo "The scan sandbox needs a POSIX system (macOS, Linux or WSL2 on Windows)."; exit 1; }

say "Backend: virtual environment and packages"
cd "$ROOT/backend"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -e ".[server,dev]"

say "Dashboard: packages"
cd "$ROOT/frontend"
npm ci

say "Local configuration (.env.local, private to this machine)"
mkdir -p "$ROOT/data/storage"
if [ ! -f "$ROOT/.env.local" ]; then
  SECRET="$("$ROOT/backend/.venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')"
  cat > "$ROOT/.env.local" <<EOF
# Local development settings for SecureLens AI. Never commit this file.
SECURELENS_DATABASE_URL=sqlite:///$ROOT/data/securelens.db
SECURELENS_SECRET_KEY=$SECRET
SECURELENS_STORAGE_DIR=$ROOT/data/storage
EOF
  chmod 600 "$ROOT/.env.local"
  echo "Wrote $ROOT/.env.local"
else
  echo "Keeping existing $ROOT/.env.local"
fi

say "Database migrations"
set -a; . "$ROOT/.env.local"; set +a
cd "$ROOT/backend" && .venv/bin/python -m securelens.manage migrate

say "Done"
echo "Start everything with:  scripts/run-local.sh   (then open http://localhost:5173)"
echo "Run the tests with:     scripts/run-local.sh --test"
