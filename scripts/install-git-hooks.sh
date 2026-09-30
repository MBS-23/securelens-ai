#!/usr/bin/env bash
# Opt-in automatic push: after every commit, push the current branch to its
# upstream (never force). Run once per clone.   --uninstall   removes the hook.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOK="$(git -C "$ROOT" rev-parse --path-format=absolute --git-path hooks)/post-commit"

if [ "${1:-}" = "--uninstall" ]; then
  rm -f "$HOOK" && echo "Automatic push turned off."
  exit 0
fi

mkdir -p "$(dirname "$HOOK")"
cat > "$HOOK" <<'EOF'
#!/bin/sh
# Installed by scripts/install-git-hooks.sh: push each commit to its upstream branch.
branch=$(git symbolic-ref --quiet --short HEAD) || exit 0
if ! git rev-parse --abbrev-ref --symbolic-full-name "@{u}" >/dev/null 2>&1; then
  echo "auto-push: '$branch' has no upstream yet; run: git push -u origin $branch"
  exit 0
fi
git push --quiet && echo "auto-push: pushed $branch" || echo "auto-push: push failed; run 'git push' when you can"
EOF
chmod +x "$HOOK"
echo "Automatic push turned on ($HOOK). Turn it off with: scripts/install-git-hooks.sh --uninstall"
