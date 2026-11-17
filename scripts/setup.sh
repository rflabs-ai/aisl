#!/usr/bin/env bash
# Developer setup for ai-security-layer (ADR-020): reproducible, offline,
# fail-closed. No remote fetches, no pipe-to-shell, no privilege escalation.
#
# Usage: scripts/setup.sh [--check-only] [--with-postgres]
set -u

failures=0
repo_root="$(cd "$(dirname "$0")/.." && pwd)"

check() {
  # The probe prints its success detail; a nonzero status records a failure.
  local name="$1"
  shift
  if detail=$("$@" 2>&1); then
    echo "  [ok]   $name :: $detail"
  else
    echo "  [FAIL] $name :: $detail"
    failures=$((failures + 1))
  fi
}

echo '== ai-security-layer setup =='

# 1. Node >= 22.5 (package.json engines).
node_ok() {
  command -v node >/dev/null 2>&1 || { echo 'node not found on PATH'; return 1; }
  version="$(node --version | sed 's/^v//')"
  major="${version%%.*}"
  minor="$(echo "$version" | cut -d. -f2)"
  if [ -z "$major" ] || [ -z "$minor" ]; then { echo "unparsable version output: $version"; return 1; }; fi
  if [ "$major" -lt 22 ] || { [ "$major" -eq 22 ] && [ "$minor" -lt 5 ]; }; then
    echo "found $version, need >= 22.5"
    return 1
  fi
  echo "found $version"
}
check 'node >= 22.5' node_ok

# 2. git on PATH (the M15 Git integration shells out to the installed CLI).
check 'git available' git --version

# 3. npm available.
check 'npm available' npm --version

if [ "${1:-}" != '--check-only' ] && [ "${2:-}" != '--check-only' ]; then
  cd "$repo_root" || exit 1

  echo '  [..]   npm install (local repo; only the npm registry is contacted)'
  if npm install; then echo '  [ok]   npm install'; else echo '  [FAIL] npm install'; failures=$((failures + 1)); fi

  echo '  [..]   typecheck'
  if npm run typecheck; then echo '  [ok]   typecheck'; else echo '  [FAIL] typecheck'; failures=$((failures + 1)); fi

  echo '  [..]   tests'
  if npm test; then echo '  [ok]   tests'; else echo '  [FAIL] tests'; failures=$((failures + 1)); fi
fi

# Optional: disposable Postgres for the Postgres-mode suites (opt-in).
if [ "${1:-}" = '--with-postgres' ] || [ "${2:-}" = '--with-postgres' ]; then
  check 'docker available' docker --version
  if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx 'sec-layer-pg'; then
    echo '  [ok]   postgres container sec-layer-pg already exists (skipping bootstrap)'
  else
    # Scratch-container only: the password never protects real data.
    # ponytail: fixed port 5433 + throwaway password; real deployments
    # supply their own secret and TLS (DEPLOYMENT.md).
    pg_password="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    if docker run -d --name sec-layer-pg --restart unless-stopped -e "POSTGRES_PASSWORD=$pg_password" -p 5433:5432 postgres:16 >/dev/null; then
      echo '  [ok]   postgres container sec-layer-pg started on 5433'
      echo '         DATABASE_URL=postgres://postgres:<password>@localhost:5433/postgres — read the password from the container env (docker inspect), never from a log'
    else
      echo '  [FAIL] postgres bootstrap'
      failures=$((failures + 1))
    fi
  fi
fi

echo ''
if [ "$failures" -gt 0 ]; then
  echo "setup FAILED: $failures check(s) did not pass — fix the failures above and re-run."
  exit 1
fi

echo 'setup complete. Next steps:'
echo '  npm run demo        # MVP acceptance walkthrough'
echo '  npm run attack      # adversarial corpus'
echo '  npm run benchmark   # measured benchmark + SLO gate'
exit 0
