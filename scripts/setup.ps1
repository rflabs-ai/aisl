<#
.SYNOPSIS
    Developer setup for ai-security-layer (ADR-020): reproducible, offline,
    fail-closed. No remote fetches, no pipe-to-shell, no privilege escalation.

.PARAMETER CheckOnly
    Run the environment checks only (no install, typecheck, or tests).

.PARAMETER WithPostgres
    Additionally bootstrap the disposable Postgres 16 container used by the
    Postgres-mode test suites (DEPLOYMENT.md, M12 workflow). Opt-in: the
    default mode needs no container.

.EXAMPLE
    pwsh -File scripts/setup.ps1
#>
param(
    [switch]$CheckOnly,
    [switch]$WithPostgres
)

$ErrorActionPreference = 'Stop'
$failures = 0
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Check([string]$name, [scriptblock]$probe) {
    # The probe prints its success detail; a throw records a failure.
    try {
        $detail = & $probe
        Write-Host "  [ok]   $name :: $detail"
    } catch {
        Write-Host "  [FAIL] $name :: $($_.Exception.Message)"
        $script:failures += 1
    }
}

Write-Host '== ai-security-layer setup ==' -ForegroundColor Cyan

# 1. Node >= 22.5 (package.json engines).
Check 'node >= 22.5' {
    $version = (node --version) -replace '^v', ''
    $major, $minor = $version.Split('.')
    if (-not $major -or -not $minor) { throw "unparsable version output: $version" }
    if ([int]$major -lt 22 -or ([int]$major -eq 22 -and [int]$minor -lt 5)) {
        throw "found $version, need >= 22.5"
    }
    "found $version"
}

# 2. git on PATH (the M15 Git integration shells out to the installed CLI).
Check 'git available' { "found $(git --version)" }

# 3. npm available.
Check 'npm available' { "found $(npm --version)" }

if (-not $CheckOnly) {
    Push-Location $RepoRoot
    try {
        Write-Host '  [..]   npm install (local repo; only the npm registry is contacted)'
        if (npm install) { Write-Host '  [ok]   npm install' } else { Write-Host '  [FAIL] npm install'; $script:failures += 1 }

        Write-Host '  [..]   typecheck'
        if (npm run typecheck) { Write-Host '  [ok]   typecheck' } else { Write-Host '  [FAIL] typecheck'; $script:failures += 1 }

        Write-Host '  [..]   tests'
        if (npm test) { Write-Host '  [ok]   tests' } else { Write-Host '  [FAIL] tests'; $script:failures += 1 }
    } finally {
        Pop-Location
    }
}

# Optional: disposable Postgres for the Postgres-mode suites (opt-in).
if ($WithPostgres) {
    Check 'docker available' { "found $(docker --version)" }
    $existing = docker ps -a --format '{{.Names}}' 2>$null | Where-Object { $_ -eq 'sec-layer-pg' }
    if ($existing) {
        Write-Host '  [ok]   postgres container sec-layer-pg already exists (skipping bootstrap)'
    } else {
        # Scratch-container only: the password never protects real data.
        # ponytail: fixed port 5433 + throwaway password; real deployments
        # supply their own secret and TLS (DEPLOYMENT.md).
        $pgPassword = [guid]::NewGuid().ToString('N')
        docker run -d --name sec-layer-pg --restart unless-stopped -e "POSTGRES_PASSWORD=$pgPassword" -p 5433:5432 postgres:16 >$null
        if ($LASTEXITCODE -ne 0) { Write-Host '  [FAIL] postgres bootstrap'; $script:failures += 1 }
        else {
            Write-Host '  [ok]   postgres container sec-layer-pg started on 5433'
            Write-Host '         DATABASE_URL=postgres://postgres:<password>@localhost:5433/postgres — read the password from the container env (docker inspect), never from a log'
        }
    }
}

Write-Host ''
if ($failures -gt 0) {
    Write-Host "setup FAILED: $failures check(s) did not pass — fix the failures above and re-run." -ForegroundColor Red
    exit 1
}

Write-Host 'setup complete. Next steps:' -ForegroundColor Green
Write-Host '  npm run demo        # MVP acceptance walkthrough'
Write-Host '  npm run attack      # adversarial corpus'
Write-Host '  npm run benchmark   # measured benchmark + SLO gate'
exit 0
