<#
.SYNOPSIS
  ADR-018 backup: plain-SQL pg_dump of one database (no custom backup format).

.DESCRIPTION
  Shells out to pg_dump. Requirements:
    - pg_dump on PATH (ships with any PostgreSQL install), OR a running Docker
      Postgres container whose pg_dump is used via docker exec (fallback; the
      container path uses the image's local-socket trust, so no password is
      placed on any command line).
    - When the host pg_dump path is used, PGPASSWORD must be set in the
      environment: the password is read from the environment only, never as an
      argument, never logged, never echoed.
    - The M3 anchor file is outside this dump by design (DEPLOYMENT.md):
      restore it from its own witness store.

.EXAMPLE
  $env:PGPASSWORD = '<password from the secret broker>'
  ./tools/backup.ps1 -Database sec-layer-c -OutFile backup.sql
#>
param(
  [Parameter(Mandatory = $true)][string]$Database,
  [string]$DbHost = 'localhost',
  [int]$Port = 5433,
  [string]$User = 'postgres',
  [string]$Container = 'sec-layer-pg',
  [string]$OutFile = ''
)

$ErrorActionPreference = 'Stop'

# These values are interpolated into the container shell command; keep them
# to plain identifiers so no operator value can inject into that command.
if ($Database -notmatch '^[A-Za-z0-9_-]+$' -or $User -notmatch '^[A-Za-z0-9_-]+$') {
  throw 'Database and User must match [A-Za-z0-9_-]+ (they reach the container shell command).'
}
if (-not $OutFile) { $OutFile = "$Database-$(Get-Date -UtcNow -Format 'yyyyMMdd-HHmmss').sql" }

if (Get-Command pg_dump -ErrorAction SilentlyContinue) {
  if (-not $env:PGPASSWORD) {
    throw 'PGPASSWORD must be set in the environment for the host pg_dump path (never on the command line).'
  }
  pg_dump -h $DbHost -p $Port -U $User -d $Database -f $OutFile
  if ($LASTEXITCODE -ne 0) { throw "pg_dump failed with exit code $LASTEXITCODE (endpoint ${DbHost}:$Port)" }
  Write-Host "backup of '$Database' (endpoint ${DbHost}:$Port) written to $OutFile"
} elseif (Get-Command docker -ErrorAction SilentlyContinue) {
  $tmp = "/tmp/sec-layer-backup-$(New-Guid).sql"
  docker exec $Container sh -c "pg_dump -U $User -d $Database > $tmp"
  if ($LASTEXITCODE -ne 0) { throw "pg_dump inside container '$Container' failed with exit code $LASTEXITCODE" }
  docker cp "${Container}:$tmp" $OutFile
  if ($LASTEXITCODE -ne 0) { throw "docker cp failed with exit code $LASTEXITCODE" }
  docker exec $Container rm -f $tmp | Out-Null
  Write-Host "backup of '$Database' (container $Container) written to $OutFile"
} else {
  throw 'pg_dump is not on PATH and docker is unavailable: install PostgreSQL client tools (pg_dump ships with any PostgreSQL install) or provide the fallback container.'
}
