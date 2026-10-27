<#
.SYNOPSIS
    Registers the nightly H14 adversarial run for the current user (ADR-033).

.DESCRIPTION
    This is convenience infrastructure, NOT a security control. Nothing in the
    evidence chain depends on it having run, and a missed night is invisible
    except via `-Status`. The repo ships the runner (`npm run adversarial`);
    the schedule belongs to the operator, which is why it lives here and not in
    a CI configuration this repository cannot publish (its only remote is a
    local bare repo).

    Every run rewrites artifacts/adversarial-report.json, so `-Status` reads the
    report's generatedAt as the truth for "when did this last actually run".

.PARAMETER DailyAt
    Local time for the daily run. Default 03:17 (off the hour, so a machine
    waking up at 03:00 does not collide with a backlog of other tasks).

.PARAMETER Status
    Print the task state and the last report timestamp; change nothing.

.PARAMETER Unregister
    Remove the task.

.EXAMPLE
    pwsh -File scripts/schedule-adversarial.ps1
    pwsh -File scripts/schedule-adversarial.ps1 -Status
#>
param(
    [string]$DailyAt = '03:17',
    [switch]$Status,
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$TaskName = 'ASL adversarial (H14)'
$ReportPath = Join-Path $RepoRoot 'artifacts/adversarial-report.json'

function Show-Report {
    if (-not (Test-Path $ReportPath)) {
        Write-Host "  [--]   no report yet ($ReportPath)"
        return
    }
    $report = Get-Content $ReportPath -Raw | ConvertFrom-Json
    $verdict = if ($report.passed) { 'PASS' } else { 'FAIL' }
    Write-Host "  [$verdict] last report :: $($report.generatedAt) @ $($report.gitHead)"
}

if ($Status) {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        Write-Host "  [--]   task '$TaskName' is not registered"
    } else {
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        Write-Host "  [ok]   task '$TaskName' :: $($task.State), last run $($info.LastRunTime), result $($info.LastTaskResult)"
    }
    Show-Report
    return
}

if ($Unregister) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "  [ok]   unregistered '$TaskName'"
    } else {
        Write-Host "  [--]   '$TaskName' was not registered"
    }
    return
}

# The log is not plumbed separately: the report file IS the output artifact and
# carries generatedAt + lanes, so there is one source of truth to read.
$command = "Set-Location '$RepoRoot'; npm run adversarial; exit `$LASTEXITCODE"
$action = New-ScheduledTaskAction -Execute 'pwsh' -Argument "-NoProfile -NonInteractive -Command `"$command`"" -WorkingDirectory $RepoRoot
$trigger = New-ScheduledTaskTrigger -Daily -At $DailyAt
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force `
    -Description 'H14 nightly adversarial evaluation (ADR-033). Convenience only; not a security control.' | Out-Null

Write-Host "  [ok]   registered '$TaskName' :: daily at $DailyAt"
Write-Host "         verify with: pwsh -File scripts/schedule-adversarial.ps1 -Status"
Show-Report
