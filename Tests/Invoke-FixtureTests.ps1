#requires -version 7.0
<#
.SYNOPSIS
    Run the golden-fixture check suite, print a summary, and optionally publish
    the results to a local SQLite database for historical tracking.

.DESCRIPTION
    Executes every fixture under Tests/Fixtures/ against its real check function
    using the shared helpers in Tests/Helpers/TestHelpers.psm1 (the same code the
    Pester suite uses). Exits non-zero if any check's actual Status does not match
    its expected Status, so this can gate CI.

.PARAMETER Publish
    Also append the run + per-check rows to a local SQLite file (offline; no network).
    The database is created on first use. Override the location with -DbPath.

.PARAMETER DbPath
    SQLite file to publish to. Defaults to the migrated local copy under
    ~/Documents/PSGuerrilla-Data/ (see Tests/Local/Publish-GuerrillaTestResultsSqlite.ps1).

.EXAMPLE
    pwsh Tests/Invoke-FixtureTests.ps1

.EXAMPLE
    pwsh Tests/Invoke-FixtureTests.ps1 -Publish
#>
[CmdletBinding()]
param(
    [switch]$Publish,
    [string]$DbPath
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

Import-Module (Join-Path $root 'Helpers' 'TestHelpers.psm1') -Force
Import-PSGuerrilla

$theaterByFamily = @{ AD = 'Reconnaissance'; Entra = 'Infiltration'; GoogleWorkspace = 'Fortification' }

$cases = Get-GuerrillaFixtureCases
$sw = [System.Diagnostics.Stopwatch]::StartNew()

$results = foreach ($c in $cases) {
    $actual = 'ERROR'
    try {
        $finding = Invoke-GuerrillaCheckFixture -AuditData $c.AuditData -Definition $c.Definition -FunctionName $c.FunctionName
        $actual = "$($finding.Status)"
    } catch {
        $actual = "ERROR: $($_.Exception.Message)"
    }
    [PSCustomObject]@{
        CheckId        = $c.CheckId
        Family         = $c.Family
        Theater        = $theaterByFamily[$c.Family]
        Scenario       = $c.Scenario
        Severity       = $c.Definition.severity
        ExpectedStatus = $c.ExpectedStatus
        ActualStatus   = $actual
        Passed         = ($actual -eq $c.ExpectedStatus)
        FixtureFile    = $c.FixtureFile
        Description    = $c.Description
    }
}
$sw.Stop()

$results | Sort-Object Family, CheckId, Scenario |
    Format-Table CheckId, Scenario, ExpectedStatus, ActualStatus, Passed -AutoSize | Out-Host

$passed = @($results | Where-Object Passed).Count
$failed = @($results | Where-Object { -not $_.Passed }).Count
Write-Host ("`n{0} checks, {1} fixtures: {2} passed, {3} failed in {4} ms" -f `
    (@($results | Select-Object -Unique CheckId).Count), $results.Count, $passed, $failed, $sw.ElapsedMilliseconds)

if ($failed -gt 0) {
    Write-Host "FAILURES:" -ForegroundColor Red
    $results | Where-Object { -not $_.Passed } |
        ForEach-Object { Write-Host ("  {0} [{1}] expected {2} got {3}" -f $_.CheckId, $_.Scenario, $_.ExpectedStatus, $_.ActualStatus) -ForegroundColor Red }
}

if ($Publish) {
    $gitSha    = (git rev-parse --short HEAD 2>$null)
    $gitBranch = (git rev-parse --abbrev-ref HEAD 2>$null)
    $summary = @{
        suite          = 'golden-fixtures'
        git_sha        = "$gitSha"
        git_branch     = "$gitBranch"
        host           = [System.Net.Dns]::GetHostName()
        runner         = $env:USER ?? $env:USERNAME
        total          = $results.Count
        passed         = $passed
        failed         = $failed
        duration_ms    = [int]$sw.ElapsedMilliseconds
        module_version = "$((Import-PowerShellDataFile (Join-Path $root '..' 'PSGuerrilla.psd1')).ModuleVersion)"
    }
    $publishArgs = @{ Summary = $summary; Results = $results }
    if ($DbPath) { $publishArgs.DbPath = $DbPath }
    & (Join-Path $root 'Local' 'Publish-GuerrillaTestResultsSqlite.ps1') @publishArgs
}

exit ($failed -gt 0 ? 1 : 0)
