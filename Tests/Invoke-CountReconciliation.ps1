#requires -version 7.0
# Guerrilla — https://github.com/jimrtyler/PSGuerrilla
# © Jim Tyler. Licensed CC BY 4.0.
<#
.SYNOPSIS
    Gate E: every public number must reconcile with the derived test artifact.

.DESCRIPTION
    The counts the module advertises (total checks, per-platform checks, fixture
    count, EIDSCA control count) are hand-typed prose in the manifest Description
    and README. The truth is derived by the golden-fixture run and written to
    test-summary.json. This gate fails when any advertised number disagrees with
    the artifact — in either direction: a stale number left behind after the
    catalog changed, or a typo introduced into the prose.

    Rules enforced:
      1. The artifact exists, recorded zero failures, and its checksTested equals
         checkDefinitions (the "every check is fixture-tested" claim).
      2. The artifact's moduleVersion equals the manifest's ModuleVersion.
      3. Every "<N> checks" claim in the manifest Description and README is one of
         the derived values (total or a per-platform count), and the total and each
         per-platform count each appear at least once in both documents.
      4. Every "<N> fixtures" claim equals the derived fixture count, present at
         least once in both documents.
      5. Every "<N>-control EIDSCA" claim equals the derived EIDSCA check count.

.PARAMETER SummaryPath
    Path to test-summary.json produced by Invoke-FixtureTests.ps1 -EmitSummary.

.PARAMETER PoisonSelfTest
    Prove the gate can fail: reconcile against an artifact whose total has been
    perturbed in memory. The run MUST exit non-zero; nothing is written.

.EXAMPLE
    pwsh Tests/Invoke-CountReconciliation.ps1
#>
[CmdletBinding()]
param(
    [string]$SummaryPath = (Join-Path $PSScriptRoot 'test-summary.json'),
    [switch]$PoisonSelfTest
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot   # repo root (this script lives in Tests/)
$problems = [System.Collections.Generic.List[string]]::new()

if (-not (Test-Path $SummaryPath)) {
    Write-Host "GATE E RED: no artifact at $SummaryPath — run Tests/Invoke-FixtureTests.ps1 -EmitSummary first." -ForegroundColor Red
    exit 1
}
$artifact = Get-Content $SummaryPath -Raw | ConvertFrom-Json
$manifest = Import-PowerShellDataFile (Join-Path $root 'source' 'Guerrilla.psd1')

# 1) Artifact integrity: green, complete, and belonging to this version.
if ([int]$artifact.failed -ne 0) { $problems.Add("artifact records $($artifact.failed) fixture failures — not a green run") }
if ([int]$artifact.checksTested -ne [int]$artifact.checkDefinitions) {
    $problems.Add("artifact checksTested ($($artifact.checksTested)) != checkDefinitions ($($artifact.checkDefinitions)) — 'every check is fixture-tested' does not hold")
}
if ("$($artifact.moduleVersion)" -ne "$($manifest.ModuleVersion)") {
    $problems.Add("artifact moduleVersion $($artifact.moduleVersion) != manifest ModuleVersion $($manifest.ModuleVersion) — stale artifact")
}

# 2) Derive the numbers. Per-platform comes from perCheck (complete because
#    checksTested == checkDefinitions is asserted above).
$total = [int]$artifact.checkDefinitions
if ($PoisonSelfTest) { $total += 1 }   # in-memory perturbation only; must turn this run red
$fixtures = [int]$artifact.fixtureCount
$perPlatform = @{}
foreach ($p in $artifact.perCheck.PSObject.Properties) {
    $plat = "$($p.Value.platform)"
    $perPlatform[$plat] = 1 + [int]($perPlatform[$plat] ?? 0)
}
$eidsca = @($artifact.perCheck.PSObject.Properties.Name | Where-Object { $_ -match '^EIDSCA' }).Count
$allowedCheckCounts = @($total) + @($perPlatform.Values | ForEach-Object { [int]$_ })

# 3) Reconcile each document's claims against the derived numbers.
function Test-Claims {
    param([string]$Label, [string]$Text)
    foreach ($m in [regex]::Matches($Text, '(\d[\d,]*)\s+checks\b')) {
        $n = [int]($m.Groups[1].Value -replace ',', '')
        if ($n -notin $allowedCheckCounts) {
            $script:problems.Add("${Label}: claims '$($m.Value)' but derived counts are total=$total, per-platform=$(($perPlatform.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', ')")
        }
    }
    foreach ($m in [regex]::Matches($Text, '(\d[\d,]*)\s+(?:golden\s+)?fixtures?\b')) {
        $n = [int]($m.Groups[1].Value -replace ',', '')
        if ($n -ne $fixtures) { $script:problems.Add("${Label}: claims '$($m.Value)' but the artifact derived $fixtures fixtures") }
    }
    foreach ($m in [regex]::Matches($Text, '(\d+)-control EIDSCA')) {
        if ([int]$m.Groups[1].Value -ne $eidsca) { $script:problems.Add("${Label}: claims '$($m.Value)' but the artifact derived $eidsca EIDSCA checks") }
    }
    # Presence: the headline numbers must actually be advertised, not merely not-wrong.
    if ($Text -notmatch [regex]::Escape("$total") + '\s+checks') { $script:problems.Add("${Label}: never states the derived total '$total checks'") }
    foreach ($kv in $perPlatform.GetEnumerator()) {
        if ($Text -notmatch "$($kv.Value)\s+checks") { $script:problems.Add("${Label}: never states the derived $($kv.Name) count '$($kv.Value) checks'") }
    }
    if ($Text -notmatch ('(' + [regex]::Escape($fixtures.ToString('N0')) + '|' + $fixtures + ')\s+(golden\s+)?fixtures?')) {
        $script:problems.Add("${Label}: never states the derived fixture count '$fixtures fixtures'")
    }
}
Test-Claims -Label 'manifest Description (source/Guerrilla.psd1)' -Text $manifest.Description
Test-Claims -Label 'README.md' -Text (Get-Content (Join-Path $root 'README.md') -Raw)

if ($problems.Count -gt 0) {
    Write-Host 'GATE E RED: public numbers do not reconcile with the derived artifact:' -ForegroundColor Red
    $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host 'Fix the prose (or regenerate the artifact) — never ship a number the gating run did not derive.' -ForegroundColor Red
    exit 1
}
Write-Host ("Gate E green: total={0}, {1}, fixtures={2}, EIDSCA={3} all reconcile with manifest Description and README." -f `
    $total, (($perPlatform.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' '), $fixtures, $eidsca) -ForegroundColor Green
exit 0
