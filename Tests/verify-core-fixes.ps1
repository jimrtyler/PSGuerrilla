# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#Requires -Version 7.0
<#
.SYNOPSIS
    Regression tests for core fixes surfaced by live-environment validation (v2.9.1):
    AD-1 (Resolve-ADSid caches), AD-2 (New-TierBleedFinding empty collection).
#>

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
Import-Module (Join-Path $PSScriptRoot '..' 'PSGuerrilla.psd1') -Force

# Gather everything inside module scope (private functions + $script: caches), then
# assert in script scope where the test helper is visible.
$r = & (Get-Module PSGuerrilla) {
    $def = @{ id = 'ADTIER-002'; name = 'x'; severity = 'High'; _categoryName = 'TierZero' }
    $hit = [pscustomobject]@{ Group = 'Domain Admins'; SamAccountName = 'svc_veeam'; MatchedKeyword = 'veeam' }
    @{
        SidCacheInit = ($null -ne $script:SidCache)
        WkSids       = $script:WellKnownSids.Count
        WkRids       = $script:WellKnownRids.Count
        Sys          = (Resolve-ADSid -SidString 'S-1-5-18')
        Admins       = (Resolve-ADSid -SidString 'S-1-5-32-544')
        Dom512       = (Resolve-ADSid -SidString 'S-1-5-21-1-2-3-512')
        TierEmpty    = (New-TierBleedFinding -CheckDefinition $def -Hits @() -ProductLabel 'Veeam').Status
        TierHit      = (New-TierBleedFinding -CheckDefinition $def -Hits @($hit) -ProductLabel 'Veeam').Status
    }
}

$pass = 0; $fail = 0
function Test-Case { param([string]$Name, [bool]$Condition)
    if ($Condition) { Write-Host "  [PASS] $Name" -ForegroundColor Green; $script:pass++ }
    else { Write-Host "  [FAIL] $Name" -ForegroundColor Red; $script:fail++ }
}

Write-Host "`n  Core fix regression tests`n  =========================" -ForegroundColor Cyan
Test-Case 'AD-1: $script:SidCache is initialized'        $r.SidCacheInit
Test-Case 'AD-1: WellKnownSids populated'                ($r.WkSids -gt 0)
Test-Case 'AD-1: WellKnownRids populated'                ($r.WkRids -gt 0)
Test-Case 'AD-1: Resolve-ADSid S-1-5-18 -> SYSTEM'       ($r.Sys -eq 'SYSTEM')
Test-Case 'AD-1: Resolve-ADSid builtin admins'           ($r.Admins -eq 'Administrators')
Test-Case 'AD-1: Resolve-ADSid domain RID 512'           ($r.Dom512 -eq 'Domain Admins')
Test-Case 'AD-2: New-TierBleedFinding @() -> PASS'       ($r.TierEmpty -eq 'PASS')
Test-Case 'AD-2: New-TierBleedFinding with a hit -> FAIL' ($r.TierHit -eq 'FAIL')

Write-Host "`n  Summary: $pass passed, $fail failed`n" -ForegroundColor Cyan
if ($fail -gt 0) { exit 1 }
Write-Host "  RESULT: ALL CHECKS PASSED" -ForegroundColor Green
