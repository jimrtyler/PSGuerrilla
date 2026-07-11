#requires -version 7.0
<#
    EIDSCA fixtures (44 data-driven controls). Synthetic data only.
    Re-run: pwsh Tests/Fixtures/_generate-fixtures-eidsca.ps1

    EIDSCA controls have no per-ID Test-* function — they all run through the dispatcher
    Invoke-EntraEidscaChecks -> Resolve-EidscaControl, which reads the raw Graph objects
    in $AuditData.AuthMethods.{AuthorizationPolicy,AuthMethodsPolicy,MethodConfigurations,
    DirectorySettings} and $AuditData.TenantConfig.AdminConsentRequestPolicy. The test
    harness (TestHelpers) detects EIDSCA-* fixtures and dispatches through the real path,
    filtering the catalog result to the control under test.

    For each of the 44 controls we synthesize 3 fixtures from the catalog accessor
    (source/configId/path/op/expected): pass=>PASS, fail=>FAIL, no-data=>SKIP (source object
    absent — never PASS). Generated programmatically so it tracks the catalog if it changes.
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$family = 'Eidsca'
function New-Fixture {
    param([string]$CheckId, [string]$Scenario, [string]$ExpectedStatus, [string]$Description, [hashtable]$AuditData)
    $obj = [ordered]@{ checkId = $CheckId; theater = 'Infiltration'; scenario = $Scenario; expectedStatus = $ExpectedStatus; description = $Description; objectShape = $false; auditData = $AuditData }
    $obj | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $root $family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $family/$CheckId.$Scenario -> $ExpectedStatus"
}

# Build a nested hashtable from a dotted path: 'a.b.c', $v -> @{ a = @{ b = @{ c = $v } } }
function New-Nested([string]$Path, $Value) {
    $segs = $Path -split '\.'
    $obj = $Value
    for ($i = $segs.Count - 1; $i -ge 0; $i--) { $obj = @{ "$($segs[$i])" = $obj } }
    $obj
}
# Merge nested hashtables (shallow recursive) so we can add `id` to a config object.
function Merge-Ht([hashtable]$A, [hashtable]$B) { $o = @{}; foreach ($k in $A.Keys) { $o[$k] = $A[$k] }; foreach ($k in $B.Keys) { $o[$k] = $B[$k] }; $o }

# Compute (Pass, Fail) leaf values for an operator + expected value.
function Get-PassFail([string]$Op, $Expected) {
    switch ($Op) {
        'eq' {
            $e = "$Expected"
            if ($e -ieq 'true')  { return @{ Pass = $true;  Fail = $false } }
            if ($e -ieq 'false') { return @{ Pass = $false; Fail = $true  } }
            return @{ Pass = $Expected; Fail = '__eidsca_nomatch__' }
        }
        'in' {
            $arr = @($Expected | Where-Object { "$_" -ne '' })
            return @{ Pass = $arr[0]; Fail = '__eidsca_not_in_list__' }
        }
        'ge' { $n = [double]$Expected; return @{ Pass = $n;       Fail = ($n - 5) } }
        'le' { $n = [double]$Expected; return @{ Pass = $n;       Fail = ($n + 5) } }
        'clike-any' { return @{ Pass = @("$Expected"); Fail = @('__eidsca_nomatch__') } }
        'notempty'  { return @{ Pass = @('aaguid-1111'); Fail = @() } }
        default     { return $null }   # fido2-aaguid-enforced handled inline
    }
}

# Wrap a built source object into the AuditData shape the dispatcher reads.
function Wrap-Source([string]$Source, [string]$ConfigId, $SourceObj) {
    switch ($Source) {
        'authorizationPolicy'       { @{ Errors = @{}; AuthMethods = @{ AuthorizationPolicy = $SourceObj } } }
        'authMethodsPolicy'         { @{ Errors = @{}; AuthMethods = @{ AuthMethodsPolicy = $SourceObj } } }
        'authMethodConfig'          { @{ Errors = @{}; AuthMethods = @{ MethodConfigurations = @($SourceObj) } } }
        'adminConsentRequestPolicy' { @{ Errors = @{}; TenantConfig = @{ AdminConsentRequestPolicy = $SourceObj } } }
        'directorySetting'          { @{ Errors = @{}; AuthMethods = @{ DirectorySettings = @($SourceObj) } } }
    }
}
# A no-data AuditData (source container empty/null) -> resolver returns SKIP (Not Assessed).
function No-Data([string]$Source) {
    switch ($Source) {
        'authorizationPolicy'       { @{ Errors = @{}; AuthMethods = @{ AuthorizationPolicy = $null } } }
        'authMethodsPolicy'         { @{ Errors = @{}; AuthMethods = @{ AuthMethodsPolicy = $null } } }
        'authMethodConfig'          { @{ Errors = @{}; AuthMethods = @{ MethodConfigurations = @() } } }
        'adminConsentRequestPolicy' { @{ Errors = @{}; TenantConfig = @{ AdminConsentRequestPolicy = $null } } }
        'directorySetting'          { @{ Errors = @{}; AuthMethods = @{ DirectorySettings = @() } } }
    }
}

# Build the source object for a given leaf value (places it at the control's path).
function Build-SourceObj([hashtable]$Ctl, $LeafValue) {
    $src = "$($Ctl.source)"; $path = "$($Ctl.path)"
    if ($src -eq 'directorySetting') {
        # a settings group whose values[] contains {name=path, value=leaf}
        return @{ displayName = 'fixture'; values = @(@{ name = $path; value = $LeafValue }) }
    }
    $nested = New-Nested $path $LeafValue
    if ($src -eq 'authMethodConfig') { return (Merge-Ht $nested @{ id = "$($Ctl.configId)" }) }
    return $nested
}

$catalog = Get-Content -Path (Join-Path $root '..' '..' 'source' 'Data' 'AuditChecks' 'EidscaChecks.json') -Raw | ConvertFrom-Json -AsHashtable
foreach ($ctl in $catalog.checks) {
    $id = "$($ctl.id)"; $src = "$($ctl.source)"; $op = "$($ctl.op)"

    if ($op -eq 'fido2-aaguid-enforced') {
        # reads keyRestrictions.aaGuids (non-empty) AND keyRestrictions.enforcementType in (allow|block)
        $passObj = Merge-Ht @{ keyRestrictions = @{ aaGuids = @('aaguid-1111'); enforcementType = 'allow' } } @{ id = "$($ctl.configId)" }
        $failObj = Merge-Ht @{ keyRestrictions = @{ aaGuids = @(); enforcementType = 'allow' } } @{ id = "$($ctl.configId)" }
        New-Fixture $id pass    PASS "$id compliant"     (Wrap-Source $src $ctl.configId $passObj)
        New-Fixture $id fail    FAIL "$id non-compliant" (Wrap-Source $src $ctl.configId $failObj)
        New-Fixture $id no-data SKIP "$id not collected" (No-Data $src)
        continue
    }

    $pf = Get-PassFail $op $ctl.expected
    if (-not $pf) { Write-Warning "skip $id (unhandled op $op)"; continue }

    New-Fixture $id pass    PASS "$id compliant"     (Wrap-Source $src $ctl.configId (Build-SourceObj $ctl $pf.Pass))
    New-Fixture $id fail    FAIL "$id non-compliant" (Wrap-Source $src $ctl.configId (Build-SourceObj $ctl $pf.Fail))
    New-Fixture $id no-data SKIP "$id not collected" (No-Data $src)
}

Write-Host "`nDone (EIDSCA: $($catalog.checks.Count) controls)."
