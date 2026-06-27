#requires -version 7.0
<#
    EIDPIM fixtures for the 7 previously-broken privileged-user checks
    (004/005/006/007/008/009/013) — repaired 2026-06-27 to bind
    $privilegedUsers = $AuditData.PIM.PrivilegedUsers + add a Not-Assessed guard.
    Synthetic data only. Re-run: pwsh Tests/Fixtures/_generate-fixtures-eidpim.ps1

    Each reads $AuditData.PIM.PrivilegedUsers (array of user objects). 006/007 also read
    $AuditData.AuthMethods.UserRegistrationDetails. SKIP via PIM.Errors['PrivilegedUsers'].
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family, [string]$CheckId, [string]$Theater, [string]$Scenario, [string]$ExpectedStatus, [string]$Description, [hashtable]$AuditData)
    $obj = [ordered]@{ checkId = $CheckId; theater = $Theater; scenario = $Scenario; expectedStatus = $ExpectedStatus; description = $Description; objectShape = $false; auditData = $AuditData }
    $obj | ConvertTo-Json -Depth 18 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$I = 'Infiltration'; $EN = 'Entra'

# A clean privileged user (member, enabled, cloud-only, signed in recently)
function User($id, $upn, $extra) {
    $u = @{ id = $id; displayName = $upn; userPrincipalName = $upn; userType = 'Member'; accountEnabled = $true; onPremisesSyncEnabled = $false; signInActivity = @{ lastSignInDateTime = '2026-06-01T00:00:00Z' }; createdDateTime = '2020-01-01T00:00:00Z' }
    if ($extra) { foreach ($k in $extra.Keys) { $u[$k] = $extra[$k] } }
    $u
}
function Pim($users) { @{ Errors = @{}; PIM = @{ Errors = @{}; PrivilegedUsers = @($users) } } }
$skPim = @{ Errors = @{}; PIM = @{ Errors = @{ PrivilegedUsers = 'Graph 429' }; PrivilegedUsers = @() }; AuthMethods = @{ Errors = @{}; UserRegistrationDetails = @() } }

# EIDPIM-004 guests in privileged roles — PASS no guests / FAIL a guest / SKIP
New-Fixture $EN EIDPIM-004 $I clean PASS 'No guest accounts hold privileged roles' (Pim @((User 'u1' 'alice@contoso.com' $null), (User 'u2' 'bob@contoso.com' $null)))
New-Fixture $EN EIDPIM-004 $I known-bad FAIL 'A guest account holds a privileged role' (Pim @((User 'u1' 'alice@contoso.com' $null), (User 'g1' 'guest@partner.com' @{ userType = 'Guest' })))
New-Fixture $EN EIDPIM-004 $I throttled SKIP 'Privileged user details not assessed' $skPim

# EIDPIM-005 on-prem synced privileged accounts — PASS 0 / FAIL 3+ / SKIP
New-Fixture $EN EIDPIM-005 $I clean PASS 'No synced accounts hold privileged cloud roles' (Pim @((User 'u1' 'alice@contoso.com' $null)))
New-Fixture $EN EIDPIM-005 $I known-bad FAIL 'Three synced accounts hold privileged cloud roles' (Pim @((User 'u1' 'a@contoso.com' @{ onPremisesSyncEnabled = $true }), (User 'u2' 'b@contoso.com' @{ onPremisesSyncEnabled = $true }), (User 'u3' 'c@contoso.com' @{ onPremisesSyncEnabled = $true })))
New-Fixture $EN EIDPIM-005 $I throttled SKIP 'Privileged user details not assessed' $skPim

# EIDPIM-006 privileged users without MFA — PASS all MFA / FAIL one without / SKIP
New-Fixture $EN EIDPIM-006 $I clean PASS 'All privileged users have MFA registered' @{ Errors = @{}; PIM = @{ Errors = @{}; PrivilegedUsers = @((User 'u1' 'alice@contoso.com' $null)) }; AuthMethods = @{ Errors = @{}; UserRegistrationDetails = @(@{ id = 'u1'; isMfaRegistered = $true; methodsRegistered = @('microsoftAuthenticatorPush') }) } }
New-Fixture $EN EIDPIM-006 $I known-bad FAIL 'A privileged user has no MFA registered' @{ Errors = @{}; PIM = @{ Errors = @{}; PrivilegedUsers = @((User 'u1' 'alice@contoso.com' $null)) }; AuthMethods = @{ Errors = @{}; UserRegistrationDetails = @(@{ id = 'u1'; isMfaRegistered = $false; methodsRegistered = @() }) } }
New-Fixture $EN EIDPIM-006 $I throttled SKIP 'Privileged user / MFA data not assessed' $skPim

# EIDPIM-007 privileged users with only weak MFA — PASS strong / FAIL weak-only / SKIP
New-Fixture $EN EIDPIM-007 $I clean PASS 'Privileged users use phishing-resistant methods' @{ Errors = @{}; PIM = @{ Errors = @{}; PrivilegedUsers = @((User 'u1' 'alice@contoso.com' $null)) }; AuthMethods = @{ Errors = @{}; UserRegistrationDetails = @(@{ id = 'u1'; isMfaRegistered = $true; methodsRegistered = @('fido2') }) } }
New-Fixture $EN EIDPIM-007 $I known-bad FAIL 'A privileged user relies on weak MFA only' @{ Errors = @{}; PIM = @{ Errors = @{}; PrivilegedUsers = @((User 'u1' 'alice@contoso.com' $null)) }; AuthMethods = @{ Errors = @{}; UserRegistrationDetails = @(@{ id = 'u1'; isMfaRegistered = $true; methodsRegistered = @('sms') }) } }
New-Fixture $EN EIDPIM-007 $I throttled SKIP 'Privileged user / MFA data not assessed' $skPim

# EIDPIM-008 disabled accounts in privileged roles — PASS none / FAIL one / SKIP
New-Fixture $EN EIDPIM-008 $I clean PASS 'No disabled accounts hold privileged roles' (Pim @((User 'u1' 'alice@contoso.com' $null)))
New-Fixture $EN EIDPIM-008 $I known-bad FAIL 'A disabled account still holds a privileged role' (Pim @((User 'u1' 'alice@contoso.com' $null), (User 'u2' 'stale@contoso.com' @{ accountEnabled = $false })))
New-Fixture $EN EIDPIM-008 $I throttled SKIP 'Privileged user details not assessed' $skPim

# EIDPIM-009 never-signed-in privileged accounts — PASS all active / FAIL 3+ never / SKIP
New-Fixture $EN EIDPIM-009 $I clean PASS 'All privileged accounts have signed in' (Pim @((User 'u1' 'alice@contoso.com' $null)))
New-Fixture $EN EIDPIM-009 $I known-bad FAIL 'Three privileged accounts have never signed in' (Pim @((User 'u1' 'a@contoso.com' @{ signInActivity = $null }), (User 'u2' 'b@contoso.com' @{ signInActivity = $null }), (User 'u3' 'c@contoso.com' @{ signInActivity = $null })))
New-Fixture $EN EIDPIM-009 $I throttled SKIP 'Privileged user details not assessed' $skPim

# EIDPIM-013 separate-admin naming convention — PASS >=80% / FAIL <50% / SKIP
New-Fixture $EN EIDPIM-013 $I clean PASS 'Privileged accounts follow admin naming convention' (Pim @((User 'u1' 'admin-alice@contoso.com' $null), (User 'u2' 'adm-bob@contoso.com' $null)))
New-Fixture $EN EIDPIM-013 $I known-bad FAIL 'Privileged accounts do not follow admin naming convention' (Pim @((User 'u1' 'alice@contoso.com' $null), (User 'u2' 'bob@contoso.com' $null)))
New-Fixture $EN EIDPIM-013 $I throttled SKIP 'Privileged user details not assessed' $skPim

Write-Host "`nDone (EIDPIM repaired-checks: 7)."
