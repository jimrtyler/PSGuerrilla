#requires -version 7.0
<#
    Low-tier fixtures (28 checks). Synthetic data only.
    Re-run: pwsh Tests/Fixtures/_generate-fixtures-low.ps1

    AD/Recon: ADDOM-011, ADGPO-002/003/004/005/024, ADPWD-018, ADSTALE-009/010.
    Google/Fortification: ADMIN-007/009, AUTH-015/016, COLLAB-007/010/011, DEVICE-011,
      DRIVE-012, EMAIL-020/021, GWS-SITES-001, GWS-CLASS-004/005, GWS-GEMINI-002/003/004, LOG-006.
    Entra/Infiltration: EIDTNT-014.

    Always-WARN: COLLAB-007/010, DRIVE-012. Always-SKIP: GWS-GEMINI-002/003/004.
    Always-PASS (+SKIP guard): ADGPO-024, ADPWD-018, ADSTALE-009/010.
    No reachable FAIL except EIDTNT-014. (10 EIDSCA resolver checks remain deferred.)

    CloudIdentity (Resolve-GooglePolicyValue) checks use the .ByType / setting.value shape
    and the objectShape flag (auto-detected) so policy value objects load as PSCustomObjects.
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family, [string]$CheckId, [string]$Theater, [string]$Scenario, [string]$ExpectedStatus, [string]$Description, [hashtable]$AuditData)
    $objShape = ($AuditData.ContainsKey('CloudIdentityPolicies') -and $AuditData['CloudIdentityPolicies'])
    $obj = [ordered]@{ checkId = $CheckId; theater = $Theater; scenario = $Scenario; expectedStatus = $ExpectedStatus; description = $Description; objectShape = [bool]$objShape; auditData = $AuditData }
    $obj | ConvertTo-Json -Depth 16 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$R = 'Recon'; $F = 'Fortification'; $I = 'Infiltration'
$AD = 'AD'; $G = 'GoogleWorkspace'; $EN = 'Entra'
function Cip($type, $val) { @{ Errors = @{}; CloudIdentityPolicies = @{ ByType = @{ "$type" = @(@{ setting = @{ value = $val } }) } } } }
$skCip = @{ Errors = @{}; CloudIdentityPolicies = $null }

# ───────────────────────────── AD / Recon ─────────────────────────────
# ADDOM-011 site links: PASS no isolated sites / WARN isolated site / SKIP DomainInfo error
New-Fixture $AD ADDOM-011 $R clean PASS 'All sites have site links' @{ Errors = @{}; Domain = @{ Sites = @(@{ Name = 'HQ'; SiteLinks = @('DEFAULTIPSITELINK') }) } }
New-Fixture $AD ADDOM-011 $R known-bad WARN 'A site has no site links (isolated)' @{ Errors = @{}; Domain = @{ Sites = @(@{ Name = 'HQ'; SiteLinks = @('DEFAULTIPSITELINK') }, @{ Name = 'Branch'; SiteLinks = @() }) } }
New-Fixture $AD ADDOM-011 $R throttled SKIP 'Domain info not collected' @{ Errors = @{ DomainInfo = 'AD enumeration failed' }; Domain = @{} }

# ADGPO-002 empty GPOs
New-Fixture $AD ADGPO-002 $R clean PASS 'No empty/fully-disabled GPOs' @{ Errors = @{}; GroupPolicies = @{ GPOs = @(@{ DisplayName = 'WS Baseline'; GUID = 'g1'; IsEmpty = $false; Flags = 0 }) } }
New-Fixture $AD ADGPO-002 $R known-bad WARN 'An empty GPO exists' @{ Errors = @{}; GroupPolicies = @{ GPOs = @(@{ DisplayName = 'Stub GPO'; GUID = 'g1'; IsEmpty = $true; Flags = 0 }) } }
New-Fixture $AD ADGPO-002 $R throttled SKIP 'GPOs not collected' @{ Errors = @{ GroupPolicyObjects = 'AD enumeration failed' }; GroupPolicies = @{} }

# ADGPO-003 unlinked GPOs
New-Fixture $AD ADGPO-003 $R clean PASS 'All GPOs linked' @{ Errors = @{}; GroupPolicies = @{ GPOs = @(@{ DisplayName = 'WS Baseline'; GUID = 'g1'; IsLinked = $true }) } }
New-Fixture $AD ADGPO-003 $R known-bad WARN 'An unlinked GPO exists' @{ Errors = @{}; GroupPolicies = @{ GPOs = @(@{ DisplayName = 'Orphan GPO'; GUID = 'g1'; IsLinked = $false }) } }
New-Fixture $AD ADGPO-003 $R throttled SKIP 'GPOs not collected' @{ Errors = @{ GroupPolicyObjects = 'AD enumeration failed' }; GroupPolicies = @{} }

# ADGPO-004 disabled section but has content
New-Fixture $AD ADGPO-004 $R clean PASS 'No disabled GPOs with settings' @{ Errors = @{}; GroupPolicies = @{ GPOs = @(@{ DisplayName = 'WS Baseline'; GUID = 'g1'; Flags = 0; IsEmpty = $false; FlagDescription = 'Enabled' }) } }
New-Fixture $AD ADGPO-004 $R known-bad WARN 'A GPO has disabled sections but contains settings' @{ Errors = @{}; GroupPolicies = @{ GPOs = @(@{ DisplayName = 'Half-off GPO'; GUID = 'g1'; Flags = 1; IsEmpty = $false; FlagDescription = 'User config disabled' }) } }
New-Fixture $AD ADGPO-004 $R throttled SKIP 'GPOs not collected' @{ Errors = @{ GroupPolicyObjects = 'AD enumeration failed' }; GroupPolicies = @{} }

# ADGPO-005 duplicate GPOs (name patterns: copy/backup/old/v#/test/temp/clone/dup, "(n)")
New-Fixture $AD ADGPO-005 $R clean PASS 'No duplicate-named GPOs' @{ Errors = @{}; GroupPolicies = @{ GPOs = @(@{ DisplayName = 'Workstation Baseline'; GUID = 'g1' }, @{ DisplayName = 'Server Baseline'; GUID = 'g2' }) } }
New-Fixture $AD ADGPO-005 $R known-bad WARN 'A "- Copy" duplicate of a base GPO exists' @{ Errors = @{}; GroupPolicies = @{ GPOs = @(@{ DisplayName = 'Policy A'; GUID = 'g1' }, @{ DisplayName = 'Policy A - Copy'; GUID = 'g2' }) } }
New-Fixture $AD ADGPO-005 $R throttled SKIP 'GPOs not collected' @{ Errors = @{ GroupPolicyObjects = 'AD enumeration failed' }; GroupPolicies = @{} }

# ADGPO-024 WMI filter review — always PASS (+SKIP guard)
New-Fixture $AD ADGPO-024 $R clean PASS 'No WMI filters defined' @{ Errors = @{}; GroupPolicies = @{ WMIFilters = @() } }
New-Fixture $AD ADGPO-024 $R throttled SKIP 'GPOs not collected' @{ Errors = @{ GroupPolicyObjects = 'AD enumeration failed' }; GroupPolicies = @{} }

# ADPWD-018 LAPS type — always PASS (informational) (+SKIP guard)
New-Fixture $AD ADPWD-018 $R clean PASS 'Windows LAPS deployed (informational)' @{ Errors = @{}; PasswordPolicies = @{ LAPSType = 'Windows' } }
New-Fixture $AD ADPWD-018 $R throttled SKIP 'Password policies not collected' @{ Errors = @{ PasswordPolicies = 'AD enumeration failed' }; PasswordPolicies = @{} }

# ADSTALE-009 abandoned OUs — always PASS (+SKIP guard)
New-Fixture $AD ADSTALE-009 $R clean PASS 'No abandoned OUs' @{ Errors = @{}; StaleObjects = @{ AbandonedOUs = @() } }
New-Fixture $AD ADSTALE-009 $R throttled SKIP 'Stale objects not collected' @{ Errors = @{ StaleObjects = 'AD enumeration failed' }; StaleObjects = @{} }

# ADSTALE-010 printer objects — always PASS (+SKIP guard)
New-Fixture $AD ADSTALE-010 $R clean PASS 'No printer objects published' @{ Errors = @{}; StaleObjects = @{ PrinterObjects = @() } }
New-Fixture $AD ADSTALE-010 $R throttled SKIP 'Stale objects not collected' @{ Errors = @{ StaleObjects = 'AD enumeration failed' }; StaleObjects = @{} }

# ───────────────────────── Google / Fortification ─────────────────────────
# ADMIN-007 OU structure — PASS when OrgUnits present / WARN when absent / SKIP on error
New-Fixture $G ADMIN-007 $F clean PASS 'OrgUnit structure available' @{ Errors = @{}; Tenant = @{ OrgUnits = @(@{ orgUnitPath = '/' }, @{ orgUnitPath = '/Staff' }) } }
New-Fixture $G ADMIN-007 $F known-bad WARN 'OrgUnit data unavailable' @{ Errors = @{}; Tenant = @{} }
New-Fixture $G ADMIN-007 $F throttled SKIP 'OrgUnits not collected' @{ Errors = @{ OrgUnits = 'Directory API error' }; Tenant = @{} }

# ADMIN-009 resource-type visibility (googleGroups) — PASS all false / WARN any true / SKIP no policy
New-Fixture $G ADMIN-009 $F clean PASS 'Group membership not externally visible' (Cip 'directory.workspace_resource_type_visibility' @{ googleGroups = $false })
New-Fixture $G ADMIN-009 $F known-bad WARN 'Group membership externally visible' (Cip 'directory.workspace_resource_type_visibility' @{ googleGroups = $true })
New-Fixture $G ADMIN-009 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# AUTH-015 2SV enrollment grace period — PASS <=168h / WARN >168h / SKIP
New-Fixture $G AUTH-015 $F clean PASS 'Grace period 24h (<= 7 days)' (Cip 'security.two_step_verification_grace_period' @{ enrollmentGracePeriod = '86400s' })
New-Fixture $G AUTH-015 $F known-bad WARN 'Grace period 14 days (> 7 days)' (Cip 'security.two_step_verification_grace_period' @{ enrollmentGracePeriod = '1209600s' })
New-Fixture $G AUTH-015 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# AUTH-016 advanced protection self-enrollment — PASS all true / WARN any not-true / SKIP
New-Fixture $G AUTH-016 $F clean PASS 'Advanced Protection self-enrollment enabled' (Cip 'security.advanced_protection_program' @{ enableAdvancedProtectionSelfEnrollment = $true })
New-Fixture $G AUTH-016 $F known-bad WARN 'Advanced Protection self-enrollment disabled' (Cip 'security.advanced_protection_program' @{ enableAdvancedProtectionSelfEnrollment = $false })
New-Fixture $G AUTH-016 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# COLLAB-007 / COLLAB-010 — always WARN (settings not exposed by API)
New-Fixture $G COLLAB-007 $F always-warn WARN 'Chat app installation settings require manual review' @{ Errors = @{} }
New-Fixture $G COLLAB-010 $F always-warn WARN 'Calendar appointment-slot external visibility requires manual review' @{ Errors = @{} }

# COLLAB-011 Meet external participant labeling — PASS all true / WARN any not-true / SKIP
New-Fixture $G COLLAB-011 $F clean PASS 'External participant labeling enabled' (Cip 'meet.safety_external_participants' @{ enableExternalLabel = $true })
New-Fixture $G COLLAB-011 $F known-bad WARN 'External participant labeling disabled' (Cip 'meet.safety_external_participants' @{ enableExternalLabel = $false })
New-Fixture $G COLLAB-011 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# DEVICE-011 company-owned inventory — PASS when devices present / WARN when none / SKIP on error
New-Fixture $G DEVICE-011 $F clean PASS 'Device inventory present' @{ Errors = @{}; MobileDevices = @(@{ status = 'ACTIVE' }); ChromeDevices = @() }
New-Fixture $G DEVICE-011 $F known-bad WARN 'No device inventory found' @{ Errors = @{}; MobileDevices = @(); ChromeDevices = @() }
New-Fixture $G DEVICE-011 $F throttled SKIP 'Device data not collected' @{ Errors = @{ MobileDevices = 'Directory API 429' }; MobileDevices = @(); ChromeDevices = @() }

# DRIVE-012 add-ons — always WARN (not exposed by API)
New-Fixture $G DRIVE-012 $F always-warn WARN 'Drive add-on settings require manual review' @{ Errors = @{} }

# EMAIL-020 Gmail confidential mode — PASS disabled / WARN enabled / SKIP
New-Fixture $G EMAIL-020 $F clean PASS 'Confidential mode disabled' (Cip 'gmail.confidential_mode' @{ enableConfidentialMode = $false })
New-Fixture $G EMAIL-020 $F known-bad WARN 'Confidential mode enabled (exfil vector)' (Cip 'gmail.confidential_mode' @{ enableConfidentialMode = $true })
New-Fixture $G EMAIL-020 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# EMAIL-021 S/MIME user cert upload — PASS admin-managed only / WARN user upload allowed / SKIP
New-Fixture $G EMAIL-021 $F clean PASS 'User certificate upload disallowed' (Cip 'gmail.enhanced_smime_encryption' @{ allowUserToUploadCertificates = $false })
New-Fixture $G EMAIL-021 $F known-bad WARN 'User certificate upload allowed' (Cip 'gmail.enhanced_smime_encryption' @{ allowUserToUploadCertificates = $true })
New-Fixture $G EMAIL-021 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# GWS-SITES-001 service state — PASS DISABLED / WARN ENABLED / SKIP
New-Fixture $G GWS-SITES-001 $F clean PASS 'Sites service disabled' (Cip 'sites.service_status' @{ serviceState = 'DISABLED' })
New-Fixture $G GWS-SITES-001 $F known-bad WARN 'Sites service enabled' (Cip 'sites.service_status' @{ serviceState = 'ENABLED' })
New-Fixture $G GWS-SITES-001 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# GWS-CLASS-004 roster import — PASS OFF / WARN ON_* / SKIP
New-Fixture $G GWS-CLASS-004 $F clean PASS 'Classroom roster import off' (Cip 'classroom.roster_import' @{ rosterImportOption = 'OFF' })
New-Fixture $G GWS-CLASS-004 $F known-bad WARN 'Classroom roster import enabled' (Cip 'classroom.roster_import' @{ rosterImportOption = 'ON_CLEVER' })
New-Fixture $G GWS-CLASS-004 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# GWS-CLASS-005 student unenrollment — PASS TEACHERS_ONLY / WARN students allowed / SKIP
New-Fixture $G GWS-CLASS-005 $F clean PASS 'Only teachers can unenroll students' (Cip 'classroom.student_unenrollment' @{ whoCanUnenrollStudents = 'TEACHERS_ONLY' })
New-Fixture $G GWS-CLASS-005 $F known-bad WARN 'Students can unenroll' (Cip 'classroom.student_unenrollment' @{ whoCanUnenrollStudents = 'STUDENTS_AND_TEACHERS' })
New-Fixture $G GWS-CLASS-005 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# GWS-GEMINI-002/003/004 — always SKIP (not exposed by API)
New-Fixture $G GWS-GEMINI-002 $F not-implemented SKIP 'Gemini Alpha-features setting not exposed via API' @{ Errors = @{} }
New-Fixture $G GWS-GEMINI-003 $F not-implemented SKIP 'Gemini conversation-history setting not exposed via API' @{ Errors = @{} }
New-Fixture $G GWS-GEMINI-004 $F not-implemented SKIP 'Gemini conversation-retention period not exposed via API' @{ Errors = @{} }

# LOG-006 Reports API delegation — PASS no reports-scope grant / WARN reports-scope grant / SKIP
New-Fixture $G LOG-006 $F clean PASS 'No domain-wide delegation grants with Reports access' @{ Errors = @{}; DomainWideDelegation = @(@{ clientId = '100200300'; scopes = @('https://www.googleapis.com/auth/drive.readonly') }) }
New-Fixture $G LOG-006 $F known-bad WARN 'A delegation grant has Reports/Audit API access' @{ Errors = @{}; DomainWideDelegation = @(@{ clientId = '100200300'; scopes = @('https://www.googleapis.com/auth/admin.reports.audit.readonly') }) }
New-Fixture $G LOG-006 $F throttled SKIP 'Domain-wide delegation not collected' @{ Errors = @{ DomainWideDelegation = 'Directory API error' } }

# ───────────────────────── Entra / Infiltration ─────────────────────────
# EIDTNT-014 managed-domain password expiry — PASS never-expire / FAIL finite expiry / SKIP no data
New-Fixture $EN EIDTNT-014 $I clean PASS 'Managed domain passwords set to never expire' @{ Errors = @{}; TenantConfig = @{ Domains = @(@{ id = 'contoso.com'; authenticationType = 'Managed'; passwordValidityPeriodInDays = 2147483647 }) } }
New-Fixture $EN EIDTNT-014 $I known-bad FAIL 'Managed domain enforces finite password expiry' @{ Errors = @{}; TenantConfig = @{ Domains = @(@{ id = 'contoso.com'; authenticationType = 'Managed'; passwordValidityPeriodInDays = 90 }) } }
New-Fixture $EN EIDTNT-014 $I no-data SKIP 'No managed domains expose password validity' @{ Errors = @{}; TenantConfig = @{ Domains = @() } }

Write-Host "`nDone (low tier: 28 checks)."
