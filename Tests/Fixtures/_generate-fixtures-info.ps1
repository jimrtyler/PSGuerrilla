#requires -version 7.0
<#
    Info-tier fixtures (31 checks). Synthetic data only.
    Re-run: pwsh Tests/Fixtures/_generate-fixtures-info.ps1

    AD/Recon (9): ADCS-001/019, ADDOM-006, ADGPO-001, ADKERB-011, ADSCRIPT-003, ADPWD-020, ADTRUST-001/011.
    Entra/Azure/Intune/Infiltration (22): AZIAM-008, EIDAPP-001/016/017, EIDAUTH-001/003/006,
      EIDCA-001/015/016, EIDFED-001/012, EIDPIM-002/011, EIDTNT-001/008/009/010, INTUNE-001/004/014/020.

    Mostly inventory checks: PASS/WARN/SKIP. Reachable FAIL only on EIDCA-015 and INTUNE-001.
    Many are always-PASS (no WARN/FAIL): ADCS-001/019, ADKERB-011, ADSCRIPT-003, ADPWD-020,
      ADTRUST-001/011, EIDAPP-016/017, EIDAUTH-001/003/006, EIDCA-016, EIDFED-012, EIDPIM-002/011,
      EIDTNT-009, INTUNE-020.
    Plain-hashtable shape (no objectShape) — consistent with earlier Entra/Intune tiers.
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family, [string]$CheckId, [string]$Theater, [string]$Scenario, [string]$ExpectedStatus, [string]$Description, [hashtable]$AuditData)
    $obj = [ordered]@{ checkId = $CheckId; theater = $Theater; scenario = $Scenario; expectedStatus = $ExpectedStatus; description = $Description; objectShape = $false; auditData = $AuditData }
    $obj | ConvertTo-Json -Depth 18 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$R = 'Recon'; $I = 'Infiltration'
$AD = 'AD'; $EN = 'Entra'
$skInt = @{ Errors = @{ Intune = 'Graph 429' }; Intune = @{ Errors = @{} } }

# ───────────────────────────── AD / Recon ─────────────────────────────
# ADCS-001 CA inventory — always PASS (+SKIP guard CertificateServices)
New-Fixture $AD ADCS-001 $R clean PASS 'Certificate Authorities inventoried' @{ Errors = @{}; CertificateServices = @{ CertificateAuthorities = @(@{ Name = 'MyCA1'; DNSHostName = 'ca1.contoso.com'; DN = 'CN=MyCA1'; Flags = 0; CertificateTemplates = @(@{ Name = 'Web' }, @{ Name = 'User' }) }) } }
New-Fixture $AD ADCS-001 $R throttled SKIP 'AD CS data not collected' @{ Errors = @{ CertificateServices = 'AD CS enumeration failed' } }

# ADCS-019 template inventory — always PASS (+SKIP guard)
New-Fixture $AD ADCS-019 $R clean PASS 'Certificate templates inventoried' @{ Errors = @{}; CertificateServices = @{ CertificateTemplates = @(@{ Name = 'Web'; DisplayName = 'Web Server'; IsPublished = $true; SchemaVersion = 2; AllowsAuthentication = $true; EnrolleeSuppliesSubject = $false; ExtendedKeyUsage = @(@{ Name = 'Server Authentication' }); EnrollmentPermissions = @() }) } }
New-Fixture $AD ADCS-019 $R throttled SKIP 'AD CS data not collected' @{ Errors = @{ CertificateServices = 'AD CS enumeration failed' } }

# ADDOM-006 FSMO roles — PASS distributed / WARN single DC / SKIP
New-Fixture $AD ADDOM-006 $R clean PASS 'FSMO roles distributed across DCs' @{ Errors = @{}; Domain = @{ FSMORoles = @{ SchemaMaster = 'dc1.contoso.com'; DomainNamingMaster = 'dc2.contoso.com'; PDCEmulator = 'dc1.contoso.com'; RIDMaster = 'dc3.contoso.com'; InfrastructureMaster = 'dc2.contoso.com' } } }
New-Fixture $AD ADDOM-006 $R known-bad WARN 'All FSMO roles on a single DC' @{ Errors = @{}; Domain = @{ FSMORoles = @{ SchemaMaster = 'dc1.contoso.com'; DomainNamingMaster = 'dc1.contoso.com'; PDCEmulator = 'dc1.contoso.com'; RIDMaster = 'dc1.contoso.com'; InfrastructureMaster = 'dc1.contoso.com' } } }
New-Fixture $AD ADDOM-006 $R throttled SKIP 'Domain info not collected' @{ Errors = @{ DomainInfo = 'AD enumeration failed' } }

# ADGPO-001 GPO inventory — PASS present / WARN none / SKIP
New-Fixture $AD ADGPO-001 $R clean PASS 'GPOs inventoried' @{ Errors = @{}; GroupPolicies = @{ GPOs = @(@{ DisplayName = 'Default Domain Policy'; GUID = 'g1'; IsLinked = $true; Flags = 0; FlagDescription = 'Enabled'; IsEmpty = $false }, @{ DisplayName = 'Default Domain Controllers Policy'; GUID = 'g2'; IsLinked = $true; Flags = 0; FlagDescription = 'Enabled'; IsEmpty = $false }) } }
# NOTE: empty GPOs hits the `-not $gpoData.GPOs` guard -> SKIP; the count-0 WARN branch is DEAD CODE (empty-array trap).
New-Fixture $AD ADGPO-001 $R empty-list SKIP 'Empty GPO list reported as Not Assessed (dead WARN branch)' @{ Errors = @{}; GroupPolicies = @{ GPOs = @() } }
New-Fixture $AD ADGPO-001 $R throttled SKIP 'GPOs not collected' @{ Errors = @{ GroupPolicyObjects = 'AD enumeration failed' }; GroupPolicies = @{} }

# ADKERB-011 SPN inventory — always PASS (+SKIP guard KerberosConfig)
New-Fixture $AD ADKERB-011 $R clean PASS 'SPNs and delegation inventoried' @{ Errors = @{}; Kerberos = @{ KerberoastableAccounts = @(@{ SamAccountName = 'svc_web'; SPNs = @('HTTP/web1.contoso.com') }); ConstrainedDelegation = @(@{ SamAccountName = 'svc_proxy'; AllowedToDelegateTo = @('HTTP/intranet.contoso.com') }) } }
New-Fixture $AD ADKERB-011 $R throttled SKIP 'Kerberos config not collected' @{ Errors = @{ KerberosConfig = 'AD enumeration failed' } }

# ADSCRIPT-003 logon script inventory — always PASS (+SKIP guard LogonScripts)
New-Fixture $AD ADSCRIPT-003 $R clean PASS 'Logon scripts inventoried' @{ Errors = @{}; LogonScripts = @{ NetlogonFiles = @(@{ Extension = '.bat' }, @{ Extension = '.ps1' }); UserScripts = @(@{ UserCount = 45 }) } }
New-Fixture $AD ADSCRIPT-003 $R throttled SKIP 'Logon script data not collected' @{ Errors = @{ LogonScripts = 'AD enumeration failed' } }

# ADPWD-020 BitLocker recovery keys — always PASS (no guard)
New-Fixture $AD ADPWD-020 $R clean PASS 'BitLocker recovery keys present (informational)' @{ Errors = @{}; PasswordPolicies = @{ BitLockerKeys = 5 } }

# ADTRUST-001 trust inventory — always PASS (+SKIP guard TrustRelationships)
New-Fixture $AD ADTRUST-001 $R clean PASS 'Trust relationships inventoried' @{ Errors = @{}; Trusts = @(@{ TrustPartner = 'partner.corp.com'; TrustDirection = 'Bidirectional'; TrustType = 'External'; IsTransitive = $false; ForestTransitive = $false; WithinForest = $false; SIDFilteringEnabled = $true; SelectiveAuthentication = $false; IsAzureAD = $false; WhenCreated = '2020-01-15T10:00:00Z'; WhenChanged = '2020-01-15T10:00:00Z' }) }
New-Fixture $AD ADTRUST-001 $R throttled SKIP 'Trust data not collected' @{ Errors = @{ TrustRelationships = 'AD enumeration failed' } }

# ADTRUST-011 trust topology — always PASS (+SKIP guard)
New-Fixture $AD ADTRUST-011 $R clean PASS 'Trust topology mapped' @{ Errors = @{}; Trusts = @(@{ TrustPartner = 'partner.corp.com'; TrustDirection = 'Bidirectional'; TrustType = 'External'; ForestTransitive = $false; WithinForest = $false; IsAzureAD = $false; IsTransitive = $false; SIDFilteringEnabled = $true; SelectiveAuthentication = $false; WhenCreated = '2020-01-15T10:00:00Z'; WhenChanged = '2020-01-15T10:00:00Z' }); Domain = @{ DomainName = 'contoso.com' }; Connection = @{ DomainDN = 'DC=contoso,DC=com' } }
New-Fixture $AD ADTRUST-011 $R throttled SKIP 'Trust data not collected' @{ Errors = @{ TrustRelationships = 'AD enumeration failed' } }

# ───────────────────── Entra / Azure / Intune / Infiltration ─────────────────────
# AZIAM-008 management group structure — PASS groups present / WARN none / SKIP
New-Fixture $EN AZIAM-008 $I clean PASS 'Management group structure present' @{ Errors = @{}; AzureIAM = @{ Errors = @{}; Subscriptions = @(@{ id = 's1' }); ManagementGroups = @(@{ id = 'mg1'; name = 'root'; properties = @{ displayName = 'Tenant Root Group'; tenantId = 't1' } }) } }
New-Fixture $EN AZIAM-008 $I known-bad WARN 'No management groups configured' @{ Errors = @{}; AzureIAM = @{ Errors = @{}; Subscriptions = @(@{ id = 's1' }); ManagementGroups = @() } }
New-Fixture $EN AZIAM-008 $I no-data SKIP 'Azure subscriptions not assessed' @{ Errors = @{}; AzureIAM = @{ Errors = @{ Subscriptions = 'ARM 401' }; Subscriptions = @() } }

# EIDAPP-001 app registration inventory — PASS any / WARN none / SKIP
New-Fixture $EN EIDAPP-001 $I clean PASS 'App registrations / service principals present' @{ Errors = @{}; Applications = @{ Errors = @{}; AppRegistrations = @(@{ appId = 'a1'; displayName = 'App1'; signInAudience = 'AzureADMyOrg'; createdDateTime = '2024-01-01T00:00:00Z' }); ServicePrincipals = @(@{ appId = 'a1'; displayName = 'App1' }) } }
New-Fixture $EN EIDAPP-001 $I known-bad WARN 'No applications or service principals found' @{ Errors = @{}; Applications = @{ Errors = @{}; AppRegistrations = @(); ServicePrincipals = @() } }
New-Fixture $EN EIDAPP-001 $I no-data SKIP 'Applications not assessed' @{ Errors = @{ Applications = 'Graph 429' }; Applications = @{ Errors = @{} } }

# EIDAPP-016 managed identity inventory — PASS / SKIP (no WARN/FAIL)
New-Fixture $EN EIDAPP-016 $I clean PASS 'Managed identities inventoried' @{ Errors = @{}; Applications = @{ Errors = @{}; ServicePrincipals = @(@{ id = 'sp1'; appId = 'a1'; displayName = 'MI1'; servicePrincipalType = 'ManagedIdentity'; accountEnabled = $true }, @{ id = 'sp2'; appId = 'a2'; displayName = 'App'; servicePrincipalType = 'Application'; accountEnabled = $true }) } }
New-Fixture $EN EIDAPP-016 $I no-data SKIP 'No service principals to assess' @{ Errors = @{}; Applications = @{ Errors = @{}; ServicePrincipals = @() } }

# EIDAPP-017 SP sign-in activity — PASS / SKIP
New-Fixture $EN EIDAPP-017 $I clean PASS 'Service principal sign-in activity present' @{ Errors = @{}; Applications = @{ Errors = @{}; ServicePrincipals = @(@{ id = 'sp1'; displayName = 'App1'; signInActivity = @{ lastSignInDateTime = '2026-06-01T00:00:00Z' } }) } }
New-Fixture $EN EIDAPP-017 $I no-data SKIP 'No service principal sign-in data' @{ Errors = @{}; Applications = @{ Errors = @{}; ServicePrincipals = @() } }

# EIDAUTH-001 auth methods policy — PASS / SKIP
New-Fixture $EN EIDAUTH-001 $I clean PASS 'Authentication methods policy present' @{ Errors = @{}; AuthMethods = @{ AuthMethodsPolicy = @{ id = 'authenticationMethodsPolicy' }; MethodConfigurations = @(@{ id = 'fido2'; state = 'enabled' }, @{ id = 'sms'; state = 'disabled' }) } }
New-Fixture $EN EIDAUTH-001 $I no-data SKIP 'Authentication methods policy not available' @{ Errors = @{}; AuthMethods = @{ AuthMethodsPolicy = $null } }

# EIDAUTH-003 MFA method distribution — PASS / SKIP
New-Fixture $EN EIDAUTH-003 $I clean PASS 'MFA registration details present' @{ Errors = @{}; AuthMethods = @{ UserRegistrationDetails = @(@{ methodsRegistered = @('microsoftAuthenticatorPush', 'fido2') }, @{ methodsRegistered = @('sms') }) } }
New-Fixture $EN EIDAUTH-003 $I no-data SKIP 'No registration details to assess' @{ Errors = @{}; AuthMethods = @{ UserRegistrationDetails = @() } }

# EIDAUTH-006 FIDO2 inventory — PASS / SKIP
New-Fixture $EN EIDAUTH-006 $I clean PASS 'FIDO2 security key registrations inventoried' @{ Errors = @{}; AuthMethods = @{ UserRegistrationDetails = @(@{ methodsRegistered = @('fido2') }, @{ methodsRegistered = @('sms') }) } }
New-Fixture $EN EIDAUTH-006 $I no-data SKIP 'No registration details to assess' @{ Errors = @{}; AuthMethods = @{ UserRegistrationDetails = $null } }

# EIDCA-001 CA policy inventory — PASS any / WARN none / SKIP
New-Fixture $EN EIDCA-001 $I clean PASS 'Conditional Access policies inventoried' @{ Errors = @{}; ConditionalAccess = @{ Errors = @{}; Policies = @(@{ id = 'p1'; displayName = 'Require MFA'; state = 'enabled'; createdDateTime = '2024-01-01T00:00:00Z'; modifiedDateTime = '2024-06-01T00:00:00Z' }) } }
New-Fixture $EN EIDCA-001 $I known-bad WARN 'No Conditional Access policies found' @{ Errors = @{}; ConditionalAccess = @{ Errors = @{}; Policies = @() } }
New-Fixture $EN EIDCA-001 $I no-data SKIP 'Conditional Access not assessed' @{ Errors = @{ ConditionalAccess = 'Graph 429' }; ConditionalAccess = @{ Errors = @{} } }

# EIDCA-015 What-If simulation — PASS protective / FAIL gap / SKIP
New-Fixture $EN EIDCA-015 $I clean PASS 'What-If: all scenarios protected' @{ Errors = @{}; ConditionalAccess = @{ Errors = @{}; WhatIf = @(@{ Verdict = 'PASS'; Name = 'Admins blocked from legacy auth'; Result = 'blocked' }) } }
New-Fixture $EN EIDCA-015 $I known-bad FAIL 'What-If: protection gap found' @{ Errors = @{}; ConditionalAccess = @{ Errors = @{}; WhatIf = @(@{ Verdict = 'FAIL'; Name = 'Legacy auth permitted'; Result = 'allowed' }) } }
New-Fixture $EN EIDCA-015 $I no-data SKIP 'No What-If results or enabled policies' @{ Errors = @{}; ConditionalAccess = @{ Errors = @{}; WhatIf = @(); Policies = @() } }

# EIDCA-016 policy documentation export — PASS / SKIP
New-Fixture $EN EIDCA-016 $I clean PASS 'Conditional Access policies exported' @{ Errors = @{}; ConditionalAccess = @{ Errors = @{}; Policies = @(@{ id = 'p1'; displayName = 'Require MFA'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All') } }; grantControls = @{ builtInControls = @('mfa') } }) } }
New-Fixture $EN EIDCA-016 $I no-data SKIP 'No policies to export' @{ Errors = @{}; ConditionalAccess = @{ Errors = @{}; Policies = @() } }

# EIDFED-001 domain enumeration — PASS any / WARN none / SKIP
New-Fixture $EN EIDFED-001 $I clean PASS 'Domains enumerated' @{ Errors = @{}; Federation = @{ Errors = @{}; Domains = @(@{ id = 'contoso.com'; authenticationType = 'Managed'; isVerified = $true; isDefault = $true; isAdminManaged = $true; supportedServices = @('Email') }) } }
New-Fixture $EN EIDFED-001 $I known-bad WARN 'No domains found' @{ Errors = @{}; Federation = @{ Errors = @{}; Domains = @() } }
New-Fixture $EN EIDFED-001 $I no-data SKIP 'Federation not assessed' @{ Errors = @{ Federation = 'Graph 429' }; Federation = @{ Errors = @{} } }

# EIDFED-012 cloud vs synced users — PASS / SKIP
New-Fixture $EN EIDFED-012 $I clean PASS 'Cloud-only vs synced user counts available' @{ Errors = @{}; Federation = @{ Errors = @{}; Users = @{ CloudOnlyCount = 120; SyncedCount = 45 } } }
New-Fixture $EN EIDFED-012 $I no-data SKIP 'User identity-source counts not collected' @{ Errors = @{}; Federation = @{ Errors = @{}; Users = @{ CloudOnlyCount = -1; SyncedCount = -1 } } }

# EIDPIM-002 privileged role assignments — PASS / SKIP
New-Fixture $EN EIDPIM-002 $I clean PASS 'Privileged role assignments inventoried' @{ Errors = @{}; PIM = @{ Errors = @{}; RoleAssignments = @(@{ principalId = 'u1'; roleDefinitionId = 'r1'; directoryScopeId = '/' }); RoleEligibilitySchedules = @(@{ principalId = 'u2'; roleDefinitionId = 'r1' }); RoleDefinitions = @(@{ id = 'r1'; displayName = 'Global Administrator' }) } }
New-Fixture $EN EIDPIM-002 $I no-data SKIP 'PIM not assessed' @{ Errors = @{ PIM = 'Graph 429' }; PIM = @{ Errors = @{} } }

# EIDPIM-011 activation history — PASS / SKIP
New-Fixture $EN EIDPIM-011 $I clean PASS 'PIM activation/assignment schedules present' @{ Errors = @{}; PIM = @{ Errors = @{}; RoleAssignmentSchedules = @(@{ assignmentType = 'Activated' }, @{ assignmentType = 'Assigned' }) } }
New-Fixture $EN EIDPIM-011 $I no-data SKIP 'No assignment schedules to assess' @{ Errors = @{}; PIM = @{ Errors = @{}; RoleAssignmentSchedules = $null } }

# EIDTNT-001 organization config — PASS org present / WARN org null / SKIP
New-Fixture $EN EIDTNT-001 $I clean PASS 'Tenant organization config present' @{ Errors = @{}; TenantConfig = @{ Errors = @{}; Organization = @{ id = 't1'; displayName = 'Contoso'; countryLetterCode = 'US'; createdDateTime = '2018-01-01T00:00:00Z'; verifiedDomains = @(@{ name = 'contoso.com' }); assignedPlans = @() } } }
New-Fixture $EN EIDTNT-001 $I known-bad WARN 'Organization data unavailable' @{ Errors = @{}; TenantConfig = @{ Errors = @{}; Organization = $null } }
New-Fixture $EN EIDTNT-001 $I no-data SKIP 'Tenant config not assessed' @{ Errors = @{ TenantConfig = 'Graph 429' }; TenantConfig = @{ Errors = @{} } }

# EIDTNT-008 subscribed SKUs — PASS present / WARN none / SKIP
New-Fixture $EN EIDTNT-008 $I clean PASS 'Subscribed SKUs inventoried' @{ Errors = @{}; TenantConfig = @{ Errors = @{}; SubscribedSkus = @(@{ skuPartNumber = 'ENTERPRISEPREMIUM'; skuId = 'sku1'; capabilityStatus = 'Enabled'; consumedUnits = 50; prepaidUnits = @{ enabled = 100; suspended = 0; warning = 0 } }) } }
New-Fixture $EN EIDTNT-008 $I known-bad WARN 'No subscribed SKUs found' @{ Errors = @{}; TenantConfig = @{ Errors = @{}; SubscribedSkus = @() } }
New-Fixture $EN EIDTNT-008 $I no-data SKIP 'Tenant config not assessed' @{ Errors = @{ TenantConfig = 'Graph 429' }; TenantConfig = @{ Errors = @{} } }

# EIDTNT-009 administrative units — PASS (always) / SKIP
New-Fixture $EN EIDTNT-009 $I clean PASS 'Administrative units inventoried' @{ Errors = @{}; TenantConfig = @{ Errors = @{}; AdminUnits = @(@{ id = 'au1'; displayName = 'West Region'; isMemberManagementRestricted = $false; visibility = 'Public' }) } }
New-Fixture $EN EIDTNT-009 $I no-data SKIP 'Tenant config not assessed' @{ Errors = @{ TenantConfig = 'Graph 429' }; TenantConfig = @{ Errors = @{} } }

# EIDTNT-010 domain verification — PASS all verified / WARN unverified / SKIP
New-Fixture $EN EIDTNT-010 $I clean PASS 'All domains verified' @{ Errors = @{}; TenantConfig = @{ Errors = @{}; Domains = @(@{ id = 'contoso.com'; isVerified = $true; isDefault = $true; isInitial = $false; authenticationType = 'Managed'; isAdminManaged = $true; supportedServices = @('Email') }) } }
New-Fixture $EN EIDTNT-010 $I known-bad WARN 'An unverified domain exists' @{ Errors = @{}; TenantConfig = @{ Errors = @{}; Domains = @(@{ id = 'contoso.com'; isVerified = $true; isDefault = $true; isInitial = $false; authenticationType = 'Managed' }, @{ id = 'pending.com'; isVerified = $false; isDefault = $false; isInitial = $false; authenticationType = 'Managed' }) } }
New-Fixture $EN EIDTNT-010 $I no-data SKIP 'Tenant config not assessed' @{ Errors = @{ TenantConfig = 'Graph 429' }; TenantConfig = @{ Errors = @{} } }

# INTUNE-001 compliance policies — PASS present / FAIL none / SKIP
New-Fixture $EN INTUNE-001 $I clean PASS 'Compliance policies present' @{ Errors = @{}; Intune = @{ Errors = @{}; CompliancePolicies = @(@{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'c1'; displayName = 'Win10 Baseline'; createdDateTime = '2024-01-01T00:00:00Z' }) } }
New-Fixture $EN INTUNE-001 $I known-bad FAIL 'No compliance policies configured' @{ Errors = @{}; Intune = @{ Errors = @{}; CompliancePolicies = @() } }
New-Fixture $EN INTUNE-001 $I throttled SKIP 'Intune compliance policies not assessed' $skInt

# INTUNE-004 device configuration profiles — PASS present / WARN none / SKIP
New-Fixture $EN INTUNE-004 $I clean PASS 'Device configuration profiles present' @{ Errors = @{}; Intune = @{ Errors = @{}; DeviceConfigurations = @(@{ '@odata.type' = '#microsoft.graph.windows10GeneralConfiguration'; id = 'd1'; displayName = 'Win10 Config'; createdDateTime = '2024-01-01T00:00:00Z' }) } }
New-Fixture $EN INTUNE-004 $I known-bad WARN 'No device configuration profiles found' @{ Errors = @{}; Intune = @{ Errors = @{}; DeviceConfigurations = @() } }
New-Fixture $EN INTUNE-004 $I throttled SKIP 'Intune device configurations not assessed' $skInt

# INTUNE-014 Autopilot profiles — PASS present / WARN none / SKIP
New-Fixture $EN INTUNE-014 $I clean PASS 'Autopilot deployment profiles present' @{ Errors = @{}; Intune = @{ Errors = @{}; AutopilotProfiles = @(@{ id = 'ap1'; displayName = 'Standard Autopilot'; deviceNameTemplate = 'CONTOSO-%SERIAL%'; language = 'en-US'; extractHardwareHash = $true }) } }
New-Fixture $EN INTUNE-014 $I known-bad WARN 'No Autopilot profiles configured' @{ Errors = @{}; Intune = @{ Errors = @{}; AutopilotProfiles = @() } }
New-Fixture $EN INTUNE-014 $I throttled SKIP 'Intune Autopilot profiles not assessed' $skInt

# INTUNE-020 device categories — PASS (always) / SKIP
New-Fixture $EN INTUNE-020 $I clean PASS 'Device categories inventoried' @{ Errors = @{}; Intune = @{ Errors = @{}; DeviceCategories = @(@{ id = 'dc1'; displayName = 'Corporate'; description = 'Company-owned' }) } }
New-Fixture $EN INTUNE-020 $I throttled SKIP 'Intune device categories not assessed' $skInt

Write-Host "`nDone (info tier: 31 checks)."
