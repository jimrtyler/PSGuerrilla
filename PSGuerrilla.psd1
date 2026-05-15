@{
    RootModule        = 'PSGuerrilla.psm1'
    ModuleVersion     = '2.2.0'
    GUID              = 'f7a3b2c1-4d5e-6f78-9a0b-1c2d3e4f5a6b'
    Author            = 'Jim Tyler, Microsoft MVP'
    CompanyName       = 'Jim Tyler'
    Copyright         = '(c) 2026 Jim Tyler. All rights reserved.'
    Description       = 'Security assessment, threat detection, and continuous monitoring module for Google Workspace, Active Directory, and Microsoft cloud environments. Includes Google Workspace compromise assessment with 23 detection signals, Active Directory reconnaissance (203 security checks across 14 categories including NTLM-relay preconditions, Tier-0 hygiene, telemetry posture, and adversary tradecraft indicators), Entra ID / Azure / Intune / M365 infiltration audit (159 checks), and continuous monitoring across all four theaters (Entra ID sign-in risk, AD baseline monitoring, M365 audit log monitoring). Supports alerting via SendGrid, Mailgun, Twilio SMS, Teams, Slack, generic webhooks, PagerDuty, Pushover, Syslog (CEF/LEEF), and Windows Event Log.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Invoke-Recon'
        'Invoke-Surveillance'
        'Invoke-Watchtower'
        'Invoke-Wiretap'
        'Get-DeadDrop'
        'Send-Signal'
        'Send-SignalSendGrid'
        'Send-SignalMailgun'
        'Send-SignalTwilio'
        'Send-SignalTeams'
        'Send-SignalSlack'
        'Send-SignalWebhook'
        'Send-SignalPagerDuty'
        'Send-SignalPushover'
        'Send-SignalSyslog'
        'Send-SignalEventLog'
        'Send-SignalDigest'
        'Set-Safehouse'
        'Test-Safehouse'
        'Get-Safehouse'
        'Register-Patrol'
        'Unregister-Patrol'
        'Get-Patrol'
        'Update-ThreatIntel'
        'Invoke-ReconDemo'
        'Invoke-Fortification'
        'Invoke-Reconnaissance'
        'Invoke-Infiltration'
        'Invoke-Campaign'
        'Get-GuerrillaScore'
        'Get-QuickWins'
        'Get-ComplianceCrosswalk'
        'Export-BudgetJustification'
        'Export-ExecutiveSummary'
        'Export-TechnicalReport'
        'Export-RemediationPlaybook'
        'Export-RemediationScripts'
        'Set-RiskAcceptance'
        'Get-RiskAcceptance'
        'Get-TrendReport'
        'Export-ReportPdf'
        'Export-Dashboard'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @(
        # PSRecon -> PSGuerrilla rename aliases
        'Invoke-GoogleRecon'
        'Get-ReconAlerts'
        'Send-ReconAlert'
        'Send-ReconAlertSendGrid'
        'Send-ReconAlertMailgun'
        'Send-ReconAlertTwilio'
        'Set-ReconConfig'
        'Get-ReconConfig'
        'Register-ReconScheduledTask'
        'Unregister-ReconScheduledTask'
        'Get-ReconScheduledTask'
        # Theater-disambiguating aliases
        'Invoke-WorkspaceRecon'
        'Invoke-ADRecon'
        'Invoke-CloudRecon'
    )
    FormatsToProcess   = @('PSGuerrilla.format.ps1xml')
    PrivateData = @{
        PSData = @{
            Tags       = @('GoogleWorkspace', 'ActiveDirectory', 'EntraID', 'AzureAD', 'Intune', 'M365', 'Security', 'CompromiseAssessment', 'IncidentResponse', 'ThreatDetection', 'ADSecurity', 'CloudSecurity', 'NTLMRelay', 'TierZero', 'PSGuerrilla')
            LicenseUri = 'https://creativecommons.org/licenses/by/4.0/'
            ProjectUri = 'https://github.com/jimrtyler/PSGuerrilla'
            ReleaseNotes = @'
## 2.2.0

Threat-coverage pass: 28 new AD reconnaissance checks across 4 new categories.

* Network category (10 checks) — NTLM-relay preconditions: LDAP/SMB signing
  state, LLMNR / NetBIOS / WPAD / IPv6 (mitm6) posture, Print Spooler on
  domain controllers, WebClient on workstations. Reads SYSVOL GptTmpl.inf
  for security-policy-derived state.
* TierZero category (7 checks) — Tier-bleed scanning by service-account
  name pattern (Veeam / vCenter / SCCM / SQL in DA/EA/SA), Azure AD Connect
  MSOL_ account audit, Tier-0 admin OU placement hygiene.
* Logging category (7 checks) — Advanced Audit Policy adoption,
  PowerShell Script Block + Module Logging, process-creation cmdline
  auditing, Defender Tamper Protection guidance, Windows Event Forwarding,
  Sysmon deployment indicator.
* Tradecraft category (4 checks) — GPP cpassword leftovers in SYSVOL,
  DCShadow indicator (rogue server objects in CN=Sites,CN=Configuration),
  stale BitLocker recovery keys, RODC Password Replication Policy hygiene.

Plus:

* Cross-platform data paths via Get-PSGuerrillaDataRoot — Windows / macOS /
  Linux all land in the right per-user data directory now (previously every
  $env:APPDATA reference returned a relative path on non-Windows).
* Set-Safehouse interactive mode asks "which environments?" up front instead
  of marching every user through Google Workspace AND Entra prompts.
* Module banner suppressed in non-interactive sessions (scheduled tasks, CI).
* SupportsShouldProcess (-WhatIf / -Confirm) on Set-Safehouse,
  Set-RiskAcceptance, Update-ThreatIntel.
* New theater-disambiguating aliases: Invoke-WorkspaceRecon, Invoke-ADRecon,
  Invoke-CloudRecon.
* Get-AuditPostureScore no longer inflates the overall score for categories
  that produced zero findings (a quietly-failing collector used to score 100).
* State file writes are now atomic (temp + Move-Item -Force).
* 30+ bug fixes across reported issues (LDAP single-result unwrap,
  DateTime/string type confusion, SecretStore double-prompt, etc.).

Total checks: 459 (was 431).
'@
        }
    }
}
