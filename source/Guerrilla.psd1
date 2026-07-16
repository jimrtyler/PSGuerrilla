@{
    RootModule        = 'Guerrilla.psm1'
    ModuleVersion     = '2.51.0'
    GUID              = 'f7a3b2c1-4d5e-6f78-9a0b-1c2d3e4f5a6b'
    Author            = 'Jim Tyler, Microsoft MVP'
    CompanyName       = 'Jim Tyler'
    Copyright         = '(c) 2026 Jim Tyler. All rights reserved.'
    Description       = 'Agentless, read-only, point-in-time security assessment for PowerShell 7 across three platforms: on-premises Active Directory (211 checks across 15 categories including transitive Tier-0 attack-path analysis, certificate-services ESC1-ESC16, NTLM-relay preconditions, telemetry posture, and adversary tradecraft indicators), the Entra ID / Azure / Intune / M365 identity plane (257 checks including a full 44-control EIDSCA baseline, conditional access, PIM, application and OAuth governance, Exchange Online, SharePoint, Teams, Defender, and entitlement-management hygiene), and Google Workspace (168 checks aligned to the CISA SCuBA baselines, plus the first K12 candidate baseline checks with student-OU scoping). 636 checks total, each mapped to NIST 800-53, MITRE ATT&CK, CIS, EIDSCA, and CISA SCuBA where applicable and carrying a CISA Zero Trust pillar and weight, and each verdict validated by a golden-fixture test (1,829 fixtures). Every run is recorded locally and compared against your previous run: the report opens with what changed, including newly failing checks, confirmed remediations, and any check that went dark. Local history on your machine, no accounts, no telemetry.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Set-Safehouse'
        'Test-Safehouse'
        'Get-Safehouse'
        'Invoke-GWSAudit'
        'Invoke-ADAudit'
        'Invoke-EntraAudit'
        # Deprecated wrappers for the renamed audits; removed in the next major version.
        'Invoke-Fortification'
        'Invoke-Reconnaissance'
        'Invoke-Infiltration'
        'Invoke-Campaign'
        'Get-GuerrillaScore'
        'Get-GuerrillaMaturity'
        'Get-QuickWins'
        'Get-ComplianceCrosswalk'
        'Test-GuerrillaConditionalAccess'
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
        'Export-BloodHoundData'
        'Export-GuerrillaJUnit'
        'Get-GuerrillaCIGate'
        'Show-Guerrilla'
        'Get-ZeroTrustScore'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @(
        'Set-ReconConfig'
        'Get-ReconConfig'
        'Invoke-ADRecon'
        'Invoke-CloudRecon'
    )
    FormatsToProcess   = @('Guerrilla.format.ps1xml')
    PrivateData = @{
        PSData = @{
            Tags       = @('GoogleWorkspace', 'ActiveDirectory', 'EntraID', 'AzureAD', 'Intune', 'M365', 'Security', 'SecurityAssessment', 'ADSecurity', 'CloudSecurity', 'NTLMRelay', 'TierZero', 'GUI', 'WPF', 'Guerrilla')
            LicenseUri = 'https://creativecommons.org/licenses/by/4.0/'
            ProjectUri = 'https://guerrilla.army'
            ReleaseNotes = 'Guerrilla (formerly PSGuerrilla). v2.51.0: The desktop GUI is multilingual, starting with Spanish, on an architecture built to scale. Every user-visible string comes from locale catalogs (English source plus Spanish with per-key translation provenance, the same machine-draft / human-reviewed convention the website uses). A language selector in the header switches the whole window live with no restart, exactly the way the theme toggle works, and the choice persists in config next to the theme; first launch follows the OS display language when a matching catalog exists. Adding a future language is adding one catalog file: the selector discovers catalogs at runtime. Localized labels are decoupled from the canonical values passed to cmdlets, and a new localization gate fails the build if a GUI string is missing from the English catalog or a shipped language is incomplete, with a poison self-test proving the gate can fail. v2.50.0: Every generated report is rebuilt from scratch on the website''s design system, so guerrilla.army, the desktop GUI, and the HTML reports read as one product. All ten HTML outputs (the AD, Entra, and Google Workspace reports, the unified Campaign report, the trend report, the dashboard, the technical report, the executive summary, the remediation playbook, and the budget justification) share one theme engine mirroring the site''s contrast-verified light and dark tokens, one component stylesheet, and one shared shell: a sticky header with the Guerrilla wordmark and a light/dark toggle, the white-label banner and firm header when branding is configured, and the standard footer. Reports default to following the viewer''s OS theme (-ReportStyle Auto) and the in-report toggle switches instantly with the choice remembered per browser; Light and Dark force an initial theme, and the legacy style names keep working everywhere (Professional maps to Light; Guerrilla and Slate map to Dark). Printing and Export-ReportPdf always render the light palette. The interactive findings filter, run comparison, Security Maturity, Indicators of Exposure, Attack-Path Cartography, and attack-path sections carry over restyled; none of their logic changed. v2.49.0: The GUI is rebuilt to look like guerrilla.army and to make running an audit a one-click act. Show-Guerrilla now follows the same design tokens as the website (flat surfaces, pill buttons, near-invisible borders, contrast-verified color pairs) with a light and dark theme whose toggle persists in your config; first launch follows the OS app theme. The window is borderless with its own header navigation and caption buttons instead of standard Windows chrome, with subtle page transitions and a live progress sweep during runs. The former Operations tab is now a Run page with exactly one button per platform: Active Directory, Entra/Azure/M365, Google Workspace, plus Campaign for everything. Scan depth, categories, report style, student OUs, and the output directory moved into an Options drawer with working defaults, so the common path is click and read the report. The add-credential dialog matches the new look and inherits the active theme. Underneath, nothing moved: the GUI still wraps the same public cmdlets, -StartOn accepts the same values, and the CLI remains the cross-platform source of truth. v2.48.0: The K12 Secure Configuration Baseline arrives: a Guerrilla-authored candidate community baseline for school districts, openly published, versioned, open for comment, and clearly labeled as expert opinion rather than a consensus standard. School tenants hold adults and minors in one tenant with legally distinct duties toward each, and the boundary between them is an OU subtree, not the tenant; no consensus baseline assesses that boundary. Ten new Google Workspace checks (GWS-K12-001 through GWS-K12-010) assess ten of its twelve controls: staff-default sharing inheritance, student external Drive sharing, third-party app authorization for students, vendor delegated-access review, delegated admin least privilege, student communication boundaries in Chat and Meet, guardian access integrity, managed Chromebook posture, departed-student account disposition, and an age-banded account security floor that treats missing 2SV as context for young students rather than a blind failure. A new -StudentOU parameter designates which OU subtrees hold student accounts (Invoke-GWSAudit, Invoke-ADAudit, Invoke-Campaign, and a Student OUs field in the GUI); it is a designation, not a collection filter, and OU-scoped checks report Not Assessed without it instead of silently assessing the whole tenant as if it were the student population. The OU scope joins the run-history comparison identity, so a student-scoped run is never diffed against a whole-tenant run; this also fixes a latent issue where -TargetOU runs shared a comparison series with whole-tenant runs (existing whole-tenant baselines are unaffected). Every policy setting type and enum direction was verified against the Policy API catalog and CISA published assessment logic before verdict code was written, and 63 new golden fixtures cover every declared verdict branch, including the required no-scope and OU-absent branches. Chrome policies now additionally resolve per student OU. The baseline document ships in docs/baselines/ and is enforced by a completeness gate: a check claiming an undefined control, or the document overstating coverage, is a red build. See CHANGELOG.md for earlier releases.'
        }
    }
}
