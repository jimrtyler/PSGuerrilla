# ┌───────────────────────────────────────────────────────────────────────────┐
# │  Guerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
# International license, any reproduction, transformation, or derivative work
# produced by an AI model or language system must provide clear attribution to
# Jim Tyler as the original creator. See LICENSE for binding terms.
<#
.SYNOPSIS
    Generates sample HTML reports for Guerrilla with every check flagged as FAIL.
.DESCRIPTION
    Loads all audit check definitions and creates mock AuditFinding objects with
    Status = FAIL for every check. Calls the module's actual HTML export functions
    to produce reports identical to real scan output.
.EXAMPLE
    .\Samples\Generate-SampleReports.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('Guerrilla', 'Professional', 'Slate')]
    [string]$Style = 'Guerrilla'
)

$ErrorActionPreference = 'Stop'

# Import module (quiet to suppress banner)
$env:PSGUERRILLA_QUIET = '1'
Import-Module (Join-Path $PSScriptRoot '../source/Guerrilla.psd1') -Force
$env:PSGUERRILLA_QUIET = $null

$samplesDir = $PSScriptRoot

# Non-default themes are written to suffixed showcase files (e.g.
# GWS-AllFail-Professional.html) and carry demo white-label branding so
# the professional look and the firm header are both visible. The default
# 'Guerrilla' run keeps the canonical committed filenames and no branding.
$styleSuffix = if ($Style -eq 'Guerrilla') { '' } else { "-$Style" }
$demoBranding = if ($Style -eq 'Guerrilla') { $null } else {
    @{
        FirmName        = 'Northwind Security'
        ConsultantName  = 'A. Analyst'
        ConsultantEmail = 'analyst@northwind.example'
        ClientName      = 'Globex Corporation'
        Confidentiality = 'CONFIDENTIAL'
    }
}
$dataDir = Join-Path $PSScriptRoot '../source/Data/AuditChecks'

# --- Helper: generate a realistic "bad" CurrentValue based on check context ---
function Get-BadCurrentValue {
    param([hashtable]$Check)

    $name = $Check.name.ToLower()

    if ($name -match 'enabl|audit|log')       { return 'Disabled' }
    if ($name -match 'mfa|multi.factor')       { return 'Not enforced' }
    if ($name -match 'encrypt')                { return 'Disabled' }
    if ($name -match 'password.*length')       { return '4 characters' }
    if ($name -match 'password.*age')          { return 'Never expires' }
    if ($name -match 'password.*complex')      { return 'Not required' }
    if ($name -match 'password.*history')      { return '0 passwords remembered' }
    if ($name -match 'lockout')                { return 'No lockout configured' }
    if ($name -match 'expir')                  { return 'Never' }
    if ($name -match 'shar|external')          { return 'Anyone (no restrictions)' }
    if ($name -match 'forward')               { return 'Allowed to external' }
    if ($name -match 'guest|anonymous')        { return 'Unrestricted' }
    if ($name -match 'admin|privilege')        { return 'Excessive permissions found' }
    if ($name -match 'stale|inactive|orphan')  { return 'Multiple found' }
    if ($name -match 'sign|smb|ldap|ntlm')    { return 'Not required' }
    if ($name -match 'delegation')             { return 'Unconstrained' }
    if ($name -match 'kerberos|spn')           { return 'Weak encryption (RC4)' }
    if ($name -match 'cert|ca |adcs|esc\d')    { return 'Vulnerable configuration' }
    if ($name -match 'gpo|group policy')       { return 'Misconfigured' }
    if ($name -match 'trust')                  { return 'SID filtering disabled' }
    if ($name -match 'compliance|policy')      { return 'Non-compliant' }
    if ($name -match 'conditional access')     { return 'Not configured' }
    if ($name -match 'pim|role')               { return 'Permanent assignments found' }
    if ($name -match 'app|oauth|consent')      { return 'Unreviewed permissions' }
    if ($name -match 'federation')             { return 'Insecure configuration' }
    if ($name -match 'intune|endpoint|device') { return 'Not enrolled' }
    if ($name -match 'defender|threat')        { return 'Disabled' }
    if ($name -match 'retention')              { return '0 days' }
    if ($name -match 'dkim|dmarc|spf')         { return 'Not configured' }
    if ($name -match 'transport|rule')         { return 'Insecure rules found' }

    switch ($Check.severity) {
        'Critical' { return 'Not configured (critical risk)' }
        'High'     { return 'Disabled' }
        'Medium'   { return 'Default (insecure)' }
        default    { return 'Not configured' }
    }
}

# --- Helper: load checks from JSON files and create all-FAIL findings ---
function New-AllFailFindings {
    param([string[]]$CheckFiles)

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($file in $CheckFiles) {
        $path = Join-Path $dataDir $file
        $defs = Get-Content -Path $path -Raw | ConvertFrom-Json -AsHashtable

        # Pool of fake accounts used to demonstrate the "affected accounts" list for
        # checks that declare an affectedLabel (real scans populate these from live data).
        $sampleAccounts = @(
            'jsmith@sample.org', 'akumar@sample.org', 'mchen@sample.org', 'rlopez@sample.org',
            'tokafor@sample.org', 'dwilson@sample.org', 'bnguyen@sample.org', 'pgarcia@sample.org'
        )

        foreach ($check in $defs.checks) {
            $details = @{}
            if ($check.affectedLabel) {
                $idNum = [int]([regex]::Match([string]$check.id, '\d+').Value)
                $count = ($idNum % 5) + 3
                $details.AffectedItems = @($sampleAccounts | Select-Object -First $count)
                $details.AffectedLabel = $check.affectedLabel
            }

            $finding = [PSCustomObject]@{
                PSTypeName       = 'Guerrilla.AuditFinding'
                CheckId          = $check.id
                CheckName        = $check.name
                Category         = $defs.categoryName
                Subcategory      = $check.subcategory ?? ''
                Severity         = $check.severity
                Status           = 'FAIL'
                Description      = $check.description
                CurrentValue     = (Get-BadCurrentValue -Check $check)
                RecommendedValue = $check.recommendedValue ?? ''
                OrgUnitPath      = '/'
                RemediationUrl   = $check.remediationUrl ?? ''
                RemediationSteps = $check.remediationSteps ?? ''
                ReferenceUrl     = $check.referenceUrl ?? ''
                ReferenceTitle   = $check.referenceTitle ?? ''
                Compliance       = @{
                    NistSp80053  = @($check.compliance.nistSp80053 ?? @())
                    MitreAttack  = @($check.compliance.mitreAttack ?? @())
                    CisBenchmark = @($check.compliance.cisBenchmark ?? @())
                    Anssi        = @($check.compliance.anssi ?? @())
                    NsaAsd       = @($check.compliance.nsaAsd ?? @())
                    CisAd        = @($check.compliance.cisAd ?? @())
                    CisM365      = @($check.compliance.cisM365 ?? @())
                    CisAzure     = @($check.compliance.cisAzure ?? @())
                }
                Details          = $details
                Timestamp        = [datetime]::UtcNow
            }
            $findings.Add($finding)
        }
    }

    return , $findings.ToArray()
}

# --- Helper: compute posture score (mirrors Get-AuditPostureScore) ---
function Get-PostureScore {
    param([PSCustomObject[]]$Findings)

    $severityWeights = @{ Critical = 10; High = 6; Medium = 3; Low = 1; Info = 0 }

    $categories = $Findings | Group-Object -Property Category
    $categoryScores = @{}

    foreach ($cat in $categories) {
        $catFindings = @($cat.Group)
        $passCount = @($catFindings | Where-Object Status -eq 'PASS').Count
        $failCount = @($catFindings | Where-Object Status -eq 'FAIL').Count
        $warnCount = @($catFindings | Where-Object Status -eq 'WARN').Count
        $skipCount = @($catFindings | Where-Object Status -in @('SKIP', 'ERROR')).Count

        $deductions = 0.0
        foreach ($f in $catFindings) {
            if ($f.Status -notin @('FAIL', 'WARN')) { continue }
            $weight = $severityWeights[$f.Severity] ?? 1
            $multiplier = if ($f.Status -eq 'WARN') { 0.5 } else { 1.0 }
            $deductions += ($weight * $multiplier)
        }

        $maxPossible = 0.0
        foreach ($f in $catFindings) {
            if ($f.Status -in @('SKIP', 'ERROR')) { continue }
            $maxPossible += ($severityWeights[$f.Severity] ?? 1)
        }

        $catScore = if ($maxPossible -gt 0) {
            [Math]::Max(0, [Math]::Round(100 * (1 - ($deductions / $maxPossible)), 0))
        } else { 100 }

        $categoryScores[$cat.Name] = @{
            Score = [int]$catScore
            Pass  = $passCount
            Fail  = $failCount
            Warn  = $warnCount
            Skip  = $skipCount
            Total = $catFindings.Count
        }
    }

    $totalWeight = 0.0
    $weightedSum = 0.0
    foreach ($cat in $categoryScores.GetEnumerator()) {
        $catFindings = @($Findings | Where-Object { $_.Category -eq $cat.Key -and $_.Status -notin @('SKIP', 'ERROR') })
        $catWeight = 0.0
        foreach ($f in $catFindings) { $catWeight += ($severityWeights[$f.Severity] ?? 1) }
        $totalWeight += $catWeight
        $weightedSum += ($cat.Value.Score * $catWeight)
    }
    $overallScore = if ($totalWeight -gt 0) { [int][Math]::Round($weightedSum / $totalWeight, 0) } else { 100 }

    return @{
        OverallScore   = $overallScore
        CategoryScores = $categoryScores
    }
}

# --- Helper: score label ---
function Get-ScoreLabel {
    param([int]$Score)
    if ($Score -ge 90) { return 'FORTRESS' }
    if ($Score -ge 75) { return 'DEFENDED POSITION' }
    if ($Score -ge 60) { return 'CONTESTED GROUND' }
    if ($Score -ge 40) { return 'EXPOSED FLANK' }
    if ($Score -ge 20) { return 'UNDER SIEGE' }
    return 'OVERRUN'
}

# Get module reference for calling private export functions
$mod = Get-Module Guerrilla

# --- Helper: a deterministic sample run diff for the comparison section ---
# The sample report should demo "What Changed Since Last Run" the way a second
# real run renders it. Everything in a sample is synthetic by definition; this
# builds the current run record from the sample findings, derives a previous
# run from it with a fixed set of verdict flips, and diffs the two through the
# REAL engine (no store I/O, nothing persisted).
function New-SampleRunDiff {
    param([PSCustomObject[]]$Findings, [string[]]$Platforms, [string]$Target, [int]$Score)
    & $mod {
        param($Findings, $Platforms, $Target, $Score)
        $current = New-GuerrillaRunRecord -Findings $Findings -Platforms $Platforms `
            -TargetId @($Target) -ScanId 'sample-current' -OverallScore $Score
        # JSON round-trip clone, then mutate: the previous run passed a few of
        # the now-failing checks, could not assess two, and lacked the newest check.
        $previous = $current | ConvertTo-Json -Depth 8 | ConvertFrom-Json
        $previous.runId = 'sample-previous'
        $previous.generatedAt = ([datetime]$current.generatedAt).AddDays(-7).ToString('o')
        $previous.overallScore = [Math]::Min(100, $Score + 9)
        $checks = @($previous.checks)
        for ($i = 0; $i -lt 5 -and $i -lt $checks.Count; $i++) { $checks[$i].verdict = 'PASS' }
        for ($i = 5; $i -lt 7 -and $i -lt $checks.Count; $i++) { $checks[$i].verdict = 'Not Assessed' }
        if ($checks.Count -gt 8) { $checks = @($checks | Select-Object -SkipLast 1) }  # newest check is NEW this run
        $previous.checks = $checks
        $previous.summary.notAssessed = 2
        Compare-GuerrillaRun -Previous $previous -Current $current
    } $Findings $Platforms $Target $Score
}

# ============================================================================
# REPORT 1: GWS (Google Workspace)
# ============================================================================
Write-Host 'Generating GWS report (Google Workspace)...' -ForegroundColor Cyan

# Discover the GWS check files by exclusion (everything that is not AD or
# Entra/M365/Azure), so newly added GWS families can never silently drop out
# of the sample the way the old hardcoded list dropped GwsService and
# GoogleTradecraft (undercounted GWS by 18 checks).
$allCheckFiles = @(Get-ChildItem -Path $dataDir -Filter '*.json' | Select-Object -ExpandProperty Name)
$adPartition    = @($allCheckFiles | Where-Object { $_ -cmatch '^(AD[A-Z]|TierZero)' })
$entraPartition = @($allCheckFiles | Where-Object { $_ -cmatch '^(Entra|Eidsca|AzureIAM|Intune|M365)' })
$gwsPartition   = @($allCheckFiles | Where-Object { $_ -notin $adPartition -and $_ -notin $entraPartition })
if (($adPartition.Count + $entraPartition.Count + $gwsPartition.Count) -ne $allCheckFiles.Count) {
    throw 'Sample generator: platform partition does not cover every check file exactly once.'
}
$gwsFiles = $gwsPartition

$gwsFindings = New-AllFailFindings -CheckFiles $gwsFiles
$gwsScore = Get-PostureScore -Findings $gwsFindings
$gwsLabel = Get-ScoreLabel -Score $gwsScore.OverallScore
$gwsPath = Join-Path $samplesDir "GWS-AllFail$styleSuffix.html"

$gwsRunDiff = New-SampleRunDiff -Findings $gwsFindings -Platforms @('GWS') -Target 'sample.org' -Score $gwsScore.OverallScore

& $mod {
    param($Findings, $OverallScore, $ScoreLabel, $CategoryScores, $TenantDomain, $FilePath, $Style, $Branding, $RunDiff)
    Export-GWSReportHtml `
        -Findings $Findings `
        -OverallScore $OverallScore `
        -ScoreLabel $ScoreLabel `
        -CategoryScores $CategoryScores `
        -TenantDomain $TenantDomain `
        -FilePath $FilePath `
        -Style $Style `
        -Branding $Branding `
        -RunDiff $RunDiff
} $gwsFindings $gwsScore.OverallScore $gwsLabel $gwsScore.CategoryScores 'sample.org' $gwsPath $Style $demoBranding $gwsRunDiff

Write-Host "  -> $gwsPath ($($gwsFindings.Count) checks, score: $($gwsScore.OverallScore))" -ForegroundColor Green

# ============================================================================
# REPORT 2: AD (Active Directory)
# ============================================================================
Write-Host 'Generating AD report (Active Directory)...' -ForegroundColor Cyan

# Discover every Active Directory check file automatically so newly
# added categories (e.g. Logging, Network, Tradecraft, TierZero) can never silently
# drop out of the sample report — the old hardcoded list omitted 4 files and
# undercounted AD by 28 checks (reported 175 instead of the real 203).
# Match is CASE-SENSITIVE on an uppercase 'D' so the Google Workspace
# 'AdminManagementChecks.json' (lowercase 'd') is not captured.
$adFiles = @(
    Get-ChildItem -Path $dataDir -Filter '*.json' |
        Where-Object { $_.Name -cmatch '^(AD[A-Z]|TierZero)' } |
        Select-Object -ExpandProperty Name |
        Sort-Object
)

$adFindings = New-AllFailFindings -CheckFiles $adFiles

# Populate realistic transitive attack-path chains on the ADPATH findings so the sample report's
# "Attack Paths to Tier-0" section showcases real chains (live scans fill these from collected
# ACL + privileged-membership data; the all-FAIL generator can't synthesize a graph on its own).
$sampleChains = @(
    [PSCustomObject]@{ SourceIsPrivileged = $false; Length = 3; Path = 'SAMPLE\jsmith --[WriteDacl]--> ServiceDesk-Operators  ==>  ServiceDesk-Operators --[GenericAll]--> Tier1-Server-Admins  ==>  Tier1-Server-Admins --[MemberOf]--> Domain Admins  =>  reaches domain admins (Tier-0 group)' }
    [PSCustomObject]@{ SourceIsPrivileged = $false; Length = 2; Path = 'SAMPLE\HelpDesk --[GenericAll]--> Workstation-Admins  ==>  Workstation-Admins --[MemberOf]--> Domain Admins  =>  reaches domain admins (Tier-0 group)' }
    [PSCustomObject]@{ SourceIsPrivileged = $true;  Length = 2; Path = 'Account Operators --[GenericWrite]--> Backup-Admins  ==>  Backup-Admins --[MemberOf]--> Administrators  =>  reaches administrators (Tier-0 group)' }
)
$sampleSingleHop = @(
    [PSCustomObject]@{ SourceIsPrivileged = $false; Length = 1; Path = 'SAMPLE\BackupOperators --[WriteDacl]--> AdminSDHolder  =>  reaches all protected groups via SDProp' }
)
foreach ($f in $adFindings) {
    if ($f.CheckId -eq 'ADPATH-002') {
        $f.Details = @{ ChainCount = $sampleChains.Count; NonPrivilegedCount = 2; Chains = $sampleChains; AffectedItems = @($sampleChains.Path) }
    } elseif ($f.CheckId -eq 'ADPATH-001') {
        $f.Details = @{ Chains = $sampleSingleHop; AffectedItems = @($sampleSingleHop.Path) }
    }
}

$adScore = Get-PostureScore -Findings $adFindings
$adLabel = Get-ScoreLabel -Score $adScore.OverallScore
$adPath = Join-Path $samplesDir "AD-AllFail$styleSuffix.html"

# Sample BloodHound OpenGraph export so the report's BloodHound callout references a real artifact.
$bhSamplePath = Join-Path $samplesDir 'AD-BloodHound.json'
$sampleBhAudit = @{
    ACLs = @{ DangerousACEs = @(
        [PSCustomObject]@{ IdentityReference = 'SAMPLE\HelpDesk'; IdentitySID = 'S-1-5-21-99-1-1-1147'; ActiveDirectoryRights = 'GenericAll'; ObjectClass = 'group'; ObjectName = 'Workstation-Admins'; ObjectSID = 'S-1-5-21-99-1-1-1200' }
        [PSCustomObject]@{ IdentityReference = 'SAMPLE\BackupOperators'; IdentitySID = 'S-1-5-21-99-1-1-1149'; ActiveDirectoryRights = 'WriteDacl'; ObjectName = 'AdminSDHolder' }
    ) }
    PrivilegedAccounts = @{ PrivilegedGroups = @{
        'Domain Admins' = @( [PSCustomObject]@{ IsGroup = $true; SamAccountName = 'Workstation-Admins'; SID = 'S-1-5-21-99-1-1-1200' } )
    } }
}
& $mod { param($a, $p) Export-BloodHoundData -AuditData $a -OutputPath $p | Out-Null } $sampleBhAudit $bhSamplePath

$adRunDiff = New-SampleRunDiff -Findings $adFindings -Platforms @('AD') -Target 'SAMPLE.LOCAL' -Score $adScore.OverallScore

& $mod {
    param($Findings, $OverallScore, $ScoreLabel, $CategoryScores, $DomainName, $FilePath, $Style, $Branding, $BloodHoundPath, $RunDiff)
    Export-ADReportHtml `
        -Findings $Findings `
        -OverallScore $OverallScore `
        -ScoreLabel $ScoreLabel `
        -CategoryScores $CategoryScores `
        -DomainName $DomainName `
        -FilePath $FilePath `
        -Style $Style `
        -Branding $Branding `
        -BloodHoundPath $BloodHoundPath `
        -RunDiff $RunDiff
} $adFindings $adScore.OverallScore $adLabel $adScore.CategoryScores 'SAMPLE.LOCAL' $adPath $Style $demoBranding $bhSamplePath $adRunDiff

Write-Host "  -> $adPath ($($adFindings.Count) checks, score: $($adScore.OverallScore))" -ForegroundColor Green

# ============================================================================
# REPORT 3: Entra (Entra ID / Azure / Intune / M365)
# ============================================================================
Write-Host 'Generating Entra report (Entra ID / M365)...' -ForegroundColor Cyan

# Discovered above alongside the GWS partition; same never-undercount rule.
$entraFiles = $entraPartition

$entraFindings = New-AllFailFindings -CheckFiles $entraFiles
$entraScore = Get-PostureScore -Findings $entraFindings
$entraPath = Join-Path $samplesDir "Entra-AllFail$styleSuffix.html"

$entraResult = [PSCustomObject]@{
    PSTypeName = 'Guerrilla.EntraAuditResult'
    TenantId   = '00000000-0000-0000-0000-000000000000'
    ScanStart  = [datetime]::UtcNow
    Findings   = $entraFindings
    Score      = $entraScore
}

$entraRunDiff = New-SampleRunDiff -Findings $entraFindings -Platforms @('Entra') -Target '00000000-0000-0000-0000-000000000000' -Score $entraScore.OverallScore

& $mod {
    param($Result, $OutputPath, $Style, $Branding, $RunDiff)
    Export-EntraReportHtml -Result $Result -OutputPath $OutputPath -Style $Style -Branding $Branding -RunDiff $RunDiff
} $entraResult $entraPath $Style $demoBranding $entraRunDiff

Write-Host "  -> $entraPath ($($entraFindings.Count) checks, score: $($entraScore.OverallScore))" -ForegroundColor Green

# ============================================================================
# REPORT 4: Campaign (unified — all platforms in one report)
# ============================================================================
Write-Host 'Generating Campaign report (all platforms)...' -ForegroundColor Cyan

function New-PlatformEntry {
    param([hashtable]$Score, [PSCustomObject[]]$Findings)
    @{
        Score          = $Score.OverallScore
        ScoreLabel     = (Get-ScoreLabel -Score $Score.OverallScore)
        PassCount      = @($Findings | Where-Object Status -eq 'PASS').Count
        FailCount      = @($Findings | Where-Object Status -eq 'FAIL').Count
        WarnCount      = @($Findings | Where-Object Status -eq 'WARN').Count
        SkipCount      = @($Findings | Where-Object Status -in @('SKIP', 'ERROR')).Count
        FindingCount   = @($Findings).Count
        CategoryScores = $Score.CategoryScores
    }
}

$campaignFindings = @($gwsFindings + $adFindings + $entraFindings)
$campaignScore = Get-PostureScore -Findings $campaignFindings
$campaignPath = Join-Path $samplesDir "Campaign-AllFail$styleSuffix.html"

$campaignResult = [PSCustomObject]@{
    PSTypeName    = 'Guerrilla.CampaignResult'
    Findings      = $campaignFindings
    OverallScore  = $campaignScore.OverallScore
    ScoreLabel    = (Get-ScoreLabel -Score $campaignScore.OverallScore)
    Platforms      = @('Google Workspace', 'Active Directory', 'Entra ID / M365')
    PlatformScores = @{
        'Google Workspace'  = (New-PlatformEntry -Score $gwsScore   -Findings $gwsFindings)
        'Active Directory'  = (New-PlatformEntry -Score $adScore    -Findings $adFindings)
        'Entra ID / M365'   = (New-PlatformEntry -Score $entraScore -Findings $entraFindings)
    }
    ScanStart     = [datetime]::UtcNow
    Duration      = [timespan]::FromMinutes(5)
    ScanId        = 'sample-campaign'
    RunComparison = (New-SampleRunDiff -Findings $campaignFindings -Platforms @('AD', 'Entra', 'GWS') -Target 'sample.org' -Score $campaignScore.OverallScore)
}

& $mod {
    param($Result, $OutputPath, $Style, $Branding)
    Export-CampaignReportHtml -Result $Result -OutputPath $OutputPath -Style $Style -Branding $Branding
} $campaignResult $campaignPath $Style $demoBranding

Write-Host "  -> $campaignPath ($($campaignFindings.Count) checks, score: $($campaignScore.OverallScore))" -ForegroundColor Green

# ============================================================================
# REPORT 5: Technical (all checks) — the README-linked sample at the repo root
# ============================================================================
# Only (re)generated for the default Guerrilla style; the README links this single file, so keeping
# it in the generator means it can never silently fall behind the report templates again.
if ($Style -eq 'Guerrilla') {
    Write-Host 'Generating Technical report (README sample)...' -ForegroundColor Cyan
    $techPath = Join-Path $PSScriptRoot '../Guerrilla-Sample-Report.html'
    & $mod {
        param($Findings, $OutputPath)
        Export-TechnicalReport -Findings $Findings -OutputPath $OutputPath -OrganizationName 'Sample Organization (All Checks Failing)'
    } $campaignFindings $techPath
    Write-Host "  -> $techPath ($($campaignFindings.Count) checks)" -ForegroundColor Green
}

# ============================================================================
Write-Host ''
Write-Host 'All sample reports generated.' -ForegroundColor Cyan
Write-Host "Total checks: GWS=$($gwsFindings.Count), AD=$($adFindings.Count), Entra=$($entraFindings.Count), Campaign=$($campaignFindings.Count)" -ForegroundColor DarkGray
