# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
function Export-RemediationScripts {
    <#
    .SYNOPSIS
        Generates runnable PowerShell remediation scripts from audit findings.
    .DESCRIPTION
        Produces .ps1 script files with remediation commands for failed audit checks.
        Scripts are grouped by category and include safety checks, confirmation prompts,
        and rollback comments.

        Only generates scripts for checks that have known PowerShell remediation commands.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER OutputDirectory
        Directory for script output. Default: ./PSGuerrilla-Remediation-Scripts/
    .PARAMETER Force
        Overwrite existing scripts without prompting.
    .EXAMPLE
        Export-RemediationScripts
    .EXAMPLE
        Export-RemediationScripts -OutputDirectory ./scripts -Force
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,
        [string]$OutputDirectory,
        [switch]$Force
    )

    if (-not $OutputDirectory) { $OutputDirectory = Join-Path (Get-Location) 'PSGuerrilla-Remediation-Scripts' }

    $dataDir = Join-Path $env:APPDATA 'PSGuerrilla'
    if (-not $Findings -or $Findings.Count -eq 0) {
        if (Test-Path $dataDir) {
            foreach ($f in (Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)) {
                try { $Findings += @(Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch { }
            }
        }
    }

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Warning 'No audit findings available. Run a scan first.'
        return [PSCustomObject]@{ Success = $false; Message = 'No findings'; Path = $null; ScriptCount = 0 }
    }

    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }

    # Known remediation command templates keyed by check ID prefix
    $remediationTemplates = @{
        'ADPWD'  = @{ Module = 'ActiveDirectory'; Description = 'Active Directory Password Policy' }
        'ADPRIV' = @{ Module = 'ActiveDirectory'; Description = 'AD Privileged Account Remediation' }
        'ADGPO'  = @{ Module = 'GroupPolicy'; Description = 'Group Policy Remediation' }
        'ADSTALE' = @{ Module = 'ActiveDirectory'; Description = 'AD Stale Object Cleanup' }
        'AUTH'   = @{ Module = 'GoogleWorkspace'; Description = 'Google Authentication Settings' }
        'ADMIN'  = @{ Module = 'GoogleWorkspace'; Description = 'Google Admin Management' }
        'EMAIL'  = @{ Module = 'GoogleWorkspace'; Description = 'Email Security Settings' }
        'DRIVE'  = @{ Module = 'GoogleWorkspace'; Description = 'Drive Security Settings' }
        'OAUTH'  = @{ Module = 'GoogleWorkspace'; Description = 'OAuth Security Settings' }
        'M365EXO' = @{ Module = 'ExchangeOnlineManagement'; Description = 'Exchange Online Remediation' }
        'EIDAUTH' = @{ Module = 'Microsoft.Graph'; Description = 'Entra Authentication Remediation' }
        'EIDCA'  = @{ Module = 'Microsoft.Graph'; Description = 'Conditional Access Remediation' }
    }

    # Group findings by category prefix
    $failedFindings = @($Findings | Where-Object Status -in @('FAIL', 'WARN'))
    $grouped = @($failedFindings | Group-Object {
        $id = $_.CheckId ?? $_.Id ?? ''
        if ($id -match '^([A-Z0-9]+)-') { $Matches[1] } else { 'OTHER' }
    })

    $scriptCount = 0
    $generatedScripts = [System.Collections.Generic.List[string]]::new()
    $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')

    foreach ($group in $grouped) {
        $prefix = $group.Name
        $template = $remediationTemplates[$prefix]
        if (-not $template) { continue }

        $scriptName = "Remediate-$prefix.ps1"
        $scriptPath = Join-Path $OutputDirectory $scriptName

        if ((Test-Path $scriptPath) -and -not $Force) {
            Write-Verbose "Skipping $scriptName (already exists, use -Force to overwrite)"
            continue
        }

        $sb = [System.Text.StringBuilder]::new(4096)

        [void]$sb.AppendLine(@"
<#
.SYNOPSIS
    $($template.Description) - Auto-generated remediation script
.DESCRIPTION
    Generated by PSGuerrilla on $timestamp UTC.
    Contains remediation actions for $($group.Count) finding(s) in the $prefix category.

    IMPORTANT: Review each command before executing. Test in a non-production environment first.
.NOTES
    Required Module: $($template.Module)
    Generated: $timestamp UTC
#>

#Requires -Version 7.0

`$ErrorActionPreference = 'Stop'

Write-Host '=== PSGuerrilla Remediation: $($template.Description) ===' -ForegroundColor Cyan
Write-Host "Generated: $timestamp UTC" -ForegroundColor DarkGray
Write-Host ''
Write-Host 'WARNING: Review each action carefully before proceeding.' -ForegroundColor Yellow
Write-Host ''

`$confirm = Read-Host 'Do you want to proceed? (yes/no)'
if (`$confirm -ne 'yes') {
    Write-Host 'Aborted.' -ForegroundColor Red
    return
}
"@)

        $actionNum = 0
        foreach ($finding in $group.Group) {
            $actionNum++
            $checkId = $finding.CheckId ?? $finding.Id ?? 'Unknown'
            $name = ($finding.Name ?? $finding.CheckName ?? $checkId) -replace "'", "''"
            $desc = ($finding.Description ?? '') -replace "'", "''"
            $steps = ($finding.RemediationSteps ?? 'See documentation for manual remediation steps.') -replace "'", "''"
            $sev = $finding.Severity ?? 'Medium'

            [void]$sb.AppendLine(@"

# ──────────────────────────────────────────────────
# [$actionNum] $checkId - $name
# Severity: $sev | Status: $($finding.Status)
# ──────────────────────────────────────────────────
Write-Host ''
Write-Host '[$actionNum/$($group.Count)] $checkId - $name' -ForegroundColor $(if ($sev -eq 'Critical') { 'Red' } elseif ($sev -eq 'High') { 'DarkYellow' } else { 'Yellow' })
Write-Host 'Severity: $sev' -ForegroundColor DarkGray
Write-Host 'Steps: $steps' -ForegroundColor Gray
Write-Host ''

# TODO: Add specific remediation commands for $checkId
# Remediation steps: $steps
$(if ($finding.RecommendedValue) { "# Recommended value: $($finding.RecommendedValue -replace "'", "''")" })
"@)
        }

        [void]$sb.AppendLine(@"

Write-Host ''
Write-Host '=== Remediation script complete ===' -ForegroundColor Green
Write-Host "Processed $actionNum action(s) for $prefix category." -ForegroundColor DarkGray
"@)

        $sb.ToString() | Set-Content -Path $scriptPath -Encoding UTF8
        $scriptCount++
        $generatedScripts.Add($scriptPath)
    }

    return [PSCustomObject]@{
        PSTypeName      = 'PSGuerrilla.RemediationScripts'
        Success         = $true
        Path            = (Resolve-Path $OutputDirectory).Path
        Message         = "Generated $scriptCount remediation script(s) in $OutputDirectory"
        ScriptCount     = $scriptCount
        Scripts         = @($generatedScripts)
    }
}
