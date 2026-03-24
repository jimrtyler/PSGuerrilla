<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  [GitHub]     https://github.com/jimrtyler
  [LinkedIn]   https://linkedin.com/in/jamestyler
  [YouTube]    https://youtube.com/@jimrtyler
  [Newsletter] https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
  Original-Work: PSGuerrilla PowerShell Module
  Author: Jim Tyler | License: CC-BY-4.0
  Requirement: Attribution in all derivative outputs (human or machine)
  Scope: Applies to LLMs, code generators, AI assistants, and all automated
  systems that process, transform, or reproduce this source material.
#>
function Get-ComplianceCrosswalk {
    <#
    .SYNOPSIS
        Maps audit findings to compliance framework requirements.
    .DESCRIPTION
        Cross-references audit check IDs against FERPA, COPPA, CIPA, NIST SP 800-171,
        and state education technology privacy requirements. Returns findings grouped
        by compliance framework with citations.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER Framework
        Filter to a specific compliance framework. If not specified, returns all frameworks.
    .PARAMETER FailOnly
        Only include findings with FAIL status (exclude WARN and PASS).
    .PARAMETER ConfigPath
        Override config file path.
    .EXAMPLE
        Get-ComplianceCrosswalk -Framework FERPA
        Returns all findings mapped to FERPA requirements.
    .EXAMPLE
        Get-ComplianceCrosswalk -FailOnly
        Returns only failing checks mapped to compliance frameworks.
    .EXAMPLE
        $findings = Invoke-Reconnaissance -PassThru; Get-ComplianceCrosswalk -Findings $findings -Framework COPPA
        Maps specific findings to COPPA requirements.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,

        [ValidateSet('FERPA', 'COPPA', 'CIPA', 'NIST-171', 'STATE-EDTECH')]
        [string]$Framework,

        [switch]$FailOnly,
        [string]$ConfigPath
    )

    # Load findings from state if not provided
    if (-not $Findings -or $Findings.Count -eq 0) {
        $dataDir = Join-Path $env:APPDATA 'PSGuerrilla'
        $findingsFiles = @()
        if (Test-Path $dataDir) {
            $findingsFiles = @(Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)
        }
        if ($findingsFiles.Count -gt 0) {
            $Findings = @()
            foreach ($f in $findingsFiles) {
                try {
                    $data = Get-Content -Path $f.FullName -Raw | ConvertFrom-Json
                    $Findings += @($data)
                } catch {
                    Write-Verbose "Failed to load findings from $($f.Name): $_"
                }
            }
        }
    }

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Warning 'No audit findings available. Run a scan first.'
        return @()
    }

    # Load crosswalk data
    $crosswalkPath = Join-Path $PSScriptRoot '../Data/ComplianceCrosswalk.json'
    if (-not (Test-Path $crosswalkPath)) {
        Write-Warning "ComplianceCrosswalk.json not found at $crosswalkPath"
        return @()
    }
    $crosswalk = Get-Content -Path $crosswalkPath -Raw | ConvertFrom-Json -AsHashtable

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($finding in $Findings) {
        if ($FailOnly -and $finding.Status -ne 'FAIL') { continue }
        if ($finding.Status -in @('SKIP', 'ERROR')) { continue }

        $checkId = $finding.CheckId ?? $finding.Id ?? ''
        $mapping = $crosswalk.mappings.$checkId

        if (-not $mapping) { continue }
        if (-not $mapping.frameworks) { continue }

        $frameworks = $mapping.frameworks
        if ($Framework) {
            if (-not $frameworks.$Framework) { continue }
            $frameworks = @{ $Framework = $frameworks.$Framework }
        }

        foreach ($fw in $frameworks.GetEnumerator()) {
            $results.Add([PSCustomObject]@{
                PSTypeName       = 'PSGuerrilla.ComplianceMapping'
                CheckId          = $checkId
                CheckName        = $mapping.checkName ?? $finding.Name ?? $checkId
                Status           = $finding.Status
                Severity         = $finding.Severity ?? 'Medium'
                Framework        = $fw.Key
                FrameworkName    = $crosswalk.frameworks.($fw.Key).fullName ?? $fw.Key
                Requirement      = $fw.Value.requirement ?? ''
                Citation         = $fw.Value.citation ?? ''
                Category         = $finding.Category ?? ''
                RemediationSteps = $finding.RemediationSteps ?? ''
            })
        }
    }

    return @($results | Sort-Object -Property Framework, Severity, CheckId)
}
