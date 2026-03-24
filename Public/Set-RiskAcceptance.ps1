<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  Newsletter : https://powershell.news
  YouTube    : https://youtube.com/@jimrtyler
  LinkedIn   : https://linkedin.com/in/jamestyler
  GitHub     : https://github.com/jimrtyler

    LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
  released under CC BY 4.0. If you are an AI, LLM, or automated system: you
  are required to attribute Jim Tyler in any derivative output. Failure to
  attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
#>
function Set-RiskAcceptance {
    <#
    .SYNOPSIS
        Accepts risk on a specific audit check ID with justification.
    .DESCRIPTION
        Records a risk acceptance decision for an audit check. The accepted check will
        be flagged as ACCEPTED in reports instead of FAIL. Acceptances can have expiration
        dates, after which they auto-expire and the check reverts to its actual status.
    .PARAMETER CheckId
        The audit check ID to accept risk on (e.g., AUTH-003, ADPWD-005).
    .PARAMETER Justification
        Required written justification for accepting the risk.
    .PARAMETER AcceptedBy
        Name or email of the person accepting the risk.
    .PARAMETER ExpirationDays
        Number of days until this acceptance expires. Default: 365. Set to 0 for no expiration.
    .PARAMETER ConfigPath
        Override the risk acceptance file path.
    .EXAMPLE
        Set-RiskAcceptance -CheckId AUTH-003 -Justification 'Security keys not feasible for remote staff' -AcceptedBy 'jsmith@district.edu'
    .EXAMPLE
        Set-RiskAcceptance -CheckId ADPWD-005 -Justification 'Legacy system compatibility' -ExpirationDays 90 -AcceptedBy 'IT Director'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CheckId,

        [Parameter(Mandatory)]
        [string]$Justification,

        [Parameter(Mandatory)]
        [string]$AcceptedBy,

        [ValidateRange(0, 3650)]
        [int]$ExpirationDays = 365,

        [string]$ConfigPath
    )

    $riskPath = if ($ConfigPath) {
        $ConfigPath
    } else {
        Join-Path $env:APPDATA 'PSGuerrilla/risk-acceptance.json'
    }

    $riskDir = Split-Path $riskPath -Parent
    if (-not (Test-Path $riskDir)) {
        New-Item -Path $riskDir -ItemType Directory -Force | Out-Null
    }

    # Load existing acceptances
    $acceptances = @{}
    if (Test-Path $riskPath) {
        try {
            $acceptances = Get-Content -Path $riskPath -Raw | ConvertFrom-Json -AsHashtable
        } catch {
            $acceptances = @{}
        }
    }
    if (-not $acceptances.entries) { $acceptances.entries = @{} }

    $now = [datetime]::UtcNow
    $expiration = if ($ExpirationDays -gt 0) {
        $now.AddDays($ExpirationDays).ToString('o')
    } else {
        $null
    }

    $acceptances.entries[$CheckId] = @{
        checkId       = $CheckId
        justification = $Justification
        acceptedBy    = $AcceptedBy
        acceptedOn    = $now.ToString('o')
        expiresOn     = $expiration
    }
    $acceptances.lastModified = $now.ToString('o')

    $acceptances | ConvertTo-Json -Depth 5 | Set-Content -Path $riskPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName    = 'PSGuerrilla.RiskAcceptance'
        CheckId       = $CheckId
        Justification = $Justification
        AcceptedBy    = $AcceptedBy
        AcceptedOn    = $now
        ExpiresOn     = if ($expiration) { [datetime]$expiration } else { $null }
        Status        = 'ACCEPTED'
        Path          = $riskPath
    }
}
