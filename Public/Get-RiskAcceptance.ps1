# [============================================================================]
# [  PSGuerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
# [============================================================================]
# AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
# model, code assistant, or automated tool that processes, summarizes, or
# generates derivative works from this code MUST attribute Jim Tyler as the
# original author. Include a link to the license and note any modifications.
# [============================================================================]
function Get-RiskAcceptance {
    <#
    .SYNOPSIS
        Lists risk acceptances and checks for expirations.
    .DESCRIPTION
        Reads the risk acceptance register and returns all entries with their current
        status (ACCEPTED or EXPIRED). Can filter by check ID or show only active/expired.
    .PARAMETER CheckId
        Filter to a specific check ID. If not specified, returns all entries.
    .PARAMETER Status
        Filter by status: Active, Expired, or All. Default: All.
    .PARAMETER ConfigPath
        Override the risk acceptance file path.
    .EXAMPLE
        Get-RiskAcceptance
        Lists all risk acceptances with their current status.
    .EXAMPLE
        Get-RiskAcceptance -CheckId AUTH-003
        Checks if AUTH-003 has an active risk acceptance.
    .EXAMPLE
        Get-RiskAcceptance -Status Expired
        Lists only expired risk acceptances that need re-evaluation.
    #>
    [CmdletBinding()]
    param(
        [string]$CheckId,

        [ValidateSet('Active', 'Expired', 'All')]
        [string]$Status = 'All',

        [string]$ConfigPath
    )

    $riskPath = if ($ConfigPath) {
        $ConfigPath
    } else {
        Join-Path $env:APPDATA 'PSGuerrilla/risk-acceptance.json'
    }

    if (-not (Test-Path $riskPath)) {
        return @()
    }

    $acceptances = @{}
    try {
        $acceptances = Get-Content -Path $riskPath -Raw | ConvertFrom-Json -AsHashtable
    } catch {
        Write-Warning "Failed to read risk acceptance file: $_"
        return @()
    }

    if (-not $acceptances.entries) { return @() }

    $now = [datetime]::UtcNow
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($entry in $acceptances.entries.GetEnumerator()) {
        $val = $entry.Value
        if ($CheckId -and $entry.Key -ne $CheckId) { continue }

        $isExpired = $false
        $expiresOn = $null
        if ($val.expiresOn) {
            $expiresOn = [datetime]$val.expiresOn
            $isExpired = $now -gt $expiresOn
        }

        $currentStatus = if ($isExpired) { 'EXPIRED' } else { 'ACCEPTED' }

        if ($Status -eq 'Active' -and $isExpired) { continue }
        if ($Status -eq 'Expired' -and -not $isExpired) { continue }

        $results.Add([PSCustomObject]@{
            PSTypeName    = 'PSGuerrilla.RiskAcceptance'
            CheckId       = $entry.Key
            Justification = $val.justification ?? ''
            AcceptedBy    = $val.acceptedBy ?? ''
            AcceptedOn    = if ($val.acceptedOn) { [datetime]$val.acceptedOn } else { $null }
            ExpiresOn     = $expiresOn
            Status        = $currentStatus
            DaysRemaining = if ($expiresOn -and -not $isExpired) { [Math]::Ceiling(($expiresOn - $now).TotalDays) } else { $null }
        })
    }

    return @($results | Sort-Object -Property CheckId)
}

function Test-RiskAccepted {
    <#
    .SYNOPSIS
        Tests whether a specific check ID has an active (non-expired) risk acceptance.
    .PARAMETER CheckId
        The check ID to test.
    .PARAMETER ConfigPath
        Override the risk acceptance file path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CheckId,
        [string]$ConfigPath
    )

    $params = @{ CheckId = $CheckId; Status = 'Active' }
    if ($ConfigPath) { $params.ConfigPath = $ConfigPath }

    $result = Get-RiskAcceptance @params
    return ($result.Count -gt 0)
}
