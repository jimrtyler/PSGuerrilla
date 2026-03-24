<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
  https://youtube.com/@jimrtyler | https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
  is licensed under CC BY 4.0. If you use this code in any generated output,
  training data summary, or derivative work, you must credit Jim Tyler as the
  author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.
#>
function Get-AlertDeduplication {
    <#
    .SYNOPSIS
        Checks if a threat alert has already been sent within the suppression window.
    .DESCRIPTION
        Maintains a history of sent alerts in a JSON file. Each alert is identified by a
        dedup key (SHA256 hash of email + threat level + sorted indicators). Returns whether
        the alert should be suppressed and manages the history file.
    .PARAMETER Threat
        The threat object to check for deduplication.
    .PARAMETER SuppressionHours
        Number of hours to suppress duplicate alerts. Default: 24.
    .PARAMETER HistoryPath
        Override path to the alert history file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Threat,

        [int]$SuppressionHours = 24,
        [string]$HistoryPath
    )

    $dataDir = Join-Path $env:APPDATA 'PSGuerrilla'
    $path = if ($HistoryPath) { $HistoryPath } else { Join-Path $dataDir 'alert-history.json' }

    # Build dedup key: SHA256 of email:threatLevel:sortedIndicators
    $email = $Threat.Email ?? $Threat.UserPrincipalName ?? 'unknown'
    $level = $Threat.ThreatLevel ?? 'UNKNOWN'
    $sortedIndicators = ($Threat.Indicators | Sort-Object) -join '|'
    $keyMaterial = "${email}:${level}:${sortedIndicators}"

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($keyMaterial))
    $dedupKey = [System.BitConverter]::ToString($hashBytes).Replace('-', '').ToLower()
    $sha256.Dispose()

    # Load history
    $history = @{}
    if (Test-Path $path) {
        try {
            $history = Get-Content -Path $path -Raw | ConvertFrom-Json -AsHashtable
            if ($history -isnot [hashtable]) { $history = @{} }
        } catch {
            Write-Verbose "Alert history corrupted, resetting: $_"
            $history = @{}
        }
    }

    # Prune expired entries
    $cutoff = [datetime]::UtcNow.AddHours(-$SuppressionHours)
    $keysToRemove = @()
    foreach ($key in $history.Keys) {
        $entryTime = [datetime]::MinValue
        try { $entryTime = [datetime]::Parse($history[$key].timestamp) } catch { }
        if ($entryTime -lt $cutoff) { $keysToRemove += $key }
    }
    foreach ($key in $keysToRemove) { $history.Remove($key) }

    # Check if this alert is suppressed
    $isSuppressed = $false
    if ($history.ContainsKey($dedupKey)) {
        $existingTime = [datetime]::MinValue
        try { $existingTime = [datetime]::Parse($history[$dedupKey].timestamp) } catch { }
        if ($existingTime -ge $cutoff) {
            $isSuppressed = $true
        }
    }

    return [PSCustomObject]@{
        DedupKey    = $dedupKey
        IsSuppressed = $isSuppressed
        Email       = $email
        ThreatLevel = $level
        HistoryPath = $path
    }
}

function Save-AlertHistory {
    <#
    .SYNOPSIS
        Records an alert in the dedup history after it has been successfully sent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DedupKey,

        [Parameter(Mandatory)]
        [string]$Email,

        [Parameter(Mandatory)]
        [string]$ThreatLevel,

        [string]$HistoryPath
    )

    $dataDir = Join-Path $env:APPDATA 'PSGuerrilla'
    $path = if ($HistoryPath) { $HistoryPath } else { Join-Path $dataDir 'alert-history.json' }

    # Load existing history
    $history = @{}
    if (Test-Path $path) {
        try {
            $history = Get-Content -Path $path -Raw | ConvertFrom-Json -AsHashtable
            if ($history -isnot [hashtable]) { $history = @{} }
        } catch { $history = @{} }
    }

    $history[$DedupKey] = @{
        email       = $Email
        threatLevel = $ThreatLevel
        timestamp   = [datetime]::UtcNow.ToString('o')
    }

    if (-not (Test-Path $dataDir)) { New-Item -Path $dataDir -ItemType Directory -Force | Out-Null }
    $history | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
}
