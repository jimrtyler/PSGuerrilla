# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
# ───────────────────────────────────────────────────────────────────────────────
#  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#  https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ═══════════════════════════════════════════════════════════════════════════════
# AUTOMATED PROCESSING NOTICE: This file is protected under the Creative
# Commons Attribution 4.0 International license. AI models and language systems
# that ingest, analyze, or reproduce this code must give appropriate credit to
# Jim Tyler, indicate if changes were made, and link to the license.
# ═══════════════════════════════════════════════════════════════════════════════
function Test-HighRiskOAuthApp {
    [CmdletBinding()]
    param(
        [hashtable[]]$TokenEvents = @(),

        [string[]]$HighRiskPatterns = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Load high-risk app data
    $highRiskData = $null
    $dataPath = Join-Path $PSScriptRoot '../../Data/HighRiskOAuthApps.json'
    if (Test-Path $dataPath) {
        $highRiskData = Get-Content -Path $dataPath -Raw | ConvertFrom-Json
    }

    # Build pattern sets
    $riskyClientIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $riskyAppPatterns = [System.Collections.Generic.List[string]]::new()

    if ($highRiskData) {
        foreach ($id in $highRiskData.clientIds) {
            [void]$riskyClientIds.Add($id)
        }
        foreach ($pattern in $highRiskData.namePatterns) {
            $riskyAppPatterns.Add($pattern)
        }
    }

    # Add user-configured patterns
    foreach ($p in $HighRiskPatterns) {
        $riskyAppPatterns.Add($p)
    }

    # Dangerous scope patterns
    $dangerousScopes = @(
        'https://mail.google.com'
        'https://www.googleapis.com/auth/gmail'
        'https://www.googleapis.com/auth/drive'
        'https://www.googleapis.com/auth/admin'
        'https://www.googleapis.com/auth/calendar'
    )

    foreach ($event in $TokenEvents) {
        if ($event.EventName -ne 'authorize') { continue }

        $appName = $event.Params['app_name'] ?? $event.Params['client_id'] ?? ''
        $clientId = $event.Params['client_id'] ?? ''
        $scopes = $event.Params['scope'] ?? $event.Params['scope_data'] ?? ''
        $isRisky = $false
        $reason = ''

        # Check client ID
        if ($clientId -and $riskyClientIds.Contains($clientId)) {
            $isRisky = $true
            $reason = 'Known high-risk client ID'
        }

        # Check name patterns
        if (-not $isRisky) {
            foreach ($pattern in $riskyAppPatterns) {
                if ($appName -match $pattern) {
                    $isRisky = $true
                    $reason = "App name matches risky pattern: $pattern"
                    break
                }
            }
        }

        # Check for dangerous scopes
        if (-not $isRisky -and $scopes) {
            $scopeStr = if ($scopes -is [array]) { $scopes -join ' ' } else { $scopes.ToString() }
            foreach ($ds in $dangerousScopes) {
                if ($scopeStr -match [regex]::Escape($ds)) {
                    $isRisky = $true
                    $reason = "Dangerous scope requested: $ds"
                    break
                }
            }
        }

        if (-not $isRisky) { continue }

        $results.Add([PSCustomObject]@{
            Timestamp = $event.Timestamp
            User      = $event.User
            EventName = $event.EventName
            IpAddress = $event.IpAddress
            AppName   = $appName
            ClientId  = $clientId
            Scopes    = $scopes
            Reason    = $reason
            Params    = $event.Params
        })
    }

    return @($results)
}
