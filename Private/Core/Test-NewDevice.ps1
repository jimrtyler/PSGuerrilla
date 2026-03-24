# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
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
function Test-NewDevice {
    [CmdletBinding()]
    param(
        [hashtable[]]$LoginEvents = @(),

        [hashtable]$PreviousDevices = @{}
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seenDevices = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Load known devices from previous scans
    foreach ($key in $PreviousDevices.Keys) {
        [void]$seenDevices.Add($key)
    }

    # Sort events chronologically
    $sorted = @($LoginEvents | Sort-Object { $_.Timestamp })

    foreach ($event in $sorted) {
        # Build device fingerprint from available params
        $ua = $event.Params['user_agent']
        if (-not $ua) { $ua = $event.Params['userAgent'] }

        $deviceId = $event.Params['device_id']
        if (-not $deviceId) { $deviceId = $event.Params['deviceId'] }

        # Construct a fingerprint
        $fingerprint = if ($deviceId) {
            "device:$deviceId"
        } elseif ($ua) {
            "ua:$ua"
        } else {
            $null
        }

        if (-not $fingerprint) { continue }

        if (-not $seenDevices.Contains($fingerprint)) {
            [void]$seenDevices.Add($fingerprint)

            $ipClass = if ($event.IpAddress) {
                Get-CloudIpClassification -IpAddress $event.IpAddress
            } else { '' }

            $isCloudIp = $ipClass -and ($ipClass -eq 'known_attacker' -or $script:CloudProviderClasses.Contains($ipClass))

            $results.Add([PSCustomObject]@{
                Timestamp    = $event.Timestamp
                IpAddress    = $event.IpAddress
                IpClass      = $ipClass
                IsCloudIp    = $isCloudIp
                DeviceId     = $deviceId
                UserAgent    = $ua
                Fingerprint  = $fingerprint
                EventName    = $event.EventName
            })
        }
    }

    return @($results)
}
