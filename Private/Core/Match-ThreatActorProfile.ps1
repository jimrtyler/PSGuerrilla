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
function Match-ThreatActorProfile {
    <#
    .SYNOPSIS
        Matches detected threat indicators to known threat actor profiles.
    .DESCRIPTION
        Compares a user's threat indicators and score against threat actor profiles
        in ThreatActorProfiles.json. Returns matching profiles with confidence levels.
    .PARAMETER ThreatProfile
        A flagged user threat object with ThreatScore, ThreatLevel, and Indicators properties.
    .PARAMETER ActorProfiles
        Pre-loaded threat actor profile data. If not provided, loads from Data/ThreatActorProfiles.json.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$ThreatProfile,

        [hashtable]$ActorProfiles
    )

    if (-not $ActorProfiles) {
        $profilePath = Join-Path $PSScriptRoot '../../Data/ThreatActorProfiles.json'
        if (Test-Path $profilePath) {
            $ActorProfiles = Get-Content -Path $profilePath -Raw | ConvertFrom-Json -AsHashtable
        } else {
            Write-Warning "ThreatActorProfiles.json not found at $profilePath"
            return @()
        }
    }

    # Extract indicator keywords from the threat profile's indicator strings
    $indicatorKeywords = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $indicatorMap = @{
        'KNOWN ATTACKER IP'        = 'knownAttackerIp'
        'REAUTH FROM CLOUD'        = 'reauthFromCloud'
        'IMPOSSIBLE TRAVEL'        = 'impossibleTravel'
        'RISKY SENSITIVE ACTION'   = 'riskyAction'
        'RISKY ACTION FROM CLOUD'  = 'riskyActionFromCloud'
        'CONCURRENT SESSIONS'      = 'concurrentSessions'
        'SUSPICIOUS COUNTRY'       = 'suspiciousCountry'
        'BRUTE FORCE ATTEMPT'      = 'bruteForceAttempt'
        'BRUTE FORCE SUCCESS'      = 'bruteForceSuccess'
        'USER AGENT ANOMALY'       = 'userAgentAnomaly'
        'OAUTH FROM CLOUD'         = 'oauthFromCloud'
        'AFTER HOURS LOGIN'        = 'afterHoursLogin'
        'CLOUD IP LOGINS'          = 'cloudLoginsOnly'
        'NEW DEVICE FROM CLOUD'    = 'newDeviceFromCloud'
        'NEW DEVICE'               = 'newDevice'
        'ADMIN PRIVILEGE ESCALATION' = 'adminPrivilegeEscalation'
        'EMAIL FORWARDING RULE'    = 'emailForwardingRule'
        'DRIVE EXTERNAL SHARING'   = 'driveExternalSharing'
        'BULK FILE DOWNLOAD'       = 'bulkFileDownload'
        'HIGH-RISK OAUTH APP'      = 'highRiskOAuthApp'
        'USER SUSPENSION'          = 'userSuspension'
        '2SV DISABLEMENT'          = 'twoSvDisablement'
        'DOMAIN-WIDE DELEGATION'   = 'domainWideDelegation'
        'WORKSPACE SETTING CHANGE' = 'workspaceSettingChange'
    }

    $indicators = @($ThreatProfile.Indicators ?? @())
    foreach ($indicator in $indicators) {
        foreach ($mapKey in $indicatorMap.Keys) {
            if ($indicator -match [regex]::Escape($mapKey)) {
                $indicatorKeywords.Add($indicatorMap[$mapKey]) | Out-Null
            }
        }
    }

    $threatScore = [int]($ThreatProfile.ThreatScore ?? 0)
    $matches = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($actor in $ActorProfiles.profiles) {
        $criteria = $actor.matchCriteria
        if (-not $criteria) { continue }

        # Check minimum threat score
        $minScore = [int]($criteria.minThreatScore ?? 0)
        if ($threatScore -lt $minScore) { continue }

        # Check required indicators
        $requiredMet = $true
        $requiredMatched = 0
        $requiredIndicators = @($criteria.requiredIndicators ?? @())
        foreach ($req in $requiredIndicators) {
            if ($indicatorKeywords.Contains($req)) {
                $requiredMatched++
            } else {
                $requiredMet = $false
            }
        }

        if (-not $requiredMet) { continue }

        # Check optional indicators
        $optionalMatched = 0
        $optionalIndicators = @($criteria.optionalIndicators ?? @())
        foreach ($opt in $optionalIndicators) {
            if ($indicatorKeywords.Contains($opt)) {
                $optionalMatched++
            }
        }

        $minOptional = [int]($criteria.minOptionalMatch ?? 0)
        if ($optionalMatched -lt $minOptional) { continue }

        # Calculate confidence
        $totalIndicators = $requiredIndicators.Count + $optionalIndicators.Count
        $totalMatched = $requiredMatched + $optionalMatched
        $matchRatio = if ($totalIndicators -gt 0) { $totalMatched / $totalIndicators } else { 0 }

        $confidence = switch ($true) {
            ($matchRatio -ge 0.75) { 'High'; break }
            ($matchRatio -ge 0.50) { 'Medium'; break }
            default { 'Low' }
        }

        $matches.Add([PSCustomObject]@{
            PSTypeName         = 'PSGuerrilla.ThreatActorMatch'
            ActorId            = $actor.id
            ActorName          = $actor.name
            Description        = $actor.description
            Sophistication     = $actor.sophistication
            Motivation         = $actor.motivation
            Confidence         = $confidence
            MatchRatio         = [Math]::Round($matchRatio, 2)
            RequiredMatched    = $requiredMatched
            OptionalMatched    = $optionalMatched
            TotalMatched       = $totalMatched
            TotalIndicators    = $totalIndicators
            MitreTechniques    = @($actor.ttps.mitre ?? @())
            TtpDescription     = $actor.ttps.description ?? ''
        })
    }

    return @($matches | Sort-Object -Property MatchRatio -Descending)
}
