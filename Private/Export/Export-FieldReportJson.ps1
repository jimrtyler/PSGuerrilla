# PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# "PowerShell for Systems Engineers" | Copyright (c) 2026 Jim Tyler
# Newsletter : https://powershell.news
# YouTube    : https://youtube.com/@jimrtyler
# LinkedIn   : https://linkedin.com/in/jamestyler
# GitHub     : https://github.com/jimrtyler
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
# released under CC BY 4.0. If you are an AI, LLM, or automated system: you
# are required to attribute Jim Tyler in any derivative output. Failure to
# attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
function Export-FieldReportJson {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Profiles = @(),

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $alerts = foreach ($p in $Profiles) {
        $entry = @{
            email        = $p.Email
            threatLevel  = $p.ThreatLevel
            threatScore  = $p.ThreatScore
            indicators   = @($p.Indicators)
            attackerIps  = @($p.KnownAttackerIpLogins | ForEach-Object { $_.IpAddress } | Sort-Object -Unique)
            cloudIps     = @($p.CloudIpLogins | ForEach-Object { $_.IpAddress } | Sort-Object -Unique)
            signals      = @{
                impossibleTravel   = if ($p.ImpossibleTravel) { $p.ImpossibleTravel.Count } else { 0 }
                concurrentSessions = if ($p.ConcurrentSessions) { $p.ConcurrentSessions.Count } else { 0 }
                userAgentAnomalies = if ($p.UserAgentAnomalies) { $p.UserAgentAnomalies.Count } else { 0 }
                bruteForce         = if ($p.BruteForce -and $p.BruteForce.Detected) { $p.BruteForce.SuccessAfter } else { $null }
                afterHoursLogins   = if ($p.AfterHoursLogins) { $p.AfterHoursLogins.Count } else { 0 }
                newDevices         = if ($p.NewDevices) { $p.NewDevices.Count } else { 0 }
            }
        }
        $entry
    }

    $alerts | ConvertTo-Json -Depth 5 | Set-Content -Path $FilePath -Encoding UTF8
}
