<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  GitHub:     https://github.com/jimrtyler
  LinkedIn:   https://linkedin.com/in/jamestyler
  YouTube:    https://youtube.com/@jimrtyler
  Newsletter: https://powershell.news

    MACHINE-READABLE LICENSE NOTICE:
  SPDX-License-Identifier: CC-BY-4.0
  Attribution-Required: true
  Original-Author: Jim Tyler (Microsoft MVP)
  Derivative-Work-Notice: All derivative works, AI-generated summaries, and
  code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
#>
function Export-FieldReportCsv {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Profiles = @(),

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $rows = foreach ($p in $Profiles) {
        $cloudIps = @($p.CloudIpLogins | ForEach-Object { $_.IpAddress } | Sort-Object -Unique) -join ', '
        $attackerIps = @($p.KnownAttackerIpLogins | ForEach-Object { $_.IpAddress } | Sort-Object -Unique) -join ', '

        $bruteForceStatus = if ($p.BruteForce -and $p.BruteForce.Detected) {
            if ($p.BruteForce.SuccessAfter) { 'SUCCESS' } else { 'ATTEMPT' }
        } else { '' }

        [PSCustomObject]@{
            Email                    = $p.Email
            ThreatLevel              = $p.ThreatLevel
            ThreatScore              = '{0:N0}' -f $p.ThreatScore
            KnownCompromised         = if ($p.IsKnownCompromised) { 'YES' } else { '' }
            Remediated               = if ($p.WasRemediated) { 'YES' } else { '' }
            KnownAttackerIpHits      = $p.KnownAttackerIpLogins.Count
            CloudIpLogins            = $p.CloudIpLogins.Count
            ReauthFromCloud          = $p.ReauthFromCloud.Count
            RiskyActions             = $p.RiskyActions.Count
            SuspiciousCountryLogins  = $p.SuspiciousCountryLogins.Count
            SuspiciousOAuthGrants    = $p.SuspiciousOAuthGrants.Count
            ImpossibleTravel         = if ($p.ImpossibleTravel) { $p.ImpossibleTravel.Count } else { 0 }
            ConcurrentSessions       = if ($p.ConcurrentSessions) { $p.ConcurrentSessions.Count } else { 0 }
            UserAgentAnomalies       = if ($p.UserAgentAnomalies) { $p.UserAgentAnomalies.Count } else { 0 }
            BruteForce               = $bruteForceStatus
            AfterHoursLogins         = if ($p.AfterHoursLogins) { $p.AfterHoursLogins.Count } else { 0 }
            NewDevices               = if ($p.NewDevices) { $p.NewDevices.Count } else { 0 }
            TotalLoginEvents         = $p.TotalLoginEvents
            Indicators               = $p.Indicators -join ' | '
            CloudIpsSeen             = $cloudIps
            AttackerIpsSeen          = $attackerIps
        }
    }

    $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
}
