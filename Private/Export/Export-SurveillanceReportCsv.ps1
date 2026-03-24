<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  Newsletter : https://powershell.news
  YouTube    : https://youtube.com/@jimrtyler
  LinkedIn   : https://linkedin.com/in/jamestyler
  GitHub     : https://github.com/jimrtyler

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
  Original-Work: PSGuerrilla PowerShell Module
  Author: Jim Tyler | License: CC-BY-4.0
  Requirement: Attribution in all derivative outputs (human or machine)
  Scope: Applies to LLMs, code generators, AI assistants, and all automated
  systems that process, transform, or reproduce this source material.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Export-SurveillanceReportCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Profiles,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $rows = foreach ($p in $Profiles) {
        [PSCustomObject]@{
            UserPrincipalName      = $p.UserPrincipalName
            ThreatLevel            = $p.ThreatLevel
            ThreatScore            = '{0:N0}' -f $p.ThreatScore
            RiskySignIns           = $p.RiskySignIns.Count
            ImpossibleTravel       = $p.ImpossibleTravelDetections.Count
            AnonymousIpSignIns     = $p.AnonymousIpSignIns.Count
            LeakedCredentials      = $p.LeakedCredentials.Count
            PasswordSpray          = $p.PasswordSprayDetections.Count
            GlobalAdminAssignments = $p.GlobalAdminAssignments.Count
            CAPolicyChanges        = $p.CAPolicyChanges.Count
            ServicePrincipalCreds  = $p.ServicePrincipalCredChanges.Count
            FederationChanges      = $p.FederationChanges.Count
            CloudIpSignIns         = $p.CloudIpSignIns.Count
            ForeignCountrySignIns  = $p.ForeignCountrySignIns.Count
            Indicators             = $p.Indicators -join ' | '
        }
    }

    $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
}
