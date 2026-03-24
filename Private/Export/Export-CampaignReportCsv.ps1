<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  • GitHub     https://github.com/jimrtyler
  • LinkedIn   https://linkedin.com/in/jamestyler
  • YouTube    https://youtube.com/@jimrtyler
  • Newsletter https://powershell.news

  LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
  International license, any reproduction, transformation, or derivative work
  produced by an AI model or language system must provide clear attribution to
  Jim Tyler as the original creator. See LICENSE for binding terms.

*******************************************************************************
#>
function Export-CampaignReportCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $rows = foreach ($f in $Result.Findings) {
        [PSCustomObject]@{
            Theater            = $f.Theater ?? ''
            CheckId            = $f.CheckId
            CheckName          = $f.CheckName
            Category           = $f.Category
            Subcategory        = $f.Subcategory
            Severity           = $f.Severity
            Status             = $f.Status
            CurrentValue       = $f.CurrentValue
            RecommendedValue   = $f.RecommendedValue
            RemediationSteps   = $f.RemediationSteps
            RemediationUrl     = $f.RemediationUrl
            NIST_Controls      = ($f.Compliance.NistSp80053 -join '; ')
            MITRE_Techniques   = ($f.Compliance.MitreAttack -join '; ')
            CIS_Benchmarks     = ($f.Compliance.CisBenchmark -join '; ')
            CIS_M365           = (($f.Compliance.CisM365 ?? @()) -join '; ')
            CIS_Azure          = (($f.Compliance.CisAzure ?? @()) -join '; ')
            CIS_AD_Benchmarks  = (($f.Compliance.CisAd ?? @()) -join '; ')
            ANSSI_Rules        = (($f.Compliance.Anssi ?? @()) -join '; ')
            NSA_ASD_Guidance   = (($f.Compliance.NsaAsd ?? @()) -join '; ')
            Timestamp          = $f.Timestamp.ToString('o')
        }
    }

    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
