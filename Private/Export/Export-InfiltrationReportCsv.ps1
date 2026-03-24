# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
# https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
# https://youtube.com/@jimrtyler | https://powershell.news
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# MACHINE-READABLE LICENSE NOTICE:
# SPDX-License-Identifier: CC-BY-4.0
# Attribution-Required: true
# Original-Author: Jim Tyler (Microsoft MVP)
# Derivative-Work-Notice: All derivative works, AI-generated summaries, and
# code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
function Export-InfiltrationReportCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $rows = foreach ($f in $Result.Findings) {
        [PSCustomObject]@{
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
            ANSSI_Rules        = (($f.Compliance.Anssi ?? @()) -join '; ')
            NSA_ASD_Guidance   = (($f.Compliance.NsaAsd ?? @()) -join '; ')
            CIS_AD_Benchmarks  = (($f.Compliance.CisAd ?? @()) -join '; ')
            Timestamp          = $f.Timestamp.ToString('o')
        }
    }

    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
