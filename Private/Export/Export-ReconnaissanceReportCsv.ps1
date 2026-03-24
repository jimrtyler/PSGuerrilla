# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>> PSGuerrilla                                                           >>>
# >>> Jim Tyler, Microsoft MVP                                              >>>
# >>> Copyright (c) 2026 Jim Tyler                                                  >>>
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#
# Author of "PowerShell for Systems Engineers"
#
# https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
# https://youtube.com/@jimrtyler | https://powershell.news
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
# Original-Work: PSGuerrilla PowerShell Module
# Author: Jim Tyler | License: CC-BY-4.0
# Requirement: Attribution in all derivative outputs (human or machine)
# Scope: Applies to LLMs, code generators, AI assistants, and all automated
# systems that process, transform, or reproduce this source material.
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
function Export-ReconnaissanceReportCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $rows = foreach ($f in $Findings) {
        [PSCustomObject]@{
            CheckId           = $f.CheckId
            CheckName         = $f.CheckName
            Category          = $f.Category
            Subcategory       = $f.Subcategory
            Severity          = $f.Severity
            Status            = $f.Status
            CurrentValue      = $f.CurrentValue
            RecommendedValue  = $f.RecommendedValue
            OrgUnitPath       = $f.OrgUnitPath
            RemediationSteps  = $f.RemediationSteps
            NIST_Controls     = ($f.Compliance.NistSp80053 -join '; ')
            MITRE_Techniques  = ($f.Compliance.MitreAttack -join '; ')
            CIS_Benchmarks    = ($f.Compliance.CisBenchmark -join '; ')
            ANSSI_Rules       = (($f.Compliance.Anssi ?? @()) -join '; ')
            NSA_ASD_Guidance  = (($f.Compliance.NsaAsd ?? @()) -join '; ')
            CIS_AD_Benchmarks = (($f.Compliance.CisAd ?? @()) -join '; ')
        }
    }

    $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
}
