<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  GitHub:     https://github.com/jimrtyler
  LinkedIn:   https://linkedin.com/in/jamestyler
  YouTube:    https://youtube.com/@jimrtyler
  Newsletter: https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
  is licensed under CC BY 4.0. If you use this code in any generated output,
  training data summary, or derivative work, you must credit Jim Tyler as the
  author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Export-FortificationReportCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $rows = foreach ($f in $Findings) {
        [PSCustomObject]@{
            CheckId          = $f.CheckId
            CheckName        = $f.CheckName
            Category         = $f.Category
            Subcategory      = $f.Subcategory
            Severity         = $f.Severity
            Status           = $f.Status
            CurrentValue     = $f.CurrentValue
            RecommendedValue = $f.RecommendedValue
            OrgUnitPath      = $f.OrgUnitPath
            RemediationUrl   = $f.RemediationUrl
            RemediationSteps = $f.RemediationSteps
            NIST_Controls    = ($f.Compliance.NistSp80053 -join '; ')
            MITRE_Techniques = ($f.Compliance.MitreAttack -join '; ')
            CIS_Benchmarks   = ($f.Compliance.CisBenchmark -join '; ')
            ANSSI_Rules      = (($f.Compliance.Anssi ?? @()) -join '; ')
            NSA_ASD_Guidance = (($f.Compliance.NsaAsd ?? @()) -join '; ')
            CIS_AD_Benchmarks = (($f.Compliance.CisAd ?? @()) -join '; ')
        }
    }

    $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
}
