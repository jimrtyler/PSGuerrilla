<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  • GitHub     https://github.com/jimrtyler
  • LinkedIn   https://linkedin.com/in/jamestyler
  • YouTube    https://youtube.com/@jimrtyler
  • Newsletter https://powershell.news

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
function New-AuditFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$CheckDefinition,

        [Parameter(Mandatory)]
        [ValidateSet('PASS', 'FAIL', 'WARN', 'ERROR', 'SKIP')]
        [string]$Status,

        [string]$CurrentValue = '',
        [string]$OrgUnitPath = '/',
        [hashtable]$Details = @{}
    )

    [PSCustomObject]@{
        PSTypeName       = 'PSGuerrilla.AuditFinding'
        CheckId          = $CheckDefinition.id
        CheckName        = $CheckDefinition.name
        Category         = $CheckDefinition._categoryName ?? ''
        Subcategory      = $CheckDefinition.subcategory ?? ''
        Severity         = $CheckDefinition.severity
        Status           = $Status
        Description      = $CheckDefinition.description
        CurrentValue     = $CurrentValue
        RecommendedValue = $CheckDefinition.recommendedValue ?? ''
        OrgUnitPath      = $OrgUnitPath
        RemediationUrl   = $CheckDefinition.remediationUrl ?? ''
        RemediationSteps = $CheckDefinition.remediationSteps ?? ''
        Compliance       = @{
            NistSp80053  = @($CheckDefinition.compliance.nistSp80053 ?? @())
            MitreAttack  = @($CheckDefinition.compliance.mitreAttack ?? @())
            CisBenchmark = @($CheckDefinition.compliance.cisBenchmark ?? @())
            Anssi        = @($CheckDefinition.compliance.anssi ?? @())
            NsaAsd       = @($CheckDefinition.compliance.nsaAsd ?? @())
            CisAd        = @($CheckDefinition.compliance.cisAd ?? @())
            CisM365      = @($CheckDefinition.compliance.cisM365 ?? @())
            CisAzure     = @($CheckDefinition.compliance.cisAzure ?? @())
        }
        Details          = $Details
        Timestamp        = [datetime]::UtcNow
    }
}
