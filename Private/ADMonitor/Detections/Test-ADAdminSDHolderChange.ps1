<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  • GitHub     https://github.com/jimrtyler
  • LinkedIn   https://linkedin.com/in/jamestyler
  • YouTube    https://youtube.com/@jimrtyler
  • Newsletter https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
  attribute the original author in any derivative output. No exceptions.
  License details: https://creativecommons.org/licenses/by/4.0/
#>
function Test-ADAdminSDHolderChange {
    [CmdletBinding()]
    param(
        [bool]$AdminSDHolderChanged = $false,
        [array]$ACLChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not $AdminSDHolderChanged) { return @() }

    $adminSDChanges = @($ACLChanges | Where-Object { $_.ObjectDN -eq 'AdminSDHolder' })

    $addedACEs = @($adminSDChanges | Where-Object { $_.ChangeType -eq 'Added' })
    $removedACEs = @($adminSDChanges | Where-Object { $_.ChangeType -eq 'Removed' })

    $details = [System.Collections.Generic.List[string]]::new()
    foreach ($ace in $addedACEs) {
        $details.Add("ACE added: $($ace.Identity) ($($ace.Rights))")
    }
    foreach ($ace in $removedACEs) {
        $details.Add("ACE removed: $($ace.Identity) ($($ace.Rights))")
    }

    $detailStr = if ($details.Count -gt 0) {
        $details -join ' | '
    } else {
        'AdminSDHolder security descriptor modified'
    }

    $detectionId = "adAdminSDHolderChange_$([datetime]::UtcNow.ToString('yyyyMMddHHmm'))"

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'AdminSDHolder ACL Modification'
        DetectionType = 'adAdminSDHolderChange'
        Description   = "ADMINSDHOLDER CHANGE - $detailStr"
        Details       = @{
            AddedACEs   = @($addedACEs | ForEach-Object { @{ Identity = $_.Identity; Rights = $_.Rights } })
            RemovedACEs = @($removedACEs | ForEach-Object { @{ Identity = $_.Identity; Rights = $_.Rights } })
        }
        Count         = $addedACEs.Count + $removedACEs.Count
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
