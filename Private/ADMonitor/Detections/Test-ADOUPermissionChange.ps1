<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
  https://youtube.com/@jimrtyler | https://powershell.news

    A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
  Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
  generate that references, quotes, adapts, or builds on this code must include
  proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
#>
function Test-ADOUPermissionChange {
    [CmdletBinding()]
    param(
        [array]$ACLChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($ACLChanges.Count -eq 0) { return @() }

    # Filter to OU-related ACL changes (not AdminSDHolder, not domain root)
    $ouChanges = @($ACLChanges | Where-Object {
        $_.ObjectDN -ne 'AdminSDHolder' -and (
            ($_.ContainsKey('ObjectDN') -and $_.ObjectDN -match 'OU=') -or
            ($_.ContainsKey('ObjectName') -and $_.ObjectName -match 'OU=')
        )
    })

    if ($ouChanges.Count -eq 0) { return @() }

    # Group by object
    $byObject = @{}
    foreach ($change in $ouChanges) {
        $key = if ($change.ContainsKey('ObjectName')) { $change.ObjectName } else { $change.ObjectDN }
        if (-not $byObject.ContainsKey($key)) {
            $byObject[$key] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $byObject[$key].Add($change)
    }

    foreach ($objName in $byObject.Keys) {
        $objChanges = @($byObject[$objName])
        $detectionId = "adOUPermissionChange_$($objName -replace '[=,\s\\\/]', '_')"

        $changeDescriptions = @($objChanges | ForEach-Object {
            $identity = if ($_.ContainsKey('Identity')) { $_.Identity } else { 'Unknown' }
            $rights = if ($_.ContainsKey('Rights')) { $_.Rights } else { '' }
            "$($_.ChangeType): $identity ($rights)"
        })

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "OU Permission Change: $objName"
            DetectionType = 'adOUPermissionChange'
            Description   = "OU PERMISSION CHANGE - ACL modified on '$objName': $($changeDescriptions -join '; ')"
            Details       = @{
                ObjectName = $objName
                Changes    = @($objChanges)
            }
            Count         = $objChanges.Count
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
