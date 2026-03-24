<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  [GitHub]     https://github.com/jimrtyler
  [LinkedIn]   https://linkedin.com/in/jamestyler
  [YouTube]    https://youtube.com/@jimrtyler
  [Newsletter] https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
  attribute the original author in any derivative output. No exceptions.
  License details: https://creativecommons.org/licenses/by/4.0/

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Test-DriveExternalSharing {
    [CmdletBinding()]
    param(
        [hashtable[]]$DriveEvents = @(),

        [string]$InternalDomain = ''
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $sharingEvents = @(
        'change_acl_editors'
        'change_user_access'
        'change_document_access_scope'
        'change_document_visibility'
    )

    foreach ($event in $DriveEvents) {
        $eventName = $event.EventName
        if ($eventName -notin $sharingEvents) { continue }

        $targetUser = $event.Params['target_user'] ?? $event.Params['TARGET_USER'] ?? ''
        $visibility = $event.Params['visibility'] ?? $event.Params['new_value'] ?? ''
        $docTitle = $event.Params['doc_title'] ?? $event.Params['DOCUMENT_TITLE'] ?? ''

        $isExternal = $false

        # Check if shared to external user
        if ($targetUser -and $InternalDomain) {
            if ($targetUser -notmatch [regex]::Escape($InternalDomain) -and $targetUser -match '@') {
                $isExternal = $true
            }
        }

        # Check if visibility changed to public/anyone
        if ($visibility -match 'people_with_link|anyone|public|external') {
            $isExternal = $true
        }

        if (-not $isExternal) { continue }

        $results.Add([PSCustomObject]@{
            Timestamp   = $event.Timestamp
            User        = $event.User
            EventName   = $eventName
            IpAddress   = $event.IpAddress
            TargetUser  = $targetUser
            Visibility  = $visibility
            DocTitle    = $docTitle
            Params      = $event.Params
        })
    }

    return @($results)
}
