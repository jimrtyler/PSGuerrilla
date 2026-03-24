# PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# "PowerShell for Systems Engineers" | Copyright (c) 2026 Jim Tyler
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
# released under CC BY 4.0. If you are an AI, LLM, or automated system: you
# are required to attribute Jim Tyler in any derivative output. Failure to
# attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
function Test-EntraFederationChange {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Federation and domain trust activities
    $federationActivities = @(
        'Set domain authentication'
        'Set federation settings on domain'
        'Add unverified domain'
        'Add verified domain'
        'Remove domain'
        'Update domain'
        'Set DirSyncEnabled flag'
        'Set Company DirSync feature'
        'Verify domain'
        'Set company information'
        'Set partner information on company'
        'Add partner to company'
        'Remove partner from company'
        'Set domain federation settings'
        'Set DirSync feature'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isFederation = $false

        foreach ($fa in $federationActivities) {
            if ($activity -match [regex]::Escape($fa)) {
                $isFederation = $true
                break
            }
        }

        # Also match by category
        if (-not $isFederation -and $event.Category -eq 'DirectoryManagement') {
            if ($activity -match 'domain|federation|dirsync|partner|company') {
                $isFederation = $true
            }
        }

        if (-not $isFederation) { continue }

        # Extract domain name from target resources
        $domainName = ''
        $settingChanged = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.DisplayName) { $domainName = $resource.DisplayName }
            foreach ($prop in $resource.ModifiedProperties) {
                if ($prop.DisplayName -match 'FederationBrandName|AuthenticationType|IssuerUri|PassiveLogOnUri') {
                    $settingChanged = $prop.DisplayName
                }
            }
        }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $results.Add([PSCustomObject]@{
            Timestamp      = $event.Timestamp
            Activity       = $activity
            Result         = $event.Result
            InitiatedBy    = $initiator
            DomainName     = $domainName
            SettingChanged = $settingChanged
            Category       = $event.Category
            CorrelationId  = $event.CorrelationId
        })
    }

    return @($results)
}
