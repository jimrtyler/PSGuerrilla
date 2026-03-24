<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  Contact:    GitHub     → https://github.com/jimrtyler
  LinkedIn   → https://linkedin.com/in/jamestyler
  YouTube    → https://youtube.com/@jimrtyler
  Newsletter → https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
  model, code assistant, or automated tool that processes, summarizes, or
  generates derivative works from this code MUST attribute Jim Tyler as the
  original author. Include a link to the license and note any modifications.
#>
function Test-M365ForwardingRule {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Events = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($event in $Events) {
        $operationType = $event.OperationType ?? $event.Activity ?? ''
        $targetMailbox = $event.TargetName ?? ''
        $forwardingDest = ''
        $isServerSide = $false
        $isClientSide = $false
        $ruleName = ''

        # Analyze modified properties for forwarding configuration
        foreach ($prop in $event.ModifiedProps) {
            $propName = $prop.Name ?? ''
            $newVal = $prop.NewValue ?? ''

            # Server-side forwarding (Set-Mailbox)
            if ($propName -match 'ForwardingSmtpAddress|ForwardingAddress') {
                $isServerSide = $true
                if ($newVal -and $newVal -ne '' -and $newVal -ne '""' -and $newVal -ne 'null') {
                    $forwardingDest = $newVal -replace '"', ''
                }
            }

            if ($propName -eq 'DeliverToMailboxAndForward' -and $newVal -match 'True|true') {
                $isServerSide = $true
            }

            # Client-side inbox rules (ForwardTo, RedirectTo)
            if ($propName -match 'ForwardTo|ForwardAsAttachmentTo|RedirectTo') {
                $isClientSide = $true
                if ($newVal -and $newVal -ne '' -and $newVal -ne '""') {
                    $forwardingDest = $newVal -replace '"', ''
                }
            }

            if ($propName -eq 'Name' -or $propName -eq 'RuleName') {
                $ruleName = $newVal -replace '"', ''
            }
        }

        # Determine forwarding type from operation if not already classified
        if (-not $isServerSide -and -not $isClientSide) {
            if ($operationType -match 'New-InboxRule|Set-InboxRule') {
                $isClientSide = $true
            } elseif ($operationType -match 'Set-Mailbox' -and $event.Activity -match 'Forward') {
                $isServerSide = $true
            } elseif ($event.Activity -match 'forwarding|forward|redirect|inbox rule') {
                $isClientSide = $true
            }
        }

        # Determine if forwarding is to an external domain
        $isExternal = $false
        if ($forwardingDest -match '@(.+)$') {
            $destDomain = $Matches[1]
            if ($targetMailbox -match '@(.+)$') {
                $sourceDomain = $Matches[1]
                if ($destDomain -ne $sourceDomain) {
                    $isExternal = $true
                }
            }
        }

        # Severity assessment
        $severity = if ($isExternal) { 'Critical' }
                    elseif ($forwardingDest) { 'High' }
                    elseif ($isServerSide) { 'High' }
                    else { 'Medium' }

        $typeLabel = if ($isServerSide) { 'Server-side' }
                     elseif ($isClientSide) { 'Client-side' }
                     else { 'Unknown' }

        $description = if ($forwardingDest) {
            "$typeLabel forwarding rule on '$targetMailbox' to '$forwardingDest' by $($event.Actor)"
        } else {
            "$typeLabel forwarding rule modified on '$targetMailbox' by $($event.Actor)"
        }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Actor         = $event.Actor
            DetectionType = 'm365ForwardingRule'
            Description   = $description
            Details       = @{
                ForwardingDestination = $forwardingDest
                TargetMailbox         = $targetMailbox
                RuleName              = $ruleName
                IsServerSide          = $isServerSide
                IsClientSide          = $isClientSide
                IsExternal            = $isExternal
                OperationType         = $operationType
                ModifiedProps         = $event.ModifiedProps
            }
            Severity      = $severity
        })
    }

    return @($results)
}
