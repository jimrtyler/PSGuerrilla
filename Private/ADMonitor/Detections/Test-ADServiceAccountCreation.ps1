# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
# Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
# generate that references, quotes, adapts, or builds on this code must include
# proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
function Test-ADServiceAccountCreation {
    [CmdletBinding()]
    param(
        [array]$NewServiceAccounts = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($NewServiceAccounts.Count -eq 0) { return @() }

    $accountNames = @($NewServiceAccounts | ForEach-Object { $_.SAM })
    $detailStr = "New service account(s): $($accountNames -join ', ')"
    $detectionId = "adServiceAccountCreation_$(($accountNames | Sort-Object) -join '_')"

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'New Service Account Created'
        DetectionType = 'adServiceAccountCreation'
        Description   = "SERVICE ACCOUNT CREATION - $($NewServiceAccounts.Count) new service account(s) detected: $detailStr"
        Details       = @{
            Accounts = @($NewServiceAccounts | ForEach-Object {
                @{
                    SAM         = $_.SAM
                    DN          = $_.DN
                    WhenCreated = $_.WhenCreated
                }
            })
        }
        Count         = $NewServiceAccounts.Count
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
