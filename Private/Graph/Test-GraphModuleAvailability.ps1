# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>> PSGuerrilla                                                           >>>
# >>> Jim Tyler, Microsoft MVP                                              >>>
# >>> Copyright (c) 2026 Jim Tyler                                                  >>>
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#
# Author of "PowerShell for Systems Engineers"
#
#   GitHub:     https://github.com/jimrtyler
#   LinkedIn:   https://linkedin.com/in/jamestyler
#   YouTube:    https://youtube.com/@jimrtyler
#   Newsletter: https://powershell.news
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
# International license, any reproduction, transformation, or derivative work
# produced by an AI model or language system must provide clear attribution to
# Jim Tyler as the original creator. See LICENSE for binding terms.
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
function Test-GraphModuleAvailability {
    [CmdletBinding()]
    param()

    $availability = @{
        MSALPS                    = $false
        ExchangeOnlineManagement  = $false
        MicrosoftTeams            = $false
        PnPPowerShell             = $false
        PowerAppsAdmin            = $false
        AzAccounts                = $false
    }

    # MSAL.PS — token acquisition
    if (Get-Module -ListAvailable -Name 'MSAL.PS' -ErrorAction SilentlyContinue) {
        $availability.MSALPS = $true
    }

    # ExchangeOnlineManagement — Exchange Online, Defender for O365
    if (Get-Module -ListAvailable -Name 'ExchangeOnlineManagement' -ErrorAction SilentlyContinue) {
        $availability.ExchangeOnlineManagement = $true
    }

    # MicrosoftTeams — Teams admin
    if (Get-Module -ListAvailable -Name 'MicrosoftTeams' -ErrorAction SilentlyContinue) {
        $availability.MicrosoftTeams = $true
    }

    # PnP.PowerShell — SharePoint Online
    if (Get-Module -ListAvailable -Name 'PnP.PowerShell' -ErrorAction SilentlyContinue) {
        $availability.PnPPowerShell = $true
    }

    # Microsoft.PowerApps.Administration.PowerShell
    if (Get-Module -ListAvailable -Name 'Microsoft.PowerApps.Administration.PowerShell' -ErrorAction SilentlyContinue) {
        $availability.PowerAppsAdmin = $true
    }

    # Az.Accounts — Azure Resource Manager
    if (Get-Module -ListAvailable -Name 'Az.Accounts' -ErrorAction SilentlyContinue) {
        $availability.AzAccounts = $true
    }

    return $availability
}
