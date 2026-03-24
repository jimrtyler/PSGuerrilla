<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  [GitHub]     https://github.com/jimrtyler
  [LinkedIn]   https://linkedin.com/in/jamestyler
  [YouTube]    https://youtube.com/@jimrtyler
  [Newsletter] https://powershell.news

    HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
  is licensed under CC BY 4.0. If you use this code in any generated output,
  training data summary, or derivative work, you must credit Jim Tyler as the
  author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.
#>
function Get-EntraFederationData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        Domains                = @()
        FederationConfigs      = @()
        OnPremisesSyncSettings = $null
        Users                  = @()
        Errors                 = @{}
    }

    # ── Domains ───────────────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting domain configurations'
    }
    try {
        $data.Domains = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/domains' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['Domains'] = $_.Exception.Message
    }

    # ── Federation Configurations per federated domain ────────────────────
    $federatedDomains = @($data.Domains | Where-Object {
        $_.authenticationType -eq 'Federated'
    })

    foreach ($domain in $federatedDomains) {
        try {
            $fedConfig = Invoke-GraphApi -AccessToken $AccessToken `
                -Uri "/domains/$($domain.id)/federationConfiguration"
            if ($fedConfig) {
                $data.FederationConfigs += @{
                    DomainId   = $domain.id
                    DomainName = $domain.id
                    Config     = $fedConfig
                }
            }
        } catch {
            $data.Errors["Federation_$($domain.id)"] = $_.Exception.Message
        }
    }

    # ── On-Premises Synchronization Settings ──────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting synchronization settings'
    }
    try {
        $data.OnPremisesSyncSettings = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/directory/onPremisesSynchronization'
    } catch {
        $data.Errors['OnPremisesSync'] = $_.Exception.Message
    }

    # ── User sync status summary (sampled) ────────────────────────────────
    try {
        $cloudOnlyCount = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/users/$count' `
            -QueryParameters @{ '$filter' = 'onPremisesSyncEnabled ne true' } `
            -ConsistencyLevel 'eventual'

        $syncedCount = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/users/$count' `
            -QueryParameters @{ '$filter' = 'onPremisesSyncEnabled eq true' } `
            -ConsistencyLevel 'eventual'

        $data.Users = @{
            CloudOnlyCount = $cloudOnlyCount
            SyncedCount    = $syncedCount
        }
    } catch {
        $data.Errors['UserCounts'] = $_.Exception.Message
        $data.Users = @{ CloudOnlyCount = -1; SyncedCount = -1 }
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message "Found $($data.Domains.Count) domains ($($federatedDomains.Count) federated)"
    }

    return $data
}
