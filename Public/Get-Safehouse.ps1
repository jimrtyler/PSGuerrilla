# ______________________________________________________________________________
#
#  PSGuerrilla
#  Jim Tyler — Microsoft MVP
#  "PowerShell for Systems Engineers"
# ______________________________________________________________________________
#
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
#
#  CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ______________________________________________________________________________
#
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
# ______________________________________________________________________________
function Get-Safehouse {
    <#
    .SYNOPSIS
        Retrieves PSGuerrilla configuration and vault status.

    .DESCRIPTION
        Returns the current runtime configuration. Credential values are stored in the
        SecretManagement vault and are not displayed unless -ShowSecrets is specified.
        Use Set-Safehouse -Status for a formatted vault status display.

    .PARAMETER ConfigPath
        Path to the PSGuerrilla runtime config file. Default: $env:APPDATA\PSGuerrilla\config.json

    .PARAMETER ShowSecrets
        Include secret values from the vault in the output (use with caution).

    .PARAMETER VaultName
        Name of the SecretManagement vault. Default: PSGuerrilla

    .EXAMPLE
        Get-Safehouse
        # Returns config with vault credential status (no secret values)

    .EXAMPLE
        Get-Safehouse -ShowSecrets
        # Returns config including actual secret values from vault
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [switch]$ShowSecrets,
        [string]$VaultName = 'PSGuerrilla'
    )

    $path = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }

    # Build result object
    $result = [ordered]@{}

    # Load runtime config if exists
    if ($path -and (Test-Path $path)) {
        $config = Get-Content -Path $path -Raw | ConvertFrom-Json
        $result.config = $config
        $result.configPath = $path
    } else {
        $result.config = $null
        $result.configPath = $path
    }

    # Load vault status
    $vault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
    $result.vaultExists = [bool]$vault
    $result.vaultName = $VaultName

    if ($vault) {
        $metadata = Get-VaultMetadata -VaultName $VaultName
        $result.vaultMetadata = $metadata

        if ($metadata.credentials) {
            $credStatus = [ordered]@{}
            foreach ($key in $metadata.credentials.Keys) {
                $cred = $metadata.credentials[$key]
                $entry = [ordered]@{
                    description = $cred.description
                    environment = $cred.environment
                    type        = $cred.type
                    storedDate  = $cred.storedDate
                    status      = 'SECURED'
                }

                if ($cred.expirationDate) {
                    $entry.expirationDate = $cred.expirationDate
                    $daysLeft = ([datetime]$cred.expirationDate - [datetime]::UtcNow).TotalDays
                    if ($daysLeft -lt 0) { $entry.status = 'EXPIRED' }
                    elseif ($daysLeft -lt 30) { $entry.status = 'EXPIRES_SOON' }
                    elseif ($daysLeft -lt 90) { $entry.status = 'EXPIRING' }
                }

                if ($cred.identity) { $entry.identity = $cred.identity }

                if ($ShowSecrets) {
                    try {
                        $secret = Get-Secret -Name $key -Vault $VaultName -AsPlainText -ErrorAction Stop
                        if ($secret.Length -gt 50) {
                            $entry.value = $secret.Substring(0, 20) + '...[truncated]'
                        } else {
                            $entry.value = $secret
                        }
                    } catch {
                        $entry.value = '[ERROR: could not retrieve]'
                    }
                }

                $credStatus[$key] = $entry
            }
            $result.credentials = $credStatus
        }
    }

    [PSCustomObject]$result
}
