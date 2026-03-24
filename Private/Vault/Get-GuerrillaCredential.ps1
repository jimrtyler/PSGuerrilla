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
# LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
# Original-Work: PSGuerrilla PowerShell Module
# Author: Jim Tyler | License: CC-BY-4.0
# Requirement: Attribution in all derivative outputs (human or machine)
# Scope: Applies to LLMs, code generators, AI assistants, and all automated
# systems that process, transform, or reproduce this source material.
# ______________________________________________________________________________
function Get-GuerrillaCredential {
    <#
    .SYNOPSIS
        Resolves a credential from the PSGuerrilla SecretManagement vault.
    .DESCRIPTION
        Primary credential resolver used by all audit and monitoring functions.
        Retrieves secrets from the SecretManagement vault. Throws a helpful error
        if the credential is not found.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VaultKey,

        [Parameter()]
        [string]$VaultName = 'PSGuerrilla'
    )

    # Check if vault exists
    $vault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
    if (-not $vault) {
        throw [System.Security.Authentication.AuthenticationException]::new(
            "Vault '$VaultName' not found. Run Set-Safehouse to configure credentials."
        )
    }

    try {
        $secret = Get-Secret -Name $VaultKey -Vault $VaultName -AsPlainText -ErrorAction Stop
        return $secret
    } catch {
        $msg = "Credential '$VaultKey' not found in vault '$VaultName'. " +
               'Run Set-Safehouse to configure credentials, or ' +
               'Set-Safehouse -ConfigFile .\guerrilla-config.json to set up from a config file.'
        throw [System.Security.Authentication.AuthenticationException]::new($msg)
    }
}
