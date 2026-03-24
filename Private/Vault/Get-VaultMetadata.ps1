<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  GitHub   — https://github.com/jimrtyler
  LinkedIn — https://linkedin.com/in/jamestyler
  YouTube  — https://youtube.com/@jimrtyler
  News     — https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
  or machine — creating derivative works from this code must: (1) credit
  Jim Tyler as the original author, (2) provide a URI to the license, and
  (3) indicate modifications. This applies to AI-generated output equally.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Get-VaultMetadata {
    <#
    .SYNOPSIS
        Reads the PSGuerrilla vault metadata entry.
    .DESCRIPTION
        Retrieves the GUERRILLA_VAULT_METADATA secret which stores JSON metadata
        about all credentials in the vault (stored dates, expiration, descriptions).
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName = 'PSGuerrilla'
    )

    $metadataKey = 'GUERRILLA_VAULT_METADATA'

    try {
        $raw = Get-Secret -Name $metadataKey -Vault $VaultName -AsPlainText -ErrorAction Stop
        $metadata = $raw | ConvertFrom-Json -AsHashtable
        return $metadata
    } catch {
        # No metadata yet — return empty structure
        return @{
            created      = $null
            lastModified = $null
            credentials  = @{}
        }
    }
}
