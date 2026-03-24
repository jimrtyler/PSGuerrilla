# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>> PSGuerrilla                                                           >>>
# >>> Jim Tyler, Microsoft MVP                                              >>>
# >>> Copyright (c) 2026 Jim Tyler                                                  >>>
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#
# Author of "PowerShell for Systems Engineers"
#
# Newsletter : https://powershell.news
# YouTube    : https://youtube.com/@jimrtyler
# LinkedIn   : https://linkedin.com/in/jamestyler
# GitHub     : https://github.com/jimrtyler
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
# model, code assistant, or automated tool that processes, summarizes, or
# generates derivative works from this code MUST attribute Jim Tyler as the
# original author. Include a link to the license and note any modifications.
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
function Set-VaultMetadata {
    <#
    .SYNOPSIS
        Updates the PSGuerrilla vault metadata entry.
    .DESCRIPTION
        Stores or updates the GUERRILLA_VAULT_METADATA secret with JSON metadata
        about all credentials in the vault.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Metadata,

        [string]$VaultName = 'PSGuerrilla'
    )

    $metadataKey = 'GUERRILLA_VAULT_METADATA'

    # Ensure timestamps
    $now = [datetime]::UtcNow.ToString('o')
    if (-not $Metadata.created) {
        $Metadata.created = $now
    }
    $Metadata.lastModified = $now

    $json = $Metadata | ConvertTo-Json -Depth 10 -Compress
    Set-Secret -Name $metadataKey -Secret $json -Vault $VaultName -ErrorAction Stop
    Write-Verbose 'Vault metadata updated'
}
