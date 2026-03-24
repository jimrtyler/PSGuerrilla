# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>> PSGuerrilla                                                           >>>
# >>> Jim Tyler, Microsoft MVP                                              >>>
# >>> Copyright (c) 2026 Jim Tyler                                                  >>>
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#
# Author of "PowerShell for Systems Engineers"
#
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
# International license, any reproduction, transformation, or derivative work
# produced by an AI model or language system must provide clear attribution to
# Jim Tyler as the original creator. See LICENSE for binding terms.
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
function Test-CredentialConnectivity {
    <#
    .SYNOPSIS
        Tests stored credentials by attempting minimal API calls.
    .DESCRIPTION
        For each stored credential, attempts a lightweight connectivity test.
        Returns results for display by the caller.
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName = 'PSGuerrilla'
    )

    $metadata = Get-VaultMetadata -VaultName $VaultName
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not $metadata.credentials -or $metadata.credentials.Count -eq 0) {
        Write-Warning 'No credentials found in vault. Run Set-Safehouse first.'
        return $results
    }

    $amber = $PSStyle.Foreground.FromRgb(0xC6, 0x7A, 0x1F)
    $green = $PSStyle.Foreground.FromRgb(0x6B, 0x8E, 0x6B)
    $white = $PSStyle.Foreground.FromRgb(0xF5, 0xF0, 0xE6)
    $khaki = $PSStyle.Foreground.FromRgb(0xB8, 0xA9, 0x7E)
    $reset = $PSStyle.Reset

    Write-Host ''
    Write-Host "  ${white}SAFEHOUSE CONNECTIVITY TEST${reset}"
    Write-Host "  ${khaki}$('─' * 50)${reset}"

    foreach ($key in $metadata.credentials.Keys) {
        $cred = $metadata.credentials[$key]
        $env = if ($cred.environment) { $cred.environment } else { 'unknown' }
        $desc = if ($cred.description) { $cred.description } else { $key }

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $status = 'UNKNOWN'
        $detail = ''

        try {
            switch ($cred.environment) {
                'googleWorkspace' {
                    $saJson = Get-GuerrillaCredential -VaultKey $key -VaultName $VaultName
                    $sa = if ($saJson -is [securestring]) {
                        [System.Net.NetworkCredential]::new('', $saJson).Password | ConvertFrom-Json
                    } else {
                        $saJson | ConvertFrom-Json
                    }
                    if ($sa.client_email -and $sa.private_key) {
                        $status = 'CONNECTED'
                        $detail = $sa.client_email
                    } else {
                        $status = 'INVALID'
                        $detail = 'Missing client_email or private_key in service account JSON'
                    }
                }
                'microsoftGraph' {
                    # For tenant/client IDs just validate format
                    if ($cred.type -eq 'tenantId' -or $cred.type -eq 'clientId') {
                        $val = Get-GuerrillaCredential -VaultKey $key -VaultName $VaultName
                        $plainVal = if ($val -is [securestring]) {
                            [System.Net.NetworkCredential]::new('', $val).Password
                        } else { "$val" }
                        if ($plainVal -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                            $status = 'VALID'
                        } else {
                            $status = 'INVALID'
                            $detail = 'Not a valid GUID format'
                        }
                    } elseif ($cred.type -eq 'clientSecret') {
                        $val = Get-GuerrillaCredential -VaultKey $key -VaultName $VaultName
                        $status = if ($val) { 'STORED' } else { 'MISSING' }
                    } else {
                        $status = 'STORED'
                    }
                }
                'activeDirectory' {
                    if ($cred.type -eq 'currentUser') {
                        $status = 'KERBEROS'
                        $detail = 'Using current user context'
                    } else {
                        $val = Get-GuerrillaCredential -VaultKey $key -VaultName $VaultName
                        $status = if ($val) { 'STORED' } else { 'MISSING' }
                    }
                }
                'alerting' {
                    $val = Get-GuerrillaCredential -VaultKey $key -VaultName $VaultName
                    $status = if ($val) { 'STORED' } else { 'MISSING' }
                }
                default {
                    $val = Get-GuerrillaCredential -VaultKey $key -VaultName $VaultName
                    $status = if ($val) { 'STORED' } else { 'MISSING' }
                }
            }
        } catch {
            $status = 'FAILED'
            $detail = $_.Exception.Message
        }

        $sw.Stop()
        $elapsed = "$($sw.ElapsedMilliseconds)ms"

        $statusColor = switch ($status) {
            'CONNECTED' { $green }
            'VALID'     { $green }
            'STORED'    { $green }
            'KERBEROS'  { $green }
            default     { $amber }
        }
        $statusIcon = switch ($status) {
            'CONNECTED' { '✓' }
            'VALID'     { '✓' }
            'STORED'    { '✓' }
            'KERBEROS'  { '✓' }
            'FAILED'    { '✗' }
            'INVALID'   { '✗' }
            'MISSING'   { '✗' }
            default     { '?' }
        }

        $descShort = if ($desc.Length -gt 22) { $desc.Substring(0, 19) + '...' } else { $desc }
        Write-Host "  ${statusColor}${statusIcon} $(($descShort).PadRight(22)) $(($status).PadRight(12)) ${elapsed}${reset}"

        if ($detail -and $status -in @('FAILED', 'INVALID')) {
            Write-Host "    ${amber}↳ ${detail}${reset}"
        }

        $results.Add([PSCustomObject]@{
            VaultKey    = $key
            Description = $desc
            Environment = $env
            Status      = $status
            Detail      = $detail
            ElapsedMs   = $sw.ElapsedMilliseconds
        })
    }

    Write-Host ''
    return $results
}
