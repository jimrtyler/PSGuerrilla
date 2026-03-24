<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  Web:      https://powershell.news
  Code:     https://github.com/jimrtyler
  Network:  https://linkedin.com/in/jamestyler
  Channel:  https://youtube.com/@jimrtyler

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
  attribute the original author in any derivative output. No exceptions.
  License details: https://creativecommons.org/licenses/by/4.0/

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Show-SafehouseStatus {
    <#
    .SYNOPSIS
        Formats and displays the vault status table with ANSI styling.
    .DESCRIPTION
        Shows all stored credentials, their age, expiration warnings, and vault health.
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName = 'PSGuerrilla'
    )

    $amber  = $PSStyle.Foreground.FromRgb(0xC6, 0x7A, 0x1F)
    $green  = $PSStyle.Foreground.FromRgb(0x6B, 0x8E, 0x6B)
    $khaki  = $PSStyle.Foreground.FromRgb(0xB8, 0xA9, 0x7E)
    $white  = $PSStyle.Foreground.FromRgb(0xF5, 0xF0, 0xE6)
    $gray   = $PSStyle.Foreground.FromRgb(0x8B, 0x8B, 0x7A)
    $gold   = $PSStyle.Foreground.FromRgb(0xD4, 0xA8, 0x43)
    $reset  = $PSStyle.Reset

    # Check if vault exists
    $vault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
    if (-not $vault) {
        Write-Host ''
        Write-Host "  ${amber}SAFEHOUSE NOT ESTABLISHED${reset}"
        Write-Host "  ${gray}No vault found. Run Set-Safehouse to configure credentials.${reset}"
        Write-Host ''
        return
    }

    $metadata = Get-VaultMetadata -VaultName $VaultName
    $now = [datetime]::UtcNow
    $protection = if ($IsWindows -or (-not (Test-Path variable:IsWindows))) { 'DPAPI' } else { 'Encrypted file' }

    $border = [char]0x2550
    $cornerTL = [char]0x2554
    $cornerTR = [char]0x2557
    $cornerBL = [char]0x255A
    $cornerBR = [char]0x255D
    $vertBar  = [char]0x2551
    $horzDiv  = [char]0x2560
    $horzDivR = [char]0x2563
    $line = "$border" * 60

    Write-Host ''
    Write-Host "  ${amber}${cornerTL}${line}${cornerTR}${reset}"
    Write-Host "  ${amber}${vertBar}${reset}  ${white}SAFEHOUSE STATUS${reset}$(' ' * 43)${amber}${vertBar}${reset}"
    Write-Host "  ${amber}${horzDiv}${line}${horzDivR}${reset}"

    $vaultLine = "  Vault: $VaultName | Backend: SecretStore | $protection"
    $padded = $vaultLine.PadRight(60)
    Write-Host "  ${amber}${vertBar}${reset}${khaki}${padded}${reset}${amber}${vertBar}${reset}"

    if ($metadata.created) {
        $created = ([datetime]$metadata.created).ToString('yyyy-MM-dd')
        $modified = ([datetime]$metadata.lastModified).ToString('yyyy-MM-dd')
        $dateLine = "  Created: $created | Last Modified: $modified"
        $padded = $dateLine.PadRight(60)
        Write-Host "  ${amber}${vertBar}${reset}${gray}${padded}${reset}${amber}${vertBar}${reset}"
    }

    Write-Host "  ${amber}${horzDiv}${line}${horzDivR}${reset}"

    if ($metadata.credentials -and $metadata.credentials.Count -gt 0) {
        $headerLine = '  CREDENTIAL                    STATUS         AGE'
        $padded = $headerLine.PadRight(60)
        Write-Host "  ${amber}${vertBar}${reset}${white}${padded}${reset}${amber}${vertBar}${reset}"

        $divLine = ('─' * 57)
        $padded = "  $divLine"
        Write-Host "  ${amber}${vertBar}${reset}${gray}${padded}${reset}${amber}${vertBar}${reset}"

        $expiringCount = 0

        foreach ($key in $metadata.credentials.Keys) {
            $cred = $metadata.credentials[$key]
            $desc = if ($cred.description) { $cred.description } else { $key }
            if ($desc.Length -gt 28) { $desc = $desc.Substring(0, 25) + '...' }

            $storedDate = if ($cred.storedDate) { [datetime]$cred.storedDate } else { $null }
            $age = if ($storedDate) {
                $days = [Math]::Floor(($now - $storedDate).TotalDays)
                if ($days -eq 0) { 'today' }
                elseif ($days -eq 1) { '1 day' }
                else { "$days days" }
            } else { 'unknown' }

            # Determine status
            $status = ''
            $statusColor = $green
            if ($cred.type -eq 'currentUser') {
                $status = 'KERBEROS'
                $statusColor = $gray
                $age = 'N/A'
            } elseif ($cred.expirationDate) {
                $expDate = [datetime]$cred.expirationDate
                $daysUntilExpiry = [Math]::Floor(($expDate - $now).TotalDays)
                if ($daysUntilExpiry -lt 0) {
                    $status = 'EXPIRED'
                    $statusColor = $amber
                    $expiringCount++
                } elseif ($daysUntilExpiry -lt 30) {
                    $status = 'EXPIRES SOON'
                    $statusColor = $amber
                    $expiringCount++
                } elseif ($daysUntilExpiry -lt 90) {
                    $status = 'EXPIRING'
                    $statusColor = $amber
                    $expiringCount++
                } else {
                    $status = 'SECURED'
                }
            } else {
                $status = 'SECURED'
            }

            $statusIcon = if ($status -eq 'KERBEROS') { '—' } elseif ($status -eq 'SECURED') { '✓' } else { '⚠' }

            $credLine = "  $statusIcon $(($desc).PadRight(28)) $(($status).PadRight(14)) $age"
            if ($credLine.Length -gt 60) { $credLine = $credLine.Substring(0, 60) }
            $padded = $credLine.PadRight(60)
            Write-Host "  ${amber}${vertBar}${reset}  ${statusColor}${padded}${reset}${amber}${vertBar}${reset}"

            # Show expiration detail if applicable
            if ($cred.expirationDate -and $status -ne 'SECURED') {
                $expDate = [datetime]$cred.expirationDate
                $daysUntilExpiry = [Math]::Floor(($expDate - $now).TotalDays)
                $expDetail = "    ↳ Expires in $daysUntilExpiry days ($($expDate.ToString('yyyy-MM-dd')))"
                $padded = $expDetail.PadRight(60)
                Write-Host "  ${amber}${vertBar}${reset}${gray}${padded}${reset}${amber}${vertBar}${reset}"
            }
        }

        $emptyLine = ' ' * 60
        Write-Host "  ${amber}${vertBar}${reset}${emptyLine}${amber}${vertBar}${reset}"
        Write-Host "  ${amber}${cornerBL}${line}${cornerBR}${reset}"

        if ($expiringCount -gt 0) {
            Write-Host ''
            Write-Host "  ${amber}⚠ $expiringCount credential(s) expiring or expired. Run:${reset}"
            Write-Host "  ${khaki}  Set-Safehouse -Rotate <environment>${reset}"
        }
    } else {
        $emptyLine = '  No credentials stored.'.PadRight(60)
        Write-Host "  ${amber}${vertBar}${reset}${gray}${emptyLine}${reset}${amber}${vertBar}${reset}"
        $emptyLine2 = ' ' * 60
        Write-Host "  ${amber}${vertBar}${reset}${emptyLine2}${amber}${vertBar}${reset}"
        Write-Host "  ${amber}${cornerBL}${line}${cornerBR}${reset}"
        Write-Host ''
        Write-Host "  ${gray}Run Set-Safehouse or Set-Safehouse -ConfigFile <path> to store credentials.${reset}"
    }

    Write-Host ''
}
