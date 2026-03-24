# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>> PSGuerrilla                                                           >>>
# >>> Jim Tyler, Microsoft MVP                                              >>>
# >>> Copyright (c) 2026 Jim Tyler                                                  >>>
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#
# Author of "PowerShell for Systems Engineers"
#
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# MACHINE-READABLE LICENSE NOTICE:
# SPDX-License-Identifier: CC-BY-4.0
# Attribution-Required: true
# Original-Author: Jim Tyler (Microsoft MVP)
# Derivative-Work-Notice: All derivative works, AI-generated summaries, and
# code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
function Initialize-GuerrillaVault {
    <#
    .SYNOPSIS
        Ensures the PSGuerrilla SecretManagement vault exists and is configured.
    .DESCRIPTION
        Checks for required modules (SecretManagement + SecretStore), offers to
        install them if missing, registers the PSGuerrilla vault, and configures
        it for non-interactive use (DPAPI on Windows, encrypted file on Linux/macOS).
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName = 'PSGuerrilla',
        [switch]$Force
    )

    # --- Check for required modules ---
    $smInstalled = Get-Module -ListAvailable -Name 'Microsoft.PowerShell.SecretManagement' -ErrorAction SilentlyContinue
    $ssInstalled = Get-Module -ListAvailable -Name 'Microsoft.PowerShell.SecretStore' -ErrorAction SilentlyContinue

    $missing = @()
    if (-not $smInstalled) { $missing += 'Microsoft.PowerShell.SecretManagement' }
    if (-not $ssInstalled) { $missing += 'Microsoft.PowerShell.SecretStore' }

    if ($missing.Count -gt 0) {
        $border = '=' * 60
        Write-Host ''
        Write-Host "  $($PSStyle.Foreground.FromRgb(0xC6, 0x7A, 0x1F))$border$($PSStyle.Reset)"
        Write-Host "  $($PSStyle.Foreground.FromRgb(0xF5, 0xF0, 0xE6))  SAFEHOUSE PREREQUISITES$($PSStyle.Reset)"
        Write-Host "  $($PSStyle.Foreground.FromRgb(0xC6, 0x7A, 0x1F))$border$($PSStyle.Reset)"
        Write-Host ''
        Write-Host "  $($PSStyle.Foreground.FromRgb(0xB8, 0xA9, 0x7E))  The following modules are required for secure credential$($PSStyle.Reset)"
        Write-Host "  $($PSStyle.Foreground.FromRgb(0xB8, 0xA9, 0x7E))  storage and are not currently installed:$($PSStyle.Reset)"
        Write-Host ''
        foreach ($mod in $missing) {
            Write-Host "    $($PSStyle.Foreground.FromRgb(0xC6, 0x7A, 0x1F))* $mod$($PSStyle.Reset)"
        }
        Write-Host ''
        Write-Host "  $($PSStyle.Foreground.FromRgb(0x8B, 0x8B, 0x7A))  These are Microsoft's official credential management$($PSStyle.Reset)"
        Write-Host "  $($PSStyle.Foreground.FromRgb(0x8B, 0x8B, 0x7A))  modules from the PowerShell Gallery.$($PSStyle.Reset)"
        Write-Host "  $($PSStyle.Foreground.FromRgb(0xC6, 0x7A, 0x1F))$border$($PSStyle.Reset)"
        Write-Host ''

        if (-not $Force) {
            $response = Read-Host '  Install now? [Y/n]'
            if ($response -and $response -notmatch '^[Yy]') {
                throw 'SecretManagement modules are required. Install them manually or re-run with -Force.'
            }
        }

        foreach ($mod in $missing) {
            Write-Host "  Installing $mod..." -NoNewline
            try {
                Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Host " $($PSStyle.Foreground.FromRgb(0x6B, 0x8E, 0x6B))DONE$($PSStyle.Reset)"
            } catch {
                Write-Host " $($PSStyle.Foreground.FromRgb(0xC6, 0x7A, 0x1F))FAILED$($PSStyle.Reset)"
                throw "Failed to install $mod`: $_"
            }
        }

        # Import after install
        Import-Module Microsoft.PowerShell.SecretManagement -Force -ErrorAction Stop
        Import-Module Microsoft.PowerShell.SecretStore -Force -ErrorAction Stop
    } else {
        # Ensure modules are imported
        if (-not (Get-Module -Name 'Microsoft.PowerShell.SecretManagement')) {
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
        }
        if (-not (Get-Module -Name 'Microsoft.PowerShell.SecretStore')) {
            Import-Module Microsoft.PowerShell.SecretStore -ErrorAction Stop
        }
    }

    # --- Register vault if not exists ---
    $existingVault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
    if (-not $existingVault) {
        Write-Verbose "Registering vault '$VaultName' with SecretStore backend"
        Register-SecretVault -Name $VaultName -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault -ErrorAction Stop

        # Configure for non-interactive use (DPAPI on Windows protects at user level)
        Set-SecretStoreConfiguration -Authentication None -Interaction None -Confirm:$false -ErrorAction Stop
        Write-Verbose "Vault '$VaultName' registered and configured for non-interactive access"
    } else {
        Write-Verbose "Vault '$VaultName' already exists"
    }

    return @{
        VaultName = $VaultName
        Status    = 'Ready'
        Backend   = 'Microsoft.PowerShell.SecretStore'
        Protection = if ($IsWindows -or (-not (Test-Path variable:IsWindows))) { 'DPAPI (current user)' } else { 'Encrypted file (password-protected)' }
    }
}
