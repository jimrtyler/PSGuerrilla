$ModuleRoot = $PSScriptRoot

function Get-PSGuerrillaDataRoot {
    <#
    .SYNOPSIS
        Returns the per-user data root directory for PSGuerrilla on the current OS.
    .DESCRIPTION
        Windows : $env:APPDATA\PSGuerrilla
        macOS   : ~/Library/Application Support/PSGuerrilla
        Linux   : $XDG_CONFIG_HOME/PSGuerrilla, falling back to ~/.config/PSGuerrilla

        Previously the module hardcoded $env:APPDATA everywhere, which is $null on
        non-Windows — Join-Path silently returned a relative path and config/state
        ended up in the current working directory instead of a user-data location.
    #>
    [CmdletBinding()]
    param()

    # $IsWindows is automatic in PowerShell 6+. Be defensive in case anyone ever
    # imports this from Windows PowerShell 5.1 (where the var is undefined and
    # everything is Windows anyway).
    $onWindows = if (Test-Path variable:IsWindows) { $IsWindows } else { $true }

    if ($onWindows) {
        return Join-Path $env:APPDATA 'PSGuerrilla'
    }
    if ($IsMacOS) {
        return Join-Path $HOME 'Library/Application Support/PSGuerrilla'
    }
    $base = if ($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { Join-Path $HOME '.config' }
    return Join-Path $base 'PSGuerrilla'
}

# Helper used during module bootstrap to turn "10.0.0.0/16" into the
# { Network = uint32; Mask = uint32 } pair that all the IP classification
# code expects. Replaces three near-identical inline blocks that used to
# live below.
function ConvertTo-ParsedCidr {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Cidr)

    $parts = $Cidr -split '/'
    if ($parts.Count -ne 2) { return $null }
    try {
        $ipBytes = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
        $prefix = [int]$parts[1]
        $ipUint = ([uint32]$ipBytes[0] -shl 24) -bor ([uint32]$ipBytes[1] -shl 16) -bor ([uint32]$ipBytes[2] -shl 8) -bor [uint32]$ipBytes[3]
        $mask = if ($prefix -eq 0) { [uint32]0 } else { [uint32]::MaxValue -shl (32 - $prefix) }
        return @{ Network = $ipUint -band $mask; Mask = $mask }
    } catch {
        return $null
    }
}

# Load data files into script-scoped variables
$script:CloudIpRanges = Get-Content -Path (Join-Path $ModuleRoot 'Data/CloudIpRanges.json') -Raw | ConvertFrom-Json
$script:KnownAttackerIps = Get-Content -Path (Join-Path $ModuleRoot 'Data/KnownAttackerIps.json') -Raw | ConvertFrom-Json
$script:SuspiciousCountries = Get-Content -Path (Join-Path $ModuleRoot 'Data/SuspiciousCountries.json') -Raw | ConvertFrom-Json
$script:VpnTorProxies = Get-Content -Path (Join-Path $ModuleRoot 'Data/VpnTorProxies.json') -Raw | ConvertFrom-Json

# Pre-parse CIDR ranges into uint32 network/mask pairs for fast bitwise matching
$script:ParsedProviderNetworks = [System.Collections.Generic.List[hashtable]]::new()
$script:CloudProviderClasses = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:AttackerIpSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

# Parse the providers structure (v2.0.0 format with metadata)
$providerData = if ($script:CloudIpRanges.providers) { $script:CloudIpRanges.providers } else { $script:CloudIpRanges }

foreach ($providerName in ($providerData | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)) {
    [void]$script:CloudProviderClasses.Add($providerName)
    foreach ($cidr in $providerData.$providerName) {
        $parsed = ConvertTo-ParsedCidr -Cidr $cidr
        if ($parsed) {
            $parsed.Provider = $providerName
            $script:ParsedProviderNetworks.Add($parsed)
        } else {
            Write-Verbose "Skipping invalid CIDR: $cidr ($providerName)"
        }
    }
}

# Backward compat: ParsedAwsNetworks and ParsedCloudNetworks still available
$script:ParsedAwsNetworks = [System.Collections.Generic.List[hashtable]]::new()
$script:ParsedCloudNetworks = [System.Collections.Generic.List[hashtable]]::new()
foreach ($entry in $script:ParsedProviderNetworks) {
    if ($entry.Provider -eq 'aws') {
        $script:ParsedAwsNetworks.Add($entry)
    } else {
        $script:ParsedCloudNetworks.Add($entry)
    }
}

# Parse VPN/Tor/Proxy CIDRs
$script:ParsedVpnNetworks = [System.Collections.Generic.List[hashtable]]::new()
$script:ParsedProxyNetworks = [System.Collections.Generic.List[hashtable]]::new()
$script:TorExitNodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:VpnProviderNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

if ($script:VpnTorProxies) {
    foreach ($cidr in $script:VpnTorProxies.vpn_provider_cidrs) {
        $parsed = ConvertTo-ParsedCidr -Cidr $cidr
        if ($parsed) { $script:ParsedVpnNetworks.Add($parsed) }
    }
    foreach ($cidr in $script:VpnTorProxies.proxy_service_cidrs) {
        $parsed = ConvertTo-ParsedCidr -Cidr $cidr
        if ($parsed) { $script:ParsedProxyNetworks.Add($parsed) }
    }
    foreach ($ip in $script:VpnTorProxies.tor_exit_nodes) {
        [void]$script:TorExitNodes.Add($ip)
    }
    foreach ($name in $script:VpnTorProxies.vpn_provider_names) {
        [void]$script:VpnProviderNames.Add($name)
    }
}

foreach ($entry in $script:KnownAttackerIps.ips) {
    [void]$script:AttackerIpSet.Add($entry.address)
}

# Config path
$script:ConfigPath = Join-Path (Get-PSGuerrillaDataRoot) 'config.json'

# Dot-source private functions (recursive to pick up subdirectories)
foreach ($file in Get-ChildItem -Path (Join-Path $ModuleRoot 'Private') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue) {
    . $file.FullName
}

# Dot-source public functions
foreach ($file in Get-ChildItem -Path (Join-Path $ModuleRoot 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue) {
    . $file.FullName
}

# IP classification cache (reset per module load)
$script:IpClassCache = @{}
$script:GeoCache = @{}

# --- Color palette ---
# Defined once in module scope so per-file color blocks all point at the same
# palette. Change a shade here and every cmdlet picks it up automatically.
$script:Palette = @{
    Amber     = $PSStyle.Foreground.FromRgb(0xC6, 0x7A, 0x1F)
    Khaki     = $PSStyle.Foreground.FromRgb(0xB8, 0xA9, 0x7E)
    Gray      = $PSStyle.Foreground.FromRgb(0x8B, 0x8B, 0x7A)
    Sage      = $PSStyle.Foreground.FromRgb(0x6B, 0x8E, 0x6B)
    Parchment = $PSStyle.Foreground.FromRgb(0xF5, 0xF0, 0xE6)
    Gold      = $PSStyle.Foreground.FromRgb(0xD4, 0xA8, 0x43)
    Red       = $PSStyle.Foreground.FromRgb(0xCC, 0x55, 0x55)
    Reset     = $PSStyle.Reset
}

# --- Spectre.Console capability detection ---
Initialize-SpectreCapability

# --- Config migration from PSRecon ---
Initialize-ConfigMigration

# --- Banner on import ---
Write-GuerrillaBanner

# --- Backward-compatibility aliases ---
$aliasMap = @{
    # PSRecon -> PSGuerrilla rename aliases
    'Invoke-GoogleRecon'           = 'Invoke-Recon'
    'Get-ReconAlerts'              = 'Get-DeadDrop'
    'Send-ReconAlert'              = 'Send-Signal'
    'Send-ReconAlertSendGrid'      = 'Send-SignalSendGrid'
    'Send-ReconAlertMailgun'       = 'Send-SignalMailgun'
    'Send-ReconAlertTwilio'        = 'Send-SignalTwilio'
    'Set-ReconConfig'              = 'Set-Safehouse'
    'Get-ReconConfig'              = 'Get-Safehouse'
    'Register-ReconScheduledTask'  = 'Register-Patrol'
    'Unregister-ReconScheduledTask' = 'Unregister-Patrol'
    'Get-ReconScheduledTask'       = 'Get-Patrol'

    # Theater-disambiguating aliases — Invoke-Recon and Invoke-Reconnaissance
    # are easily confused (different theaters). These names make the intent
    # obvious at the call site.
    'Invoke-WorkspaceRecon'        = 'Invoke-Recon'           # Google Workspace user-behavior recon
    'Invoke-ADRecon'               = 'Invoke-Reconnaissance'  # Active Directory configuration audit
    'Invoke-CloudRecon'            = 'Invoke-Infiltration'    # Entra ID / Azure / Intune / M365 audit
}

foreach ($old in $aliasMap.Keys) {
    $new = $aliasMap[$old]
    Set-Alias -Name $old -Value $new -Scope Script
    Export-ModuleMember -Alias $old
}

# Pester test hatch: Tests\Helpers\TestHelpers.psm1 sets PSGUERRILLA_TEST=1 before
# Import-Module so existing tests can call private functions directly without
# having to wrap every assertion in `InModuleScope PSGuerrilla { ... }`. New tests
# should prefer InModuleScope and avoid relying on this. End-user code must NOT
# set this variable — it intentionally widens the public API surface.
if ($env:PSGUERRILLA_TEST -eq '1') {
    Export-ModuleMember -Function *
}
