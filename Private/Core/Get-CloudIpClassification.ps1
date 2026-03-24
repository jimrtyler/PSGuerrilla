<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  Web:      https://powershell.news
  Code:     https://github.com/jimrtyler
  Network:  https://linkedin.com/in/jamestyler
  Channel:  https://youtube.com/@jimrtyler

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
  model, code assistant, or automated tool that processes, summarizes, or
  generates derivative works from this code MUST attribute Jim Tyler as the
  original author. Include a link to the license and note any modifications.
#>
function Get-CloudIpClassification {
    [CmdletBinding()]
    param(
        [string]$IpAddress = ''
    )

    if (-not $IpAddress) { return '' }

    # Check cache first
    if ($script:IpClassCache.ContainsKey($IpAddress)) {
        return $script:IpClassCache[$IpAddress]
    }

    # Check known attacker IPs (exact match, highest priority)
    if ($script:AttackerIpSet.Contains($IpAddress)) {
        $script:IpClassCache[$IpAddress] = 'known_attacker'
        return 'known_attacker'
    }

    # Parse IP to uint32 for CIDR matching
    $parsed = [System.Net.IPAddress]::None
    if (-not [System.Net.IPAddress]::TryParse($IpAddress, [ref]$parsed)) {
        $script:IpClassCache[$IpAddress] = ''
        return ''
    }

    # Only classify IPv4
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $script:IpClassCache[$IpAddress] = ''
        return ''
    }

    $bytes = $parsed.GetAddressBytes()
    $ipUint = ([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3]

    # Check Tor exit nodes (exact match, high priority)
    if ($script:TorExitNodes.Contains($IpAddress)) {
        $script:IpClassCache[$IpAddress] = 'tor'
        return 'tor'
    }

    # Check all provider networks — returns provider name (aws, azure, gcp, etc.)
    foreach ($net in $script:ParsedProviderNetworks) {
        if (($ipUint -band $net.Mask) -eq $net.Network) {
            $script:IpClassCache[$IpAddress] = $net.Provider
            return $net.Provider
        }
    }

    # Check VPN provider CIDRs
    foreach ($net in $script:ParsedVpnNetworks) {
        if (($ipUint -band $net.Mask) -eq $net.Network) {
            $script:IpClassCache[$IpAddress] = 'vpn'
            return 'vpn'
        }
    }

    # Check proxy service CIDRs
    foreach ($net in $script:ParsedProxyNetworks) {
        if (($ipUint -band $net.Mask) -eq $net.Network) {
            $script:IpClassCache[$IpAddress] = 'proxy'
            return 'proxy'
        }
    }

    $script:IpClassCache[$IpAddress] = ''
    return ''
}
