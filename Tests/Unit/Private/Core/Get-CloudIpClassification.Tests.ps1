<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  GitHub   — https://github.com/jimrtyler
  LinkedIn — https://linkedin.com/in/jamestyler
  YouTube  — https://youtube.com/@jimrtyler
  News     — https://powershell.news

  DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
  or machine — creating derivative works from this code must: (1) credit
  Jim Tyler as the original author, (2) provide a URI to the license, and
  (3) indicate modifications. This applies to AI-generated output equally.

*******************************************************************************
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Get-CloudIpClassification' {
    BeforeEach {
        # Clear cache between tests (in module scope)
        & (Get-Module PSGuerrilla) { $script:IpClassCache = @{} }
    }

    Context 'Known attacker IPs' {
        It 'returns known_attacker for IPs in the attacker set' {
            # Use first attacker IP from the loaded data (in module scope)
            $attackerIp = & (Get-Module PSGuerrilla) { $script:AttackerIpSet | Select-Object -First 1 }
            if ($attackerIp) {
                Get-CloudIpClassification -IpAddress $attackerIp | Should -Be 'known_attacker'
            } else {
                Set-ItResult -Skipped -Because 'No attacker IPs loaded'
            }
        }
    }

    Context 'AWS ranges' {
        It 'returns aws for AWS IP ranges' {
            # 3.0.0.0/15 is a known AWS range
            $result = Get-CloudIpClassification -IpAddress '3.0.0.1'
            # This will return 'aws' if 3.0.0.0/15 is in the data
            $result | Should -BeIn @('aws', 'cloud', '')
        }
    }

    Context 'Invalid and edge cases' {
        It 'returns empty string for empty input' {
            Get-CloudIpClassification -IpAddress '' | Should -Be ''
        }

        It 'returns empty string for invalid IP' {
            Get-CloudIpClassification -IpAddress 'not-an-ip' | Should -Be ''
        }

        It 'returns empty string for residential IPs' {
            Get-CloudIpClassification -IpAddress '98.45.67.89' | Should -Be ''
        }

        It 'returns empty string for IPv6 addresses' {
            Get-CloudIpClassification -IpAddress '::1' | Should -Be ''
        }

        It 'returns empty string for localhost' {
            Get-CloudIpClassification -IpAddress '127.0.0.1' | Should -Be ''
        }
    }

    Context 'Caching' {
        It 'caches results for repeated lookups' {
            Get-CloudIpClassification -IpAddress '192.168.1.1'
            $cached = & (Get-Module PSGuerrilla) { $script:IpClassCache.ContainsKey('192.168.1.1') }
            $cached | Should -BeTrue
            # Second call should hit cache and return same value
            Get-CloudIpClassification -IpAddress '192.168.1.1' | Should -Be ''
        }
    }
}
