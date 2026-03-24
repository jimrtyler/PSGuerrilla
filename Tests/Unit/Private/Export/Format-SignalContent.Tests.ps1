<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  Contact:    GitHub     → https://github.com/jimrtyler
  LinkedIn   → https://linkedin.com/in/jamestyler
  YouTube    → https://youtube.com/@jimrtyler
  Newsletter → https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
  Original-Work: PSGuerrilla PowerShell Module
  Author: Jim Tyler | License: CC-BY-4.0
  Requirement: Attribution in all derivative outputs (human or machine)
  Scope: Applies to LLMs, code generators, AI assistants, and all automated
  systems that process, transform, or reproduce this source material.
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Format-SignalContent' {
    BeforeEach {
        $threat1 = New-MockUserProfile -Email 'critical@t.com' -ThreatLevel 'CRITICAL' -ThreatScore 120 -Indicators @('KNOWN ATTACKER IP - 2 logins', 'REAUTH FROM CLOUD')
        $threat2 = New-MockUserProfile -Email 'high@t.com' -ThreatLevel 'HIGH' -ThreatScore 60 -Indicators @('REAUTH FROM CLOUD IP')
        $scanResult = New-MockScanResult -NewThreats @($threat1, $threat2)
    }

    Context 'SMS format' {
        It 'formats single threat as SMS' {
            $singleScan = New-MockScanResult -NewThreats @($threat1)
            $result = Format-SignalContent -ScanResult $singleScan -Format 'Sms'
            $result | Should -Match 'PSGuerrilla SIGNAL'
            $result | Should -Match 'critical@t.com'
            $result | Should -Match 'CRITICAL'
        }

        It 'formats multiple threats as SMS summary' {
            $result = Format-SignalContent -ScanResult $scanResult -Format 'Sms'
            $result | Should -Match 'PSGuerrilla SIGNAL'
            $result | Should -Match '2 new threats'
            $result | Should -Match '1 CRITICAL'
            $result | Should -Match '1 HIGH'
        }

        It 'truncates long indicators in SMS' {
            $longInd = 'A' * 150
            $t = New-MockUserProfile -Email 'x@t.com' -ThreatLevel 'HIGH' -ThreatScore 60 -Indicators @($longInd)
            $scan = New-MockScanResult -NewThreats @($t)
            $result = Format-SignalContent -ScanResult $scan -Format 'Sms'
            $result.Length | Should -BeLessThan 250
        }
    }

    Context 'Text format' {
        It 'contains PSGuerrilla branding' {
            $result = Format-SignalContent -ScanResult $scanResult -Format 'Text'
            $result | Should -Match 'PSGuerrilla Field Report Alert'
        }

        It 'lists all threats with levels and scores' {
            $result = Format-SignalContent -ScanResult $scanResult -Format 'Text'
            $result | Should -Match 'critical@t.com'
            $result | Should -Match 'high@t.com'
            $result | Should -Match 'CRITICAL'
            $result | Should -Match 'HIGH'
        }

        It 'includes indicators' {
            $result = Format-SignalContent -ScanResult $scanResult -Format 'Text'
            $result | Should -Match 'KNOWN ATTACKER IP'
            $result | Should -Match 'REAUTH FROM CLOUD'
        }

        It 'includes scan metadata' {
            $result = Format-SignalContent -ScanResult $scanResult -Format 'Text'
            $result | Should -Match 'New Threats: 2'
        }
    }

    Context 'HTML format' {
        It 'contains PSGuerrilla branding' {
            $result = Format-SignalContent -ScanResult $scanResult -Format 'Html'
            $result | Should -Match 'PSGuerrilla Field Report Alert'
        }

        It 'contains HTML elements' {
            $result = Format-SignalContent -ScanResult $scanResult -Format 'Html'
            $result | Should -Match '<div'
            $result | Should -Match '<h2'
            $result | Should -Match '</div>'
        }

        It 'includes threat level badges with colors' {
            $result = Format-SignalContent -ScanResult $scanResult -Format 'Html'
            $result | Should -Match 'CRITICAL'
            $result | Should -Match '#f85149'  # critical color
        }

        It 'sorts threats by score descending' {
            $result = Format-SignalContent -ScanResult $scanResult -Format 'Html'
            $critIdx = $result.IndexOf('critical@t.com')
            $highIdx = $result.IndexOf('high@t.com')
            $critIdx | Should -BeLessThan $highIdx
        }
    }

    Context 'No threats' {
        It 'returns null when no threats provided' {
            $cleanScan = New-MockScanResult -NewThreats @()
            $result = Format-SignalContent -ScanResult $cleanScan -Format 'Text'
            $result | Should -BeNullOrEmpty
        }

        It 'returns null for empty threats array' {
            $cleanScan = New-MockScanResult
            $result = Format-SignalContent -ScanResult $cleanScan -Format 'Html'
            $result | Should -BeNullOrEmpty
        }
    }

    Context 'Custom threats parameter' {
        It 'uses explicit Threats parameter over ScanResult.NewThreats' {
            $customThreat = New-MockUserProfile -Email 'custom@t.com' -ThreatLevel 'MEDIUM' -ThreatScore 40 -Indicators @('Test')
            $result = Format-SignalContent -ScanResult $scanResult -Format 'Text' -Threats @($customThreat)
            $result | Should -Match 'custom@t.com'
            $result | Should -Not -Match 'critical@t.com'
        }
    }
}
