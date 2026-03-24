<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  • GitHub     https://github.com/jimrtyler
  • LinkedIn   https://linkedin.com/in/jamestyler
  • YouTube    https://youtube.com/@jimrtyler
  • Newsletter https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  MACHINE-READABLE LICENSE NOTICE:
  SPDX-License-Identifier: CC-BY-4.0
  Attribution-Required: true
  Original-Author: Jim Tyler (Microsoft MVP)
  Derivative-Work-Notice: All derivative works, AI-generated summaries, and
  code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
#>
BeforeAll {
    . "$PSScriptRoot/../../../../Private/Core/Test-NewDevice.ps1"
    . "$PSScriptRoot/../../../../Private/Core/Get-CloudIpClassification.ps1"

    # Initialize script-scoped variables that Get-CloudIpClassification and Test-NewDevice depend on
    $script:IpClassCache = @{}
    $script:AttackerIpSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $script:TorExitNodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $script:ParsedProviderNetworks = [System.Collections.Generic.List[hashtable]]::new()
    $script:ParsedVpnNetworks = [System.Collections.Generic.List[hashtable]]::new()
    $script:ParsedProxyNetworks = [System.Collections.Generic.List[hashtable]]::new()
    $script:CloudProviderClasses = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
}

Describe 'Test-NewDevice' {
    BeforeEach {
        # Reset caches and classification data before each test
        $script:IpClassCache = @{}
        $script:AttackerIpSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $script:TorExitNodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $script:ParsedProviderNetworks = [System.Collections.Generic.List[hashtable]]::new()
        $script:ParsedVpnNetworks = [System.Collections.Generic.List[hashtable]]::new()
        $script:ParsedProxyNetworks = [System.Collections.Generic.List[hashtable]]::new()
        $script:CloudProviderClasses = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }

    Context 'when there are no events' {
        It 'should return an empty array' {
            $result = Test-NewDevice -LoginEvents @()
            $result | Should -HaveCount 0
        }
    }

    Context 'when an event has a device_id' {
        It 'should detect the first occurrence as a new device' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        device_id  = 'device-abc-123'
                    }
                }
            )
            $result = Test-NewDevice -LoginEvents $events
            $result | Should -HaveCount 1
            $result[0].DeviceId | Should -Be 'device-abc-123'
            $result[0].Fingerprint | Should -Be 'device:device-abc-123'
            $result[0].IpAddress | Should -Be '1.2.3.4'
            $result[0].EventName | Should -Be 'login_success'
        }
    }

    Context 'when the same device_id appears twice' {
        It 'should only report the first occurrence' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        device_id  = 'device-abc-123'
                    }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 14:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        device_id  = 'device-abc-123'
                    }
                }
            )
            $result = Test-NewDevice -LoginEvents $events
            $result | Should -HaveCount 1
            $result[0].Timestamp | Should -Be ([datetime]'2026-01-15 10:00:00Z')
        }
    }

    Context 'when using the PreviousDevices parameter' {
        It 'should not flag a known device' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        device_id  = 'device-abc-123'
                    }
                }
            )
            $previousDevices = @{
                'device:device-abc-123' = $true
            }
            $result = Test-NewDevice -LoginEvents $events -PreviousDevices $previousDevices
            $result | Should -HaveCount 0
        }

        It 'should flag a device not in PreviousDevices' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        device_id  = 'device-new-456'
                    }
                }
            )
            $previousDevices = @{
                'device:device-abc-123' = $true
            }
            $result = Test-NewDevice -LoginEvents $events -PreviousDevices $previousDevices
            $result | Should -HaveCount 1
            $result[0].DeviceId | Should -Be 'device-new-456'
        }
    }

    Context 'when a new device logs in from a cloud IP' {
        It 'should set IsCloudIp to true for a known cloud provider IP' {
            # Register 'aws' as a cloud provider class
            [void]$script:CloudProviderClasses.Add('aws')

            # Mock Get-CloudIpClassification to return 'aws'
            Mock Get-CloudIpClassification { return 'aws' }

            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '52.94.76.1'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        device_id  = 'device-cloud-789'
                    }
                }
            )
            $result = Test-NewDevice -LoginEvents $events
            $result | Should -HaveCount 1
            $result[0].IsCloudIp | Should -BeTrue
            $result[0].IpClass | Should -Be 'aws'
        }

        It 'should set IsCloudIp to true for a known_attacker IP' {
            Mock Get-CloudIpClassification { return 'known_attacker' }

            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '198.51.100.1'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        device_id  = 'device-attacker-111'
                    }
                }
            )
            $result = Test-NewDevice -LoginEvents $events
            $result | Should -HaveCount 1
            $result[0].IsCloudIp | Should -BeTrue
            $result[0].IpClass | Should -Be 'known_attacker'
        }

        It 'should set IsCloudIp to false for a residential IP' {
            Mock Get-CloudIpClassification { return '' }

            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '192.168.1.100'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        device_id  = 'device-home-222'
                    }
                }
            )
            $result = Test-NewDevice -LoginEvents $events
            $result | Should -HaveCount 1
            $result[0].IsCloudIp | Should -BeFalse
            $result[0].IpClass | Should -Be ''
        }
    }

    Context 'when events use user_agent instead of device_id' {
        It 'should use user_agent as the fingerprint' {
            Mock Get-CloudIpClassification { return '' }

            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
                    }
                }
            )
            $result = Test-NewDevice -LoginEvents $events
            $result | Should -HaveCount 1
            $result[0].Fingerprint | Should -Be 'ua:Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
            $result[0].DeviceId | Should -BeNullOrEmpty
            $result[0].UserAgent | Should -Be 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
        }
    }

    Context 'when events have neither device_id nor user_agent' {
        It 'should skip the event entirely' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                    }
                }
            )
            $result = Test-NewDevice -LoginEvents $events
            $result | Should -HaveCount 0
        }
    }

    Context 'when device_id takes priority over user_agent' {
        It 'should use device_id for the fingerprint when both are present' {
            Mock Get-CloudIpClassification { return '' }

            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        device_id  = 'device-abc-123'
                        user_agent = 'Mozilla/5.0 Chrome/120.0.0.0'
                    }
                }
            )
            $result = Test-NewDevice -LoginEvents $events
            $result | Should -HaveCount 1
            $result[0].Fingerprint | Should -Be 'device:device-abc-123'
        }
    }

    Context 'result object structure' {
        It 'should contain the expected properties' {
            Mock Get-CloudIpClassification { return '' }

            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        device_id  = 'device-abc-123'
                    }
                }
            )
            $result = Test-NewDevice -LoginEvents $events
            $result[0].PSObject.Properties.Name | Should -Contain 'Timestamp'
            $result[0].PSObject.Properties.Name | Should -Contain 'IpAddress'
            $result[0].PSObject.Properties.Name | Should -Contain 'IpClass'
            $result[0].PSObject.Properties.Name | Should -Contain 'IsCloudIp'
            $result[0].PSObject.Properties.Name | Should -Contain 'DeviceId'
            $result[0].PSObject.Properties.Name | Should -Contain 'UserAgent'
            $result[0].PSObject.Properties.Name | Should -Contain 'Fingerprint'
            $result[0].PSObject.Properties.Name | Should -Contain 'EventName'
        }
    }
}
