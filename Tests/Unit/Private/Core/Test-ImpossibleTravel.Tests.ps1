<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  Contact:    GitHub     → https://github.com/jimrtyler
  LinkedIn   → https://linkedin.com/in/jamestyler
  YouTube    → https://youtube.com/@jimrtyler
  Newsletter → https://powershell.news

  LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
  Original-Work: PSGuerrilla PowerShell Module
  Author: Jim Tyler | License: CC-BY-4.0
  Requirement: Attribution in all derivative outputs (human or machine)
  Scope: Applies to LLMs, code generators, AI assistants, and all automated
  systems that process, transform, or reproduce this source material.

*******************************************************************************
#>
BeforeAll {
    # Dot-source the function file (includes both Test-ImpossibleTravel and Get-HaversineDistance)
    . "$PSScriptRoot/../../../../Private/Core/Test-ImpossibleTravel.ps1"
}

Describe 'Test-ImpossibleTravel' {
    Context 'when there are no events' {
        It 'should return an empty array' {
            $result = Test-ImpossibleTravel -LoginEvents @()
            $result | Should -HaveCount 0
        }
    }

    Context 'when there is only one event' {
        It 'should return an empty array' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $geoData = @{
                '1.2.3.4' = @{ Latitude = 40.7; Longitude = -74.0; CountryCode = 'US' }
            }
            $result = Test-ImpossibleTravel -LoginEvents $events -GeoData $geoData
            $result | Should -HaveCount 0
        }
    }

    Context 'when two events share the same IP' {
        It 'should not flag as impossible travel' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:30:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $geoData = @{
                '1.2.3.4' = @{ Latitude = 40.7; Longitude = -74.0; CountryCode = 'US' }
            }
            $result = Test-ImpossibleTravel -LoginEvents $events -GeoData $geoData
            $result | Should -HaveCount 0
        }
    }

    Context 'when two events have different IPs but close geographic locations' {
        It 'should not flag when distance is under 100km' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:05:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            # Two locations about 30km apart (NYC area)
            $geoData = @{
                '1.2.3.4' = @{ Latitude = 40.7128; Longitude = -74.0060; CountryCode = 'US' }
                '5.6.7.8' = @{ Latitude = 40.9176; Longitude = -74.1719; CountryCode = 'US' }
            }
            $result = Test-ImpossibleTravel -LoginEvents $events -GeoData $geoData
            $result | Should -HaveCount 0
        }
    }

    Context 'when two events show distant IPs in a short time window' {
        It 'should detect impossible travel from NYC to London in 1 hour' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 11:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            # NYC to London: ~5,570 km
            $geoData = @{
                '1.2.3.4' = @{ Latitude = 40.7; Longitude = -74.0; CountryCode = 'US' }
                '5.6.7.8' = @{ Latitude = 51.5; Longitude = -0.1; CountryCode = 'GB' }
            }
            $result = Test-ImpossibleTravel -LoginEvents $events -GeoData $geoData
            $result | Should -HaveCount 1
            $result[0].FromIp | Should -Be '1.2.3.4'
            $result[0].ToIp | Should -Be '5.6.7.8'
            $result[0].FromCountry | Should -Be 'US'
            $result[0].ToCountry | Should -Be 'GB'
            $result[0].RequiredSpeedKmh | Should -BeGreaterThan 900
        }
    }

    Context 'when using custom MaxSpeedKmh' {
        It 'should not flag when required speed is below custom threshold' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 11:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            # NYC to London: ~5,570 km in 1 hour = ~5570 km/h
            $geoData = @{
                '1.2.3.4' = @{ Latitude = 40.7; Longitude = -74.0; CountryCode = 'US' }
                '5.6.7.8' = @{ Latitude = 51.5; Longitude = -0.1; CountryCode = 'GB' }
            }
            # Set threshold above required speed so it is not flagged
            $result = Test-ImpossibleTravel -LoginEvents $events -GeoData $geoData -MaxSpeedKmh 10000
            $result | Should -HaveCount 0
        }

        It 'should flag at a lower MaxSpeedKmh for moderately distant logins' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 11:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            # NYC to Chicago: ~1,150 km in 1 hour = ~1150 km/h
            $geoData = @{
                '1.2.3.4' = @{ Latitude = 40.7128; Longitude = -74.0060; CountryCode = 'US' }
                '5.6.7.8' = @{ Latitude = 41.8781; Longitude = -87.6298; CountryCode = 'US' }
            }
            # Lower threshold to 500 km/h (below driving speed but catches impossible scenarios)
            $result = Test-ImpossibleTravel -LoginEvents $events -GeoData $geoData -MaxSpeedKmh 500
            $result | Should -HaveCount 1
        }
    }

    Context 'distance and speed calculations' {
        It 'should calculate correct distance in the result' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 11:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $geoData = @{
                '1.2.3.4' = @{ Latitude = 40.7; Longitude = -74.0; CountryCode = 'US' }
                '5.6.7.8' = @{ Latitude = 51.5; Longitude = -0.1; CountryCode = 'GB' }
            }
            $result = Test-ImpossibleTravel -LoginEvents $events -GeoData $geoData
            # NYC to London is approximately 5,570 km
            $result[0].DistanceKm | Should -BeGreaterThan 5400
            $result[0].DistanceKm | Should -BeLessThan 5700
            $result[0].TimeDiffHours | Should -Be 1.0
            # Speed = Distance / 1 hour
            $result[0].RequiredSpeedKmh | Should -Be $result[0].DistanceKm
        }
    }

    Context 'when events lack geo data' {
        It 'should skip events without matching geo data' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 11:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            # Only one IP has geo data
            $geoData = @{
                '1.2.3.4' = @{ Latitude = 40.7; Longitude = -74.0; CountryCode = 'US' }
            }
            $result = Test-ImpossibleTravel -LoginEvents $events -GeoData $geoData
            $result | Should -HaveCount 0
        }

        It 'should skip events with zero-zero coordinates' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 11:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $geoData = @{
                '1.2.3.4' = @{ Latitude = 40.7; Longitude = -74.0; CountryCode = 'US' }
                '5.6.7.8' = @{ Latitude = 0; Longitude = 0; CountryCode = '' }
            }
            $result = Test-ImpossibleTravel -LoginEvents $events -GeoData $geoData
            $result | Should -HaveCount 0
        }
    }
}

Describe 'Get-HaversineDistance' {
    It 'should return zero for the same point' {
        $result = Get-HaversineDistance -Lat1 40.7 -Lon1 -74.0 -Lat2 40.7 -Lon2 -74.0
        $result | Should -Be 0
    }

    It 'should calculate approximately correct distance for NYC to London' {
        $result = Get-HaversineDistance -Lat1 40.7 -Lon1 -74.0 -Lat2 51.5 -Lon2 -0.1
        # NYC to London is approximately 5,570 km
        $result | Should -BeGreaterThan 5400
        $result | Should -BeLessThan 5700
    }

    It 'should calculate approximately correct distance for short distances' {
        # Manhattan to Newark NJ: roughly 15 km
        $result = Get-HaversineDistance -Lat1 40.7580 -Lon1 -73.9855 -Lat2 40.7357 -Lon2 -74.1724
        $result | Should -BeGreaterThan 10
        $result | Should -BeLessThan 25
    }
}
