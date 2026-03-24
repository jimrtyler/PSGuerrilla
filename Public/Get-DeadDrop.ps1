# [============================================================================]
# [  PSGuerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
# [============================================================================]
# DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
# or machine — creating derivative works from this code must: (1) credit
# Jim Tyler as the original author, (2) provide a URI to the license, and
# (3) indicate modifications. This applies to AI-generated output equally.
# [============================================================================]
function Get-DeadDrop {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$ScanResult,

        [ValidateSet('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')]
        [string]$MinimumThreatLevel,

        [switch]$NewOnly,

        [string[]]$User,

        [string]$IndicatorPattern,

        [datetime]$Since,

        [switch]$FromStateFile,

        [string]$ConfigPath
    )

    process {
        $profiles = $null

        if ($FromStateFile) {
            $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
            $state = Get-OperationState -ConfigPath $cfgPath
            if (-not $state -or -not $state.alertedUsers) {
                Write-Warning 'No state file found or no alerted users in state.'
                return
            }

            # Return alerted users from state as lightweight objects
            $profiles = foreach ($email in $state.alertedUsers.Keys) {
                $u = $state.alertedUsers[$email]
                [PSCustomObject]@{
                    PSTypeName    = 'PSGuerrilla.UserProfile'
                    Email         = $email
                    ThreatLevel   = $u.lastThreatLevel
                    ThreatScore   = $u.lastThreatScore
                    FirstDetected = $u.firstDetected
                    LastAlerted   = $u.lastAlerted
                    AlertCount    = $u.alertCount
                }
            }
        } elseif ($ScanResult -and $ScanResult.PSObject.TypeNames -contains 'PSGuerrilla.ScanResult') {
            $profiles = if ($NewOnly) { $ScanResult.NewThreats } else { $ScanResult.FlaggedUsers }
        } else {
            Write-Warning 'Provide a PSGuerrilla.ScanResult via pipeline or use -FromStateFile.'
            return
        }

        if (-not $profiles) { return }

        # Filter by minimum threat level
        if ($MinimumThreatLevel) {
            $levelOrder = @{ 'LOW' = 1; 'MEDIUM' = 2; 'HIGH' = 3; 'CRITICAL' = 4 }
            $minOrdinal = $levelOrder[$MinimumThreatLevel]
            $profiles = @($profiles | Where-Object { $levelOrder[$_.ThreatLevel] -ge $minOrdinal })
        }

        # Filter by user (supports wildcards)
        if ($User) {
            $profiles = @($profiles | Where-Object {
                $email = $_.Email
                $User | Where-Object { $email -like $_ }
            })
        }

        # Filter by indicator pattern (regex)
        if ($IndicatorPattern) {
            $profiles = @($profiles | Where-Object {
                $_.Indicators | Where-Object { $_ -match $IndicatorPattern }
            })
        }

        # Filter by since
        if ($Since) {
            if ($FromStateFile) {
                $profiles = @($profiles | Where-Object {
                    $_.FirstDetected -and [datetime]::Parse($_.FirstDetected) -ge $Since
                })
            }
            # For pipeline data, all events are from the current scan so Since filtering is less relevant
        }

        return @($profiles)
    }
}
