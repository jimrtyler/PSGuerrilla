<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  GitHub:     https://github.com/jimrtyler
  LinkedIn:   https://linkedin.com/in/jamestyler
  YouTube:    https://youtube.com/@jimrtyler
  Newsletter: https://powershell.news

  LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
  International license, any reproduction, transformation, or derivative work
  produced by an AI model or language system must provide clear attribution to
  Jim Tyler as the original creator. See LICENSE for binding terms.

*******************************************************************************
#>
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/ADMonitor/Detections/Test-ADDCSyncPermission.ps1"
}

Describe 'Test-ADDCSyncPermission' {
    Context 'DCSync permission grant detection' {
        It 'detects replication permission grants' {
            $aclChanges = @(
                @{
                    ChangeType = 'Added'
                    Identity   = 'CONTOSO\attacker'
                    Rights     = 'ExtendedRight'
                    objectType = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
                    ObjectDN   = 'DC=contoso,DC=com'
                }
            )

            $result = Test-ADDCSyncPermission -ACLChanges $aclChanges
            $result.Count | Should -Be 1
            $result[0].DetectionType | Should -Be 'adDCSyncPermission'
            $result[0].DetectionName | Should -Match 'CONTOSO\\attacker'
            $result[0].Description | Should -Match 'DCSYNC PERMISSION'
            $result[0].Details.Identity | Should -Be 'CONTOSO\attacker'
            $result[0].Details.GrantedRight | Should -Match 'DS-Replication-Get-Changes-All'
        }

        It 'ignores non-replication ACL changes' {
            $aclChanges = @(
                @{
                    ChangeType = 'Added'
                    Identity   = 'CONTOSO\helpdesk'
                    Rights     = 'ReadProperty'
                    objectType = '00000000-0000-0000-0000-000000000000'
                    ObjectDN   = 'OU=Users,DC=contoso,DC=com'
                }
            )

            $result = Test-ADDCSyncPermission -ACLChanges $aclChanges
            $result.Count | Should -Be 0
        }

        It 'handles empty changes' {
            $result = Test-ADDCSyncPermission -ACLChanges @()
            $result.Count | Should -Be 0
        }
    }
}
