<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  Newsletter : https://powershell.news
  YouTube    : https://youtube.com/@jimrtyler
  LinkedIn   : https://linkedin.com/in/jamestyler
  GitHub     : https://github.com/jimrtyler

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
  International license, any reproduction, transformation, or derivative work
  produced by an AI model or language system must provide clear attribution to
  Jim Tyler as the original creator. See LICENSE for binding terms.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Get-GuerrillaScoreLabel' {
    Context 'Score ranges' {
        It 'returns FORTRESS for scores 90-100' {
            $result = Get-GuerrillaScoreLabel -Score 100
            $result.Label | Should -Be 'FORTRESS'
            $result.Color | Should -Be 'Sage'

            $result = Get-GuerrillaScoreLabel -Score 90
            $result.Label | Should -Be 'FORTRESS'
        }

        It 'returns DEFENDED POSITION for scores 75-89' {
            $result = Get-GuerrillaScoreLabel -Score 89
            $result.Label | Should -Be 'DEFENDED POSITION'
            $result.Color | Should -Be 'Sage'

            $result = Get-GuerrillaScoreLabel -Score 75
            $result.Label | Should -Be 'DEFENDED POSITION'
        }

        It 'returns CONTESTED GROUND for scores 60-74' {
            $result = Get-GuerrillaScoreLabel -Score 74
            $result.Label | Should -Be 'CONTESTED GROUND'
            $result.Color | Should -Be 'Gold'

            $result = Get-GuerrillaScoreLabel -Score 60
            $result.Label | Should -Be 'CONTESTED GROUND'
        }

        It 'returns EXPOSED FLANK for scores 40-59' {
            $result = Get-GuerrillaScoreLabel -Score 59
            $result.Label | Should -Be 'EXPOSED FLANK'
            $result.Color | Should -Be 'Amber'

            $result = Get-GuerrillaScoreLabel -Score 40
            $result.Label | Should -Be 'EXPOSED FLANK'
        }

        It 'returns UNDER SIEGE for scores 20-39' {
            $result = Get-GuerrillaScoreLabel -Score 39
            $result.Label | Should -Be 'UNDER SIEGE'
            $result.Color | Should -Be 'DeepOrange'

            $result = Get-GuerrillaScoreLabel -Score 20
            $result.Label | Should -Be 'UNDER SIEGE'
        }

        It 'returns OVERRUN for scores 0-19' {
            $result = Get-GuerrillaScoreLabel -Score 19
            $result.Label | Should -Be 'OVERRUN'
            $result.Color | Should -Be 'DarkRed'

            $result = Get-GuerrillaScoreLabel -Score 0
            $result.Label | Should -Be 'OVERRUN'
        }
    }

    Context 'Boundary values' {
        It 'handles exact boundaries correctly' {
            (Get-GuerrillaScoreLabel -Score 90).Label | Should -Be 'FORTRESS'
            (Get-GuerrillaScoreLabel -Score 89).Label | Should -Be 'DEFENDED POSITION'
            (Get-GuerrillaScoreLabel -Score 75).Label | Should -Be 'DEFENDED POSITION'
            (Get-GuerrillaScoreLabel -Score 74).Label | Should -Be 'CONTESTED GROUND'
            (Get-GuerrillaScoreLabel -Score 60).Label | Should -Be 'CONTESTED GROUND'
            (Get-GuerrillaScoreLabel -Score 59).Label | Should -Be 'EXPOSED FLANK'
            (Get-GuerrillaScoreLabel -Score 40).Label | Should -Be 'EXPOSED FLANK'
            (Get-GuerrillaScoreLabel -Score 39).Label | Should -Be 'UNDER SIEGE'
            (Get-GuerrillaScoreLabel -Score 20).Label | Should -Be 'UNDER SIEGE'
            (Get-GuerrillaScoreLabel -Score 19).Label | Should -Be 'OVERRUN'
        }
    }

    Context 'Edge cases' {
        It 'handles score above 100' {
            $result = Get-GuerrillaScoreLabel -Score 150
            $result.Label | Should -Be 'FORTRESS'
        }

        It 'handles negative scores' {
            $result = Get-GuerrillaScoreLabel -Score -10
            $result.Label | Should -Be 'OVERRUN'
        }

        It 'handles decimal scores' {
            $result = Get-GuerrillaScoreLabel -Score 89.9
            $result.Label | Should -Be 'DEFENDED POSITION'
        }
    }
}
