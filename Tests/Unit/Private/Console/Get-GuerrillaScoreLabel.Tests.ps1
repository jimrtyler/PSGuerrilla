<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  Guerrilla PowerShell Module
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
    Import-Guerrilla
}

Describe 'Get-GuerrillaScoreLabel' {
    Context 'Score ranges' {
        It 'returns Low Risk for scores 90-100' {
            $result = Get-GuerrillaScoreLabel -Score 100
            $result.Label | Should -Be 'Low Risk'
            $result.Color | Should -Be 'Sage'

            $result = Get-GuerrillaScoreLabel -Score 90
            $result.Label | Should -Be 'Low Risk'
        }

        It 'returns Moderate Risk for scores 75-89' {
            $result = Get-GuerrillaScoreLabel -Score 89
            $result.Label | Should -Be 'Moderate Risk'
            $result.Color | Should -Be 'Sage'

            $result = Get-GuerrillaScoreLabel -Score 75
            $result.Label | Should -Be 'Moderate Risk'
        }

        It 'returns Elevated Risk for scores 60-74' {
            $result = Get-GuerrillaScoreLabel -Score 74
            $result.Label | Should -Be 'Elevated Risk'
            $result.Color | Should -Be 'Gold'

            $result = Get-GuerrillaScoreLabel -Score 60
            $result.Label | Should -Be 'Elevated Risk'
        }

        It 'returns High Risk for scores 40-59' {
            $result = Get-GuerrillaScoreLabel -Score 59
            $result.Label | Should -Be 'High Risk'
            $result.Color | Should -Be 'Amber'

            $result = Get-GuerrillaScoreLabel -Score 40
            $result.Label | Should -Be 'High Risk'
        }

        It 'returns Severe Risk for scores 20-39' {
            $result = Get-GuerrillaScoreLabel -Score 39
            $result.Label | Should -Be 'Severe Risk'
            $result.Color | Should -Be 'DeepOrange'

            $result = Get-GuerrillaScoreLabel -Score 20
            $result.Label | Should -Be 'Severe Risk'
        }

        It 'returns Critical Risk for scores 0-19' {
            $result = Get-GuerrillaScoreLabel -Score 19
            $result.Label | Should -Be 'Critical Risk'
            $result.Color | Should -Be 'DarkRed'

            $result = Get-GuerrillaScoreLabel -Score 0
            $result.Label | Should -Be 'Critical Risk'
        }
    }

    Context 'Boundary values' {
        It 'handles exact boundaries correctly' {
            (Get-GuerrillaScoreLabel -Score 90).Label | Should -Be 'Low Risk'
            (Get-GuerrillaScoreLabel -Score 89).Label | Should -Be 'Moderate Risk'
            (Get-GuerrillaScoreLabel -Score 75).Label | Should -Be 'Moderate Risk'
            (Get-GuerrillaScoreLabel -Score 74).Label | Should -Be 'Elevated Risk'
            (Get-GuerrillaScoreLabel -Score 60).Label | Should -Be 'Elevated Risk'
            (Get-GuerrillaScoreLabel -Score 59).Label | Should -Be 'High Risk'
            (Get-GuerrillaScoreLabel -Score 40).Label | Should -Be 'High Risk'
            (Get-GuerrillaScoreLabel -Score 39).Label | Should -Be 'Severe Risk'
            (Get-GuerrillaScoreLabel -Score 20).Label | Should -Be 'Severe Risk'
            (Get-GuerrillaScoreLabel -Score 19).Label | Should -Be 'Critical Risk'
        }
    }

    Context 'Edge cases' {
        It 'handles score above 100' {
            $result = Get-GuerrillaScoreLabel -Score 150
            $result.Label | Should -Be 'Low Risk'
        }

        It 'handles negative scores' {
            $result = Get-GuerrillaScoreLabel -Score -10
            $result.Label | Should -Be 'Critical Risk'
        }

        It 'handles decimal scores' {
            $result = Get-GuerrillaScoreLabel -Score 89.9
            $result.Label | Should -Be 'Moderate Risk'
        }
    }
}
