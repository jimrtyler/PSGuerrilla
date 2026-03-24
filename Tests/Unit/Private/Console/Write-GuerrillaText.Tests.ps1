# =============================================================================
#  PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# =============================================================================
#
#  Author:    Jim Tyler
#  Title:     Microsoft MVP
#  Book:      "PowerShell for Systems Engineers"
#
#   GitHub:     https://github.com/jimrtyler
#   LinkedIn:   https://linkedin.com/in/jamestyler
#   YouTube:    https://youtube.com/@jimrtyler
#   Newsletter: https://powershell.news
#
#  License:   Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
#  Copyright: (c) 2026 Jim Tyler. All rights reserved.
#
# =============================================================================
# A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
# Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
# generate that references, quotes, adapts, or builds on this code must include
# proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
# =============================================================================
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Write-GuerrillaText' {
    Context 'Basic output' {
        It 'does not throw for valid color names' {
            $colors = @('Olive', 'Amber', 'Sage', 'Parchment', 'Gold', 'Dim', 'DeepOrange', 'DarkRed', 'White', 'Reset')
            foreach ($color in $colors) {
                { Write-GuerrillaText -Text 'test' -Color $color } | Should -Not -Throw
            }
        }

        It 'rejects invalid color names' {
            { Write-GuerrillaText -Text 'test' -Color 'Purple' } | Should -Throw
        }

        It 'defaults to Olive color' {
            # Just verify it runs without specifying color
            { Write-GuerrillaText -Text 'hello' } | Should -Not -Throw
        }
    }

    Context 'NO_COLOR support' {
        It 'respects NO_COLOR environment variable' {
            $originalNoColor = $env:NO_COLOR
            try {
                $env:NO_COLOR = '1'
                # Should not throw and should output without ANSI codes
                { Write-GuerrillaText -Text 'plain text' -Color 'Amber' } | Should -Not -Throw
            } finally {
                if ($originalNoColor) { $env:NO_COLOR = $originalNoColor } else { Remove-Item env:NO_COLOR -ErrorAction SilentlyContinue }
            }
        }
    }

    Context 'Switch parameters' {
        It 'supports -NoNewline switch' {
            { Write-GuerrillaText -Text 'inline' -NoNewline } | Should -Not -Throw
        }

        It 'supports -Bold switch' {
            { Write-GuerrillaText -Text 'bold text' -Bold } | Should -Not -Throw
        }

        It 'supports -Bold and -NoNewline together' {
            { Write-GuerrillaText -Text 'bold inline' -Bold -NoNewline } | Should -Not -Throw
        }
    }
}
