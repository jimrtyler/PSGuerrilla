<#
*******************************************************************************
*  Guerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  Contact:    GitHub     → https://github.com/jimrtyler
  LinkedIn   → https://linkedin.com/in/jamestyler
  YouTube    → https://youtube.com/@jimrtyler
  Newsletter → https://powershell.news

  TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
  attribute the original author in any derivative output. No exceptions.
  License details: https://creativecommons.org/licenses/by/4.0/

*******************************************************************************
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'Export-TechnicalReport' {
    Context 'Risk acceptance free-text is HTML-encoded' {
        BeforeEach {
            Mock -ModuleName Guerrilla Get-RiskAcceptance {
                [PSCustomObject]@{
                    CheckId       = 'AUTH-001'
                    Justification = "<script>alert('xss')</script>"
                    AcceptedBy    = '<img src=x onerror=alert(1)>'
                    Status        = 'ACCEPTED'
                }
            }
        }

        It 'encodes AcceptedBy and Justification instead of emitting raw tags' {
            $finding = New-MockAuditFinding -CheckId 'AUTH-001' -Status 'FAIL'
            $outPath = Join-Path $TestDrive 'tech-report.html'

            $result = Export-TechnicalReport -Findings @($finding) -OutputPath $outPath
            $result.Success | Should -BeTrue

            $html = Get-Content $outPath -Raw
            $html | Should -Match 'Risk Acceptance'
            $html | Should -Not -Match ([regex]::Escape("<script>alert('xss')</script>"))
            $html | Should -Not -Match ([regex]::Escape('<img src=x onerror=alert(1)>'))
            $html | Should -Match ([regex]::Escape('&lt;script&gt;'))
            $html | Should -Match ([regex]::Escape('&lt;img src=x onerror=alert(1)&gt;'))
        }
    }
}
