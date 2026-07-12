# Unit tests for the collector-throw synthesis helper: a category check function
# that THROWS must yield Not-Assessed (ERROR) findings for every check it would
# have produced, so a broken collector classifies as lost visibility in the next
# run diff instead of a benign "retired" check set.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'Get-GuerrillaFailedCategoryFinding' {

    It 'synthesizes one ERROR finding per check definition of the failed category' {
        InModuleScope Guerrilla {
            $defs = Get-AuditCategoryDefinitions -Category 'ADTrustChecks'
            $findings = @(Get-GuerrillaFailedCategoryFinding -CategoryFunction 'Invoke-ADTrustChecks' -Reason 'LDAP timeout')

            $findings.Count | Should -Be @($defs.checks).Count
            foreach ($f in $findings) {
                $f.Status | Should -Be 'ERROR'
                $f.CurrentValue | Should -Match 'Not Assessed'
                $f.CurrentValue | Should -Match 'LDAP timeout'
                $f.Details.NotAssessed | Should -BeTrue
                $f.Details.FailedCategoryFunction | Should -Be 'Invoke-ADTrustChecks'
            }
            @($findings | ForEach-Object CheckId) | Should -Be @($defs.checks | ForEach-Object { $_.id })
        }
    }

    It 'synthesized findings normalize to Not Assessed in a run record (never PASS, never absent)' {
        InModuleScope Guerrilla {
            $findings = @(Get-GuerrillaFailedCategoryFinding -CategoryFunction 'Invoke-ADTrustChecks' -Reason 'boom')
            $rec = New-GuerrillaRunRecord -Findings $findings -Platforms @('AD') `
                -TargetId @('corp.example.com') -ScanId 's1' -OverallScore $null
            @($rec.checks | ForEach-Object verdict) | Sort-Object -Unique | Should -Be @('Not Assessed')
            $rec.summary.notAssessed | Should -Be $findings.Count
        }
    }

    It 'a thrown category classifies as lost visibility, never retired, in the next diff' {
        InModuleScope Guerrilla {
            $naFindings = @(Get-GuerrillaFailedCategoryFinding -CategoryFunction 'Invoke-AuthenticationChecks' -Reason 'API 500')
            $naFindings.Count | Should -BeGreaterThan 1

            # Previous run: the same checks were assessed.
            $assessed = @(foreach ($f in $naFindings) { New-MockAuditFinding -CheckId $f.CheckId -Status 'PASS' })
            $prev = New-GuerrillaRunRecord -Findings $assessed -Platforms @('GWS') -TargetId @('x.example.com') -ScanId 'p' -OverallScore 90
            $curr = New-GuerrillaRunRecord -Findings $naFindings -Platforms @('GWS') -TargetId @('x.example.com') -ScanId 'c' -OverallScore 90

            $diff = Compare-GuerrillaRun -Previous $prev -Current $curr
            @($diff.LostVisibility).Count | Should -Be $naFindings.Count
            @($diff.RetiredChecks).Count | Should -Be 0
        }
    }

    It 'maps the data-driven EIDSCA dispatcher to its catalog' {
        InModuleScope Guerrilla {
            Get-GuerrillaCategoryDefinitionName -CategoryFunction 'Invoke-EntraEidscaChecks' | Should -Be 'EidscaChecks'
            $findings = @(Get-GuerrillaFailedCategoryFinding -CategoryFunction 'Invoke-EntraEidscaChecks' -Reason 'Graph auth expired')
            $defs = Get-AuditCategoryDefinitions -Category 'EidscaChecks'
            $findings.Count | Should -Be @($defs.checks).Count
        }
    }

    It 'falls back to one loud synthetic ERROR finding when definitions cannot be loaded' {
        InModuleScope Guerrilla {
            $findings = @(Get-GuerrillaFailedCategoryFinding -CategoryFunction 'Invoke-NoSuchChecks' -Reason 'boom')
            $findings.Count | Should -Be 1
            $findings[0].CheckId | Should -Be 'CATFAIL-NOSUCHCHECKS'
            $findings[0].Status | Should -Be 'ERROR'
            $findings[0].CurrentValue | Should -Match 'Not Assessed'
        }
    }

    It 'carries the org unit scope through (GWS audits pass a TargetOU)' {
        InModuleScope Guerrilla {
            $findings = @(Get-GuerrillaFailedCategoryFinding -CategoryFunction 'Invoke-DriveSecurityChecks' -Reason 'boom' -OrgUnitPath '/Engineering')
            @($findings | ForEach-Object OrgUnitPath) | Sort-Object -Unique | Should -Be @('/Engineering')
        }
    }
}

Describe 'Get-GuerrillaPlatformCheckFunction' {

    It 'every listed category function exists and resolves to a shipped definition file' {
        InModuleScope Guerrilla {
            foreach ($platform in 'AD', 'Entra', 'GWS') {
                $fns = @(Get-GuerrillaPlatformCheckFunction -Platform $platform)
                $fns.Count | Should -BeGreaterThan 0
                foreach ($fn in $fns) {
                    Get-Command $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn must exist"
                    { Get-AuditCategoryDefinitions -Category (Get-GuerrillaCategoryDefinitionName -CategoryFunction $fn) } |
                        Should -Not -Throw -Because "$fn must map to a definitions file"
                }
            }
        }
    }

    It 'tracks the orchestrator categoryMap tables (source assertion)' {
        # The platform lists must not drift from the categoryMap tables in the
        # orchestrators: every function named there appears in the platform list.
        InModuleScope Guerrilla {
            $srcRoot = Join-Path $script:ModuleRoot 'public'
            $cases = @(
                @{ File = 'Invoke-ADAudit.ps1'; Platform = 'AD' }
                @{ File = 'Invoke-EntraAudit.ps1'; Platform = 'Entra' }
                @{ File = 'Invoke-GWSAudit.ps1'; Platform = 'GWS' }
            )
            foreach ($case in $cases) {
                $src = Get-Content -Raw (Join-Path $srcRoot $case.File)
                $named = @([regex]::Matches($src, "'(Invoke-[A-Za-z0-9]+Checks)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
                $listed = @(Get-GuerrillaPlatformCheckFunction -Platform $case.Platform)
                foreach ($fn in $named) {
                    $listed | Should -Contain $fn -Because "$($case.File) runs $fn"
                }
            }
        }
    }
}
