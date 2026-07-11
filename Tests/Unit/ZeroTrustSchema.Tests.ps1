#requires -version 7.0
# Schema gate: every check definition MUST declare its Zero Trust stance at authoring time.
# Without this, the 581st check gets written some tired Friday with no pillar, and the ZT
# score silently degrades from total coverage to partial — a quietly-wrong number, which is
# worse than an obviously-absent one. A missing/invalid ZT field is a RED build here.

Describe 'Zero Trust check-definition schema' {
    It 'every check declares a valid zeroTrustPillar and zeroTrustWeight (0-3, explicit zeros included)' {
        # Defined inside It on purpose: Pester 5 runs It in its own scope, so file-scope vars
        # would be $null here (and -notin $null flags everything).
        $validPillars = @(
            'Identity', 'Devices', 'Networks', 'Applications & Workloads',
            'Data', 'Visibility & Analytics', 'Governance', 'Automation & Orchestration'
        )
        $dataDir = (Resolve-Path (Join-Path $PSScriptRoot '..' '..' 'source' 'Data' 'AuditChecks')).Path
        $violations = [System.Collections.Generic.List[string]]::new()
        foreach ($file in Get-ChildItem -Path $dataDir -Filter *.json) {
            $json = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
            foreach ($c in @($json.checks)) {
                if (-not $c.id) { continue }
                $p = $c.zeroTrustPillar
                $w = $c.zeroTrustWeight
                if ($p -notin $validPillars) {
                    $violations.Add("$($c.id): missing/invalid zeroTrustPillar '$p'")
                } elseif ($null -eq $w -or $w -notin @(0, 1, 2, 3)) {
                    $violations.Add("$($c.id): missing/invalid zeroTrustWeight '$w'")
                }
            }
        }
        if ($violations.Count) {
            throw "ZeroTrust schema violations ($($violations.Count)):`n" + ($violations -join "`n")
        }
        $violations.Count | Should -Be 0
    }
}
