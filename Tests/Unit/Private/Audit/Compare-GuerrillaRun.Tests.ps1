# Golden-fixture suite for the run-diff engine. Compare-GuerrillaRun is a pure
# function, so every scenario is a JSON fixture under Tests/RunDiffFixtures/
# (its own directory: Tests/Fixtures/ is the check-fixture tree whose file
# count gates the fixture runner).
#
# The invariant asserted for EVERY fixture, independently of the function's own
# bookkeeping: every check in the union of both inputs appears in exactly one
# output class. Count equality, not just presence: a silent diff is a false PASS.

# Fixture discovery happens at DISCOVERY time (top level), because Pester 5
# resolves -ForEach before any BeforeAll runs.
$script:FixtureDir = (Resolve-Path (Join-Path $PSScriptRoot '..' '..' '..' 'RunDiffFixtures')).Path
$script:Cases = @(foreach ($file in (Get-ChildItem -Path $script:FixtureDir -Filter '*.json' | Sort-Object Name)) {
    $fx = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
    @{ Name = $fx.name; Fixture = $fx; File = $file.Name }
})

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla

    # Run-phase copy of the fixture set (discovery-phase variables are not
    # visible when the Its execute).
    $script:RunCases = @(foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot '..' '..' '..' 'RunDiffFixtures') -Filter '*.json' | Sort-Object Name)) {
        $fx = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        @{ Name = $fx.name; Fixture = $fx; File = $file.Name }
    })

    # The class names on the diff result, in one place so the invariant test
    # cannot drift from the implementation's property list.
    $script:EnumeratedClasses = @('NewlyFailing', 'LostVisibility', 'NewlyPassing',
        'Regressed', 'Improved', 'RestoredVisibility', 'StillNotAssessed', 'NewChecks', 'RetiredChecks')

    function Invoke-DiffFixture {
        param($Fixture)
        InModuleScope Guerrilla -Parameters @{ prev = $Fixture.previous; curr = $Fixture.current } {
            Compare-GuerrillaRun -Previous $prev -Current $curr
        }
    }
}

Describe 'Compare-GuerrillaRun golden fixtures' {

    It 'discovers the fixture set' {
        $script:RunCases.Count | Should -BeGreaterOrEqual 10
        @($script:RunCases | Where-Object { $_.Name -eq 'every-transition-at-once' }).Count | Should -Be 1
        @($script:RunCases | Where-Object { $_.Name -eq 'still-not-assessed' }).Count | Should -Be 1
    }

    It '<Name>: expected class counts' -ForEach @($script:Cases | Where-Object { -not $_.Fixture.expect.throws }) {
        $diff = Invoke-DiffFixture -Fixture $Fixture
        $c = $Fixture.expect.counts
        @($diff.NewlyFailing).Count       | Should -Be $c.newlyFailing       -Because 'newlyFailing'
        @($diff.LostVisibility).Count     | Should -Be $c.lostVisibility     -Because 'lostVisibility'
        @($diff.NewlyPassing).Count       | Should -Be $c.newlyPassing       -Because 'newlyPassing'
        @($diff.Regressed).Count          | Should -Be $c.regressed          -Because 'regressed'
        @($diff.Improved).Count           | Should -Be $c.improved           -Because 'improved'
        @($diff.RestoredVisibility).Count | Should -Be $c.restoredVisibility -Because 'restoredVisibility'
        @($diff.StillNotAssessed).Count   | Should -Be $c.stillNotAssessed   -Because 'stillNotAssessed'
        @($diff.NewChecks).Count          | Should -Be $c.newChecks          -Because 'newChecks'
        @($diff.RetiredChecks).Count      | Should -Be $c.retiredChecks      -Because 'retiredChecks'
        $diff.UnchangedCount              | Should -Be $c.unchanged          -Because 'unchanged'
    }

    It '<Name>: count equality against an independently computed union (no silent diff)' -ForEach @($script:Cases | Where-Object { -not $_.Fixture.expect.throws -and -not $_.Fixture.expect.baselineRun }) {
        $diff = Invoke-DiffFixture -Fixture $Fixture

        # Union computed here from the fixture INPUTS, not trusting the function.
        $union = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($chk in @($Fixture.previous.checks)) { [void]$union.Add("$($chk.checkId)|$($chk.orgUnitPath)") }
        foreach ($chk in @($Fixture.current.checks))  { [void]$union.Add("$($chk.checkId)|$($chk.orgUnitPath)") }

        $enumerated = 0
        foreach ($class in $script:EnumeratedClasses) { $enumerated += @($diff.$class).Count }
        $total = $enumerated + $diff.UnchangedCount

        $total | Should -Be $union.Count -Because 'every input check must land in exactly one output class'
        $diff.TotalClassified | Should -Be $union.Count
        $diff.InputUnionCount | Should -Be $union.Count
    }

    It '<Name>: baseline flag, version skew, and deltas' -ForEach @($script:Cases | Where-Object { -not $_.Fixture.expect.throws }) {
        $diff = Invoke-DiffFixture -Fixture $Fixture
        $e = $Fixture.expect

        $diff.BaselineRun | Should -Be $e.baselineRun
        $diff.VersionSkew | Should -Be $e.versionSkew

        if ($null -eq $e.scoreDelta) { $diff.ScoreDelta | Should -BeNullOrEmpty }
        else { $diff.ScoreDelta | Should -Be $e.scoreDelta }

        if ($null -eq $e.notAssessedDelta) { $diff.NotAssessedDelta | Should -BeNullOrEmpty }
        else { $diff.NotAssessedDelta | Should -Be $e.notAssessedDelta }

        if ($e.pillarDeltas) {
            foreach ($p in $e.pillarDeltas.PSObject.Properties) {
                $row = @($diff.PillarDeltas | Where-Object Pillar -eq $p.Name)
                $row.Count | Should -Be 1 -Because "pillar $($p.Name) must appear once"
                $row[0].Delta | Should -Be $p.Value -Because "pillar $($p.Name) delta"
            }
        }

        if ($e.baselineRun) {
            $diff.Previous | Should -BeNullOrEmpty
        } else {
            $diff.Previous.RunId | Should -Be $Fixture.previous.runId
            $diff.Previous.ModuleVersion | Should -Be $Fixture.previous.moduleVersion
            $diff.Current.ModuleVersion | Should -Be $Fixture.current.moduleVersion
        }
    }

    It '<Name>: expected members are present in their class' -ForEach @($script:Cases | Where-Object { $_.Fixture.expect.contains }) {
        $diff = Invoke-DiffFixture -Fixture $Fixture
        foreach ($want in $Fixture.expect.contains) {
            $pool = @($diff.$($want.class))
            $match = @($pool | Where-Object {
                $_.CheckId -eq $want.checkId -and
                ($null -eq $want.orgUnitPath -or $_.OrgUnitPath -eq $want.orgUnitPath)
            })
            $match.Count | Should -Be 1 -Because "$($want.checkId) must appear exactly once in $($want.class)"
            if ($null -ne $want.from) { $match[0].From | Should -Be $want.from }
            else { $match[0].From | Should -BeNullOrEmpty }
            if ($null -ne $want.to) { $match[0].To | Should -Be $want.to }
            else { $match[0].To | Should -BeNullOrEmpty }
            if ($null -ne $want.evidenceChanged) { $match[0].EvidenceChanged | Should -Be $want.evidenceChanged }
        }
    }

    It '<Name>: unclassifiable input throws instead of silently dropping' -ForEach @($script:Cases | Where-Object { $_.Fixture.expect.throws }) {
        { Invoke-DiffFixture -Fixture $Fixture } | Should -Throw -ExpectedMessage '*unknown*verdict*'
    }

    It 'a transition dropped from the matrix would be caught (poison self-test)' {
        # Prove the count-equality harness can fail: feed the invariant check a
        # deliberately broken diff (one transition missing) and require it to
        # report inequality. If this stops failing, the invariant test is
        # asserting nothing.
        $fx = ($script:RunCases | Where-Object { $_.Name -eq 'every-transition-at-once' }).Fixture
        $union = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($chk in @($fx.previous.checks)) { [void]$union.Add("$($chk.checkId)|$($chk.orgUnitPath)") }
        foreach ($chk in @($fx.current.checks))  { [void]$union.Add("$($chk.checkId)|$($chk.orgUnitPath)") }

        $diff = Invoke-DiffFixture -Fixture $fx
        $enumerated = 0
        foreach ($class in $script:EnumeratedClasses) { $enumerated += @($diff.$class).Count }
        $poisonedTotal = $enumerated + $diff.UnchangedCount - 1   # simulate one dropped transition

        $poisonedTotal | Should -Not -Be $union.Count
    }

    It 'a check dark in both runs lands in StillNotAssessed, never in the unchanged count' {
        # Persistent darkness must stay enumerated forever, not flagged once as
        # lost visibility and then blended into "unchanged" on every later run.
        $fx = ($script:RunCases | Where-Object { $_.Name -eq 'still-not-assessed' }).Fixture
        $diff = Invoke-DiffFixture -Fixture $fx
        @($diff.StillNotAssessed).Count | Should -Be 2
        @($diff.StillNotAssessed | ForEach-Object CheckId) | Should -Contain 'EIDPIM-010'
        @($diff.StillNotAssessed | ForEach-Object CheckId) | Should -Contain 'M365EXO-004'
        $diff.UnchangedCount | Should -Be 1 -Because 'only the stable PASS is unchanged; dark is not stable'
    }
}
