# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

function Compare-GuerrillaRun {
    <#
    .SYNOPSIS
        Pure diff of two run records: (previous, current) -> drift result.
    .DESCRIPTION
        No I/O, no clock, no state: everything the result contains is derived
        from the two inputs, which is what makes this function fixturable.

        Transition classes over the four verdicts (PASS, WARN, FAIL,
        Not Assessed), keyed by checkId|orgUnitPath:

          newlyFailing       PASS/WARN -> FAIL          regression, lead item
          lostVisibility     assessed  -> Not Assessed  a check went dark; how
                                                        revoked read access or a
                                                        broken collector hides an
                                                        attacker. Never "no change".
          newlyPassing       FAIL/WARN -> PASS          remediation confirmed
          regressed          PASS -> WARN
          improved           FAIL -> WARN
          restoredVisibility Not Assessed -> assessed   (current verdict shown;
                                                        an NA->FAIL restoration is
                                                        visible failure, listed here)
          stillNotAssessed   Not Assessed -> Not Assessed  persistent darkness:
                                                        a check dark in BOTH runs is
                                                        enumerated, never folded into
                                                        "unchanged" — absence of
                                                        evidence must never read as
                                                        stability.
          unchanged          same assessed verdict      count only, never enumerated

        Checks present only in the current run are NEW (module upgrade), never a
        transition. Checks present only in the previous run are RETIRED, never a
        transition. An unrecognized verdict pair THROWS: a silent diff is a
        false PASS, so unclassifiable input must be loud.

        The result carries TotalClassified and InputUnionCount; they are equal
        by construction and asserted here, and the golden fixtures assert the
        same equality from the outside.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$Previous,
        [Parameter(Mandatory)]$Current
    )

    $validVerdicts = @('PASS', 'WARN', 'FAIL', 'Not Assessed')

    # --- First run ever: no baseline, say so plainly, fabricate nothing. ---
    if ($null -eq $Previous) {
        return [PSCustomObject]@{
            PSTypeName        = 'Guerrilla.RunDiff'
            BaselineRun       = $true
            Previous          = $null
            Current           = [PSCustomObject]@{
                RunId         = "$($Current.runId)"
                GeneratedAt   = "$($Current.generatedAt)"
                ModuleVersion = "$($Current.moduleVersion)"
                OverallScore  = $Current.overallScore
            }
            VersionSkew       = $false
            NewlyFailing      = @()
            LostVisibility    = @()
            NewlyPassing      = @()
            Regressed         = @()
            Improved          = @()
            RestoredVisibility = @()
            StillNotAssessed  = @()
            NewChecks         = @()
            RetiredChecks     = @()
            UnchangedCount    = 0
            ScoreDelta        = $null
            PillarDeltas      = @()
            NotAssessedDelta  = $null
            TotalClassified   = 0
            InputUnionCount   = 0
        }
    }

    # --- Index both sides by identity key. ---
    $keyOf = { param($c) "$($c.checkId)|$($c.orgUnitPath)" }
    $prevByKey = @{}
    foreach ($c in @($Previous.checks)) { $prevByKey[(& $keyOf $c)] = $c }
    $currByKey = @{}
    foreach ($c in @($Current.checks)) { $currByKey[(& $keyOf $c)] = $c }

    $entryOf = {
        param($c, $from, $to)
        [PSCustomObject]@{
            CheckId         = "$($c.checkId)"
            OrgUnitPath     = "$($c.orgUnitPath)"
            Severity        = "$($c.severity)"
            Category        = "$($c.category)"
            ZeroTrustPillar = "$($c.zeroTrustPillar)"
            From            = $from
            To              = $to
            EvidenceChanged = $null   # set below where both sides carry a hash
        }
    }

    $newlyFailing = [System.Collections.Generic.List[object]]::new()
    $lostVisibility = [System.Collections.Generic.List[object]]::new()
    $newlyPassing = [System.Collections.Generic.List[object]]::new()
    $regressed = [System.Collections.Generic.List[object]]::new()
    $improved = [System.Collections.Generic.List[object]]::new()
    $restoredVisibility = [System.Collections.Generic.List[object]]::new()
    $stillNotAssessed = [System.Collections.Generic.List[object]]::new()
    $newChecks = [System.Collections.Generic.List[object]]::new()
    $retiredChecks = [System.Collections.Generic.List[object]]::new()
    $unchangedCount = 0

    foreach ($key in $currByKey.Keys) {
        $curr = $currByKey[$key]
        $to = "$($curr.verdict)"
        if ($to -notin $validVerdicts) { throw "Compare-GuerrillaRun: unknown current verdict '$to' for $key." }

        if (-not $prevByKey.ContainsKey($key)) {
            # New in this run (module upgrade or widened collection): a label, not a transition.
            $newChecks.Add((& $entryOf $curr $null $to))
            continue
        }

        $prev = $prevByKey[$key]
        $from = "$($prev.verdict)"
        if ($from -notin $validVerdicts) { throw "Compare-GuerrillaRun: unknown previous verdict '$from' for $key." }

        $entry = & $entryOf $curr $from $to
        if ($prev.evidenceHash -and $curr.evidenceHash) {
            $entry.EvidenceChanged = ("$($prev.evidenceHash)" -ne "$($curr.evidenceHash)")
        }

        # Exhaustive transition matrix. The default arm throws on purpose:
        # every pair must land in exactly one class or the diff is lying.
        switch ("$from>$to") {
            'PASS>PASS'                 { $unchangedCount++ }
            'WARN>WARN'                 { $unchangedCount++ }
            'FAIL>FAIL'                 { $unchangedCount++ }
            'Not Assessed>Not Assessed' { $stillNotAssessed.Add($entry) }   # persistent darkness, never "unchanged"
            'PASS>FAIL'                 { $newlyFailing.Add($entry) }
            'WARN>FAIL'                 { $newlyFailing.Add($entry) }
            'PASS>Not Assessed'         { $lostVisibility.Add($entry) }
            'WARN>Not Assessed'         { $lostVisibility.Add($entry) }
            'FAIL>Not Assessed'         { $lostVisibility.Add($entry) }
            'FAIL>PASS'                 { $newlyPassing.Add($entry) }
            'WARN>PASS'                 { $newlyPassing.Add($entry) }
            'PASS>WARN'                 { $regressed.Add($entry) }
            'FAIL>WARN'                 { $improved.Add($entry) }
            'Not Assessed>PASS'         { $restoredVisibility.Add($entry) }
            'Not Assessed>WARN'         { $restoredVisibility.Add($entry) }
            'Not Assessed>FAIL'         { $restoredVisibility.Add($entry) }
            default { throw "Compare-GuerrillaRun: unclassified transition '$from' -> '$to' for $key. A silent diff is a false PASS." }
        }
    }

    foreach ($key in $prevByKey.Keys) {
        if (-not $currByKey.ContainsKey($key)) {
            $prev = $prevByKey[$key]
            $from = "$($prev.verdict)"
            if ($from -notin $validVerdicts) { throw "Compare-GuerrillaRun: unknown previous verdict '$from' for $key." }
            # Present before, absent now (removed in an upgrade): a label, not a transition.
            $retiredChecks.Add((& $entryOf $prev $from $null))
        }
    }

    # --- Count equality: every check in the input union appears exactly once. ---
    $unionKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($k in $prevByKey.Keys) { [void]$unionKeys.Add($k) }
    foreach ($k in $currByKey.Keys) { [void]$unionKeys.Add($k) }
    $totalClassified = $newlyFailing.Count + $lostVisibility.Count + $newlyPassing.Count +
        $regressed.Count + $improved.Count + $restoredVisibility.Count + $stillNotAssessed.Count +
        $newChecks.Count + $retiredChecks.Count + $unchangedCount
    if ($totalClassified -ne $unionKeys.Count) {
        throw ("Compare-GuerrillaRun: classified $totalClassified of $($unionKeys.Count) checks. " +
            'A transition fell through the matrix; refusing to return a partial diff.')
    }

    # --- Score deltas. Null-safe: a side without a score yields a null delta, not zero. ---
    $scoreDelta = if ($null -ne $Previous.overallScore -and $null -ne $Current.overallScore) {
        [int]$Current.overallScore - [int]$Previous.overallScore
    } else { $null }

    # A record's pillarScores is an IDictionary when freshly built and a
    # PSCustomObject when read back from JSON; normalize both to a hashtable.
    $toMap = {
        param($scores)
        $map = @{}
        if ($null -eq $scores) { return $map }
        if ($scores -is [System.Collections.IDictionary]) {
            foreach ($k in $scores.Keys) { $map["$k"] = $scores[$k] }
        } else {
            foreach ($prop in $scores.PSObject.Properties) { $map["$($prop.Name)"] = $prop.Value }
        }
        return $map
    }
    $prevPillars = & $toMap $Previous.pillarScores
    $currPillars = & $toMap $Current.pillarScores
    $pillarNames = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $prevPillars.Keys) { [void]$pillarNames.Add($p) }
    foreach ($p in $currPillars.Keys) { [void]$pillarNames.Add($p) }
    $pillarDeltas = foreach ($name in $pillarNames) {
        $pv = $prevPillars[$name]
        $cv = $currPillars[$name]
        [PSCustomObject]@{
            Pillar   = $name
            Previous = $pv
            Current  = $cv
            Delta    = if ($null -ne $pv -and $null -ne $cv) { [int]$cv - [int]$pv } else { $null }
        }
    }

    $prevNA = $Previous.summary.notAssessed
    $currNA = $Current.summary.notAssessed
    $notAssessedDelta = if ($null -ne $prevNA -and $null -ne $currNA) { [int]$currNA - [int]$prevNA } else { $null }

    [PSCustomObject]@{
        PSTypeName        = 'Guerrilla.RunDiff'
        BaselineRun       = $false
        Previous          = [PSCustomObject]@{
            RunId         = "$($Previous.runId)"
            GeneratedAt   = "$($Previous.generatedAt)"
            ModuleVersion = "$($Previous.moduleVersion)"
            OverallScore  = $Previous.overallScore
        }
        Current           = [PSCustomObject]@{
            RunId         = "$($Current.runId)"
            GeneratedAt   = "$($Current.generatedAt)"
            ModuleVersion = "$($Current.moduleVersion)"
            OverallScore  = $Current.overallScore
        }
        VersionSkew       = ("$($Previous.moduleVersion)" -ne "$($Current.moduleVersion)")
        NewlyFailing      = @($newlyFailing)
        LostVisibility    = @($lostVisibility)
        NewlyPassing      = @($newlyPassing)
        Regressed         = @($regressed)
        Improved          = @($improved)
        RestoredVisibility = @($restoredVisibility)
        StillNotAssessed  = @($stillNotAssessed)
        NewChecks         = @($newChecks)
        RetiredChecks     = @($retiredChecks)
        UnchangedCount    = $unchangedCount
        ScoreDelta        = $scoreDelta
        PillarDeltas      = @($pillarDeltas)
        NotAssessedDelta  = $notAssessedDelta
        TotalClassified   = $totalClassified
        InputUnionCount   = $unionKeys.Count
    }
}
