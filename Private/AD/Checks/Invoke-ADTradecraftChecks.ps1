# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADTradecraftChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADTradecraftChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Recon$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_"))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented'))
        }
    }

    return @($findings)
}

# ── ADTRADE-001: GPP cpassword Leftovers ───────────────────────────────────
function Test-ReconADTRADE001 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )
    $tc = $AuditData.Tradecraft
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    if (-not $tc.SysvolReadable) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not readable from this host (auth/network issue).'
    }
    $hits = @($tc.CpasswordHits)
    if ($hits.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No GPP cpassword fields found in SYSVOL Policies XML files (MS14-025 cleanup verified)' `
            -Details @{ FilesScanned = 'SYSVOL Policies recursive *.xml' }
    }
    $summary = @($hits | Select-Object -First 5 | ForEach-Object { "$($_.ExposedUser) in $($_.FilePath)" }) -join '; '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "Found $($hits.Count) GPP cpassword leftover(s) in SYSVOL. Examples: $summary. Rotate every exposed credential — the cpassword AES key is public, anyone with SYSVOL read access can decrypt." `
        -Details @{ HitCount = $hits.Count; Hits = $hits }
}

# ── ADTRADE-002: DCShadow Indicator ────────────────────────────────────────
function Test-ReconADTRADE002 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )
    $tc = $AuditData.Tradecraft
    $dcs = $AuditData.DomainControllers
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    $configServers = @($tc.ConfigPartitionServers)
    if ($configServers.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No server objects found under CN=Sites,CN=Configuration. This is unusual for a real domain — verify the collector had read access to the configuration partition.' `
            -Details @{ ConfigServerCount = 0 }
    }

    # Build a set of known DC hostnames (lowercased) from the DomainControllers collection.
    # Get-ADDomainControllers returns a flat array of DC hashtables — keys are Name + FQDN.
    $knownDcHosts = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($dcs) {
        foreach ($d in @($dcs)) {
            if ($d.FQDN) { [void]$knownDcHosts.Add($d.FQDN) }
            if ($d.Name) { [void]$knownDcHosts.Add($d.Name) }
        }
    }
    if ($knownDcHosts.Count -eq 0) {
        # If we have no DC inventory we can't tell orphans from real DCs — SKIP rather
        # than flag every server in the config partition as a rogue.
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DomainControllers data not available to cross-reference. Re-run with DomainForest category enabled to populate the DC inventory.'
    }

    $orphans = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($s in $configServers) {
        $sHost = $s.DNSHostName ?? $s.CN ?? ''
        if (-not $sHost) { continue }
        # The configuration partition may include short-name servers; also try just the CN.
        $isKnown = $knownDcHosts.Contains($sHost) -or $knownDcHosts.Contains($s.CN)
        if (-not $isKnown) {
            $orphans.Add(@{
                Server     = $sHost
                DN         = $s.DistinguishedName
                Created    = $s.WhenCreated
            })
        }
    }

    if ($orphans.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "All $($configServers.Count) server objects in CN=Sites,CN=Configuration match known domain controllers — no DCShadow indicator." `
            -Details @{ ConfigServerCount = $configServers.Count; DcCount = $knownDcHosts.Count }
    }

    $summary = @($orphans | ForEach-Object { "$($_.Server) (created $($_.Created))" }) -join '; '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($orphans.Count) server object(s) under CN=Sites,CN=Configuration that do NOT match a known DC: $summary. Investigate immediately — DCShadow registers fake DCs here, but legitimate causes also exist (replicated objects from a removed DC, legacy site setup)." `
        -Details @{ OrphanCount = $orphans.Count; Orphans = @($orphans) }
}

# ── ADTRADE-003: Stale BitLocker Recovery Keys ─────────────────────────────
function Test-ReconADTRADE003 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )
    $tc = $AuditData.Tradecraft
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    $keys = @($tc.BitLockerKeys)
    if ($keys.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No BitLocker recovery information found in AD. Either BitLocker is not deployed, or the recovery keys are stored elsewhere (Intune, MBAM, etc.).' `
            -Details @{ KeyCount = 0 }
    }

    $thresholdDays = 365
    $cutoff = [datetime]::UtcNow.AddDays(-$thresholdDays)
    $staleKeys = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($k in $keys) {
        $created = $k.WhenCreated
        if ($created -is [datetime] -and $created -lt $cutoff) {
            $staleKeys.Add(@{
                DN            = $k.DistinguishedName
                ParentComputer = $k.ParentComputer
                AgeDays        = [int]([datetime]::UtcNow - $created).TotalDays
            })
        }
    }

    if ($staleKeys.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "$($keys.Count) BitLocker recovery key(s) found, all within $thresholdDays days" `
            -Details @{ KeyCount = $keys.Count }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($staleKeys.Count) BitLocker recovery key(s) older than $thresholdDays days (of $($keys.Count) total). Review their parent computer accounts — confirm the drives have been destroyed or wiped, then prune the AD computer objects to cascade-delete the orphan keys." `
        -Details @{ StaleCount = $staleKeys.Count; TotalCount = $keys.Count; ThresholdDays = $thresholdDays; Sample = @($staleKeys | Select-Object -First 10) }
}

# ── ADTRADE-004: RODC Password Replication Policy Hygiene ──────────────────
function Test-ReconADTRADE004 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )
    $tc = $AuditData.Tradecraft
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    $rodcs = @($tc.Rodcs)
    if ($rodcs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No RODCs in this domain — PRP hygiene N/A.' `
            -Details @{ RodcCount = 0 }
    }
    # The PRP itself isn't a simple LDAP attribute — it's expressed via msDS-RevealOnDemandGroup
    # and msDS-NeverRevealGroup on each RODC computer object, plus the canonical Deny / Allow
    # groups. Surfacing the inventory + the manual verification command is the right call here
    # rather than half-checking with incomplete logic.
    $summary = @($rodcs | ForEach-Object { $_.DNSHostName }) -join ', '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Domain has $($rodcs.Count) RODC(s): $summary. Verify each RODC's Password Replication Policy out-of-band: Get-ADDomainControllerPasswordReplicationPolicy -Identity <rodc> -Denied. Domain Admins, Enterprise Admins, Schema Admins, Account Operators, and krbtgt must be in the Denied list (typically via the 'Denied RODC Password Replication Group' builtin)." `
        -Details @{ RodcCount = $rodcs.Count; Rodcs = @($rodcs) }
}
