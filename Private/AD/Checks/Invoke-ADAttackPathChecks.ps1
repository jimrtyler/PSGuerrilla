# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADAttackPathChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADAttackPathChecks'
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

# ── ADPATH-001: Escalation Paths to Tier-0 ─────────────────────────────────
function Test-ReconADPATH001 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $analysis = Get-ADAttackPath -AuditData $AuditData

    if (-not $analysis.DataAvailable) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available — run with the ACLDelegation (or All) category enabled to compute attack paths'
    }

    $paths = @($analysis.Paths)
    if ($paths.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No non-default principals have control over Tier-0 objects — no one-hop escalation paths found' `
            -Details @{ PathCount = 0 }
    }

    $nonPriv = @($paths | Where-Object { -not $_.SourceIsPrivileged })
    $preview = @($paths | Select-Object -First 6 | ForEach-Object { $_.Path }) -join ' | '

    $currentValue = "$($paths.Count) escalation path(s) to Tier-0"
    if ($nonPriv.Count -gt 0) {
        $currentValue += " — $($nonPriv.Count) from NON-privileged principals (highest risk)"
    }
    $currentValue += ": $preview"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            PathCount          = $paths.Count
            NonPrivilegedCount = $nonPriv.Count
            AffectedLabel      = 'Escalation paths to Tier-0'
            AffectedItems      = @($paths | ForEach-Object { $_.Path })
            Paths              = @($paths)
        }
}
