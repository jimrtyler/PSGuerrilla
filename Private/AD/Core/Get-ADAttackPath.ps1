# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# AD attack-path analysis (v1). Turns the flat "dangerous ACE" findings into named
# privilege-escalation PATHS to Tier-0, with the concrete takeover technique each edge
# enables. v1 models the highest-value edge class — non-default control of a Tier-0
# object (Domain root, AdminSDHolder, the DC OU, the GPO/Config/Schema containers) — which
# the existing ACL collector already gathers. Each such edge is a one-hop path to Domain
# Admin equivalence, so v1 reports those paths and their impact.
#
# NOTE: full domain-wide transitive chaining (low-priv user -> GenericWrite group ->
# nested group -> DA) needs a full-domain ACL collector, which PSGuerrilla does not yet
# run (it reads ACLs on the 6 critical objects only). That deeper traversal is a separate
# roadmap item; this engine is structured so additional edge sources can feed straight in.

function Get-ADAttackPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    # Returns { DataAvailable; Paths }. DataAvailable distinguishes "ACL data not collected"
    # (caller SKIPs) from "collected, zero paths" (caller PASSes) — an explicit flag avoids
    # the PowerShell `$null -eq @()` ambiguity that an empty-array return would introduce.
    $notCollected = [PSCustomObject]@{ DataAvailable = $false; Paths = @() }

    $acl = $AuditData.ACLs
    if (-not $acl) { return $notCollected }
    if ($acl -is [System.Collections.IDictionary] -and -not $acl.Contains('DangerousACEs')) { return $notCollected }

    # Per Tier-0 object: what controlling it actually gets the attacker.
    $impactByObject = @{
        'Domain Root'            = @{ Target = 'the domain (every credential, incl. krbtgt)'; Severity = 'Critical'
            Impact = 'grant themselves DCSync replication rights and extract every domain hash — Domain Admin equivalent' }
        'AdminSDHolder'          = @{ Target = 'all protected groups (Domain/Enterprise/Schema Admins, etc.)'; Severity = 'Critical'
            Impact = 'write an attacker ACE that SDProp propagates to every protected (adminCount=1) object within ~60 min — persistent Tier-0 control' }
        'Domain Controllers OU'  = @{ Target = 'every Domain Controller'; Severity = 'Critical'
            Impact = 'link a malicious GPO to the DC OU and execute code as SYSTEM on every DC — Domain Admin' }
        'GPO Container'          = @{ Target = 'any host where a controlled GPO is linked'; Severity = 'High'
            Impact = 'create or modify Group Policy Objects and execute code wherever they are linked' }
        'Configuration Container' = @{ Target = 'the forest configuration partition'; Severity = 'Critical'
            Impact = 'modify forest-wide configuration (sites, services, AD CS) — forest compromise' }
        'Schema Container'       = @{ Target = 'the AD schema'; Severity = 'Critical'
            Impact = 'modify the schema (defaultSecurityDescriptor) for forest-wide, persistent control' }
    }

    # Build a fast lookup of which principals are already inside a privileged group, so a
    # path from a NON-privileged principal (the genuinely dangerous case) can be flagged.
    $privSids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $privNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($AuditData.PrivilegedAccounts -and $AuditData.PrivilegedAccounts.PrivilegedGroups) {
        foreach ($grp in $AuditData.PrivilegedAccounts.PrivilegedGroups.Values) {
            foreach ($m in @($grp)) {
                if ($m.SID) { [void]$privSids.Add([string]$m.SID) }
                if ($m.SamAccountName) { [void]$privNames.Add([string]$m.SamAccountName) }
            }
        }
    }

    $paths = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($ace in @($acl.DangerousACEs)) {
        $objName = [string]$ace.ObjectName
        $map = $impactByObject[$objName]
        if (-not $map) { continue }   # an ACE on something we don't model an impact for

        $principal = [string]($ace.IdentityReference ?? $ace.IdentitySID ?? 'Unknown')
        $sid = [string]($ace.IdentitySID ?? '')

        # Prefer the friendly extended-right name (e.g. DS-Replication-Get-Changes) over
        # the raw rights flags when this is a specific extended right.
        $right = if ($ace.ObjectType -and "$($ace.ActiveDirectoryRights)" -match 'ExtendedRight|WriteProperty') {
            [string]$ace.ObjectType
        } else {
            [string]$ace.ActiveDirectoryRights
        }

        # Dedup on principal + object + right.
        $key = "$principal|$objName|$right"
        if (-not $seen.Add($key)) { continue }

        $alreadyPrivileged = ($sid -and $privSids.Contains($sid)) -or $privNames.Contains(($principal -split '\\')[-1])

        $paths.Add([PSCustomObject]@{
            PSTypeName         = 'PSGuerrilla.AttackPath'
            Source             = $principal
            SourceSID          = $sid
            SourceIsPrivileged = [bool]$alreadyPrivileged
            Edge               = $right
            Inherited          = [bool]$ace.IsInherited
            TargetObject       = $objName
            ReachesTier0       = $map.Target
            Technique          = $map.Impact
            Severity           = $map.Severity
            # One-line, human-readable path.
            Path               = "$principal --[$right]--> $objName  =>  can $($map.Impact)"
        })
    }

    # Highest-impact, genuinely-non-privileged paths first.
    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $sorted = @($paths | Sort-Object `
        @{ Expression = { if ($_.SourceIsPrivileged) { 1 } else { 0 } } }, `
        @{ Expression = { $sevRank[$_.Severity] ?? 4 } }, `
        Source)
    return [PSCustomObject]@{ DataAvailable = $true; Paths = $sorted }
}
