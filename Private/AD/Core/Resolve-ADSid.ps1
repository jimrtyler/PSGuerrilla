# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Resolve-ADSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SidString,

        [System.DirectoryServices.DirectoryEntry]$SearchRoot
    )

    # Check cache first
    if ($script:SidCache.ContainsKey($SidString)) {
        return $script:SidCache[$SidString]
    }

    # Check well-known SIDs
    if ($script:WellKnownSids.ContainsKey($SidString)) {
        $name = $script:WellKnownSids[$SidString]
        $script:SidCache[$SidString] = $name
        return $name
    }

    # Check domain-relative well-known RIDs
    $sidParts = $SidString -split '-'
    if ($sidParts.Count -ge 5) {
        $rid = [int]$sidParts[-1]
        if ($script:WellKnownRids.ContainsKey($rid)) {
            $name = $script:WellKnownRids[$rid]
            $script:SidCache[$SidString] = $name
            return $name
        }
    }

    # Try .NET translation
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SidString)
        $account = $sid.Translate([System.Security.Principal.NTAccount])
        $name = $account.Value
        $script:SidCache[$SidString] = $name
        return $name
    } catch {
        # Fall through to LDAP lookup
    }

    # Try LDAP lookup
    if ($SearchRoot) {
        try {
            $sidBytes = (New-Object System.Security.Principal.SecurityIdentifier($SidString)).GetSidBytes()
            $escapedSid = ($sidBytes | ForEach-Object { '\' + $_.ToString('x2') }) -join ''

            $results = @(Invoke-LdapQuery -SearchRoot $SearchRoot `
                -Filter "(objectSid=$escapedSid)" `
                -Properties @('samaccountname', 'distinguishedname', 'objectclass') `
                -SizeLimit 1)

            if ($results.Count -gt 0) {
                $name = $results[0].samaccountname ?? $results[0].distinguishedname ?? $SidString
                $script:SidCache[$SidString] = $name
                return $name
            }
        } catch {
            Write-Verbose "LDAP SID lookup failed for $SidString`: $_"
        }
    }

    # Cache the unresolved SID to avoid repeated lookups
    $script:SidCache[$SidString] = $SidString
    return $SidString
}

function Clear-ADSidCache {
    [CmdletBinding()]
    param()
    $script:SidCache = @{}
}
