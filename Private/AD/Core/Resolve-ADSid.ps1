# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
# ───────────────────────────────────────────────────────────────────────────────
#  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#  https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ═══════════════════════════════════════════════════════════════════════════════
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
# ═══════════════════════════════════════════════════════════════════════════════
$script:SidCache = @{}

$script:WellKnownSids = @{
    'S-1-0-0'       = 'Nobody'
    'S-1-1-0'       = 'Everyone'
    'S-1-2-0'       = 'Local'
    'S-1-2-1'       = 'Console Logon'
    'S-1-3-0'       = 'Creator Owner'
    'S-1-3-1'       = 'Creator Group'
    'S-1-5-1'       = 'Dialup'
    'S-1-5-2'       = 'Network'
    'S-1-5-3'       = 'Batch'
    'S-1-5-4'       = 'Interactive'
    'S-1-5-6'       = 'Service'
    'S-1-5-7'       = 'Anonymous Logon'
    'S-1-5-9'       = 'Enterprise Domain Controllers'
    'S-1-5-10'      = 'Self'
    'S-1-5-11'      = 'Authenticated Users'
    'S-1-5-13'      = 'Terminal Server User'
    'S-1-5-14'      = 'Remote Interactive Logon'
    'S-1-5-15'      = 'This Organization'
    'S-1-5-17'      = 'IUSR'
    'S-1-5-18'      = 'SYSTEM'
    'S-1-5-19'      = 'LOCAL SERVICE'
    'S-1-5-20'      = 'NETWORK SERVICE'
    'S-1-5-32-544'  = 'BUILTIN\Administrators'
    'S-1-5-32-545'  = 'BUILTIN\Users'
    'S-1-5-32-546'  = 'BUILTIN\Guests'
    'S-1-5-32-547'  = 'BUILTIN\Power Users'
    'S-1-5-32-548'  = 'BUILTIN\Account Operators'
    'S-1-5-32-549'  = 'BUILTIN\Server Operators'
    'S-1-5-32-550'  = 'BUILTIN\Print Operators'
    'S-1-5-32-551'  = 'BUILTIN\Backup Operators'
    'S-1-5-32-552'  = 'BUILTIN\Replicators'
    'S-1-5-32-554'  = 'BUILTIN\Pre-Windows 2000 Compatible Access'
    'S-1-5-32-555'  = 'BUILTIN\Remote Desktop Users'
    'S-1-5-32-556'  = 'BUILTIN\Network Configuration Operators'
    'S-1-5-32-557'  = 'BUILTIN\Incoming Forest Trust Builders'
    'S-1-5-32-558'  = 'BUILTIN\Performance Monitor Users'
    'S-1-5-32-559'  = 'BUILTIN\Performance Log Users'
    'S-1-5-32-560'  = 'BUILTIN\Windows Authorization Access Group'
    'S-1-5-32-561'  = 'BUILTIN\Terminal Server License Servers'
    'S-1-5-32-562'  = 'BUILTIN\Distributed COM Users'
    'S-1-5-32-568'  = 'BUILTIN\IIS_IUSRS'
    'S-1-5-32-569'  = 'BUILTIN\Cryptographic Operators'
    'S-1-5-32-573'  = 'BUILTIN\Event Log Readers'
    'S-1-5-32-574'  = 'BUILTIN\Certificate Service DCOM Access'
    'S-1-5-32-575'  = 'BUILTIN\RDS Remote Access Servers'
    'S-1-5-32-576'  = 'BUILTIN\RDS Endpoint Servers'
    'S-1-5-32-577'  = 'BUILTIN\RDS Management Servers'
    'S-1-5-32-578'  = 'BUILTIN\Hyper-V Administrators'
    'S-1-5-32-579'  = 'BUILTIN\Access Control Assistance Operators'
    'S-1-5-32-580'  = 'BUILTIN\Remote Management Users'
    'S-1-5-32-581'  = 'BUILTIN\Default Account'
    'S-1-5-32-582'  = 'BUILTIN\Storage Replica Administrators'
}

# Well-known domain-relative RIDs
$script:WellKnownRids = @{
    500  = 'Administrator'
    501  = 'Guest'
    502  = 'krbtgt'
    512  = 'Domain Admins'
    513  = 'Domain Users'
    514  = 'Domain Guests'
    515  = 'Domain Computers'
    516  = 'Domain Controllers'
    517  = 'Cert Publishers'
    518  = 'Schema Admins'
    519  = 'Enterprise Admins'
    520  = 'Group Policy Creator Owners'
    521  = 'Read-only Domain Controllers'
    522  = 'Cloneable Domain Controllers'
    525  = 'Protected Users'
    526  = 'Key Admins'
    527  = 'Enterprise Key Admins'
    553  = 'RAS and IAS Servers'
    571  = 'Allowed RODC Password Replication Group'
    572  = 'Denied RODC Password Replication Group'
    1101 = 'DnsAdmins'
    1102 = 'DnsUpdateProxy'
}

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

            $results = Invoke-LdapQuery -SearchRoot $SearchRoot `
                -Filter "(objectSid=$escapedSid)" `
                -Properties @('samaccountname', 'distinguishedname', 'objectclass') `
                -SizeLimit 1

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
