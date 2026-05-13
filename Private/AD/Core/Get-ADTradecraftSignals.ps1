# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADTradecraftSignals {
    <#
    .SYNOPSIS
        Collects signals for advanced-adversary tradecraft detection.
    .DESCRIPTION
        Gathers:
          * GPP cpassword matches across SYSVOL Policies\**\*.xml
          * Server objects under CN=Sites,CN=Configuration (DCShadow surface)
          * msFVE-RecoveryInformation objects + parent computer staleness
          * RODC inventory (so the PRP check can short-circuit if none)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    $result = @{
        CpasswordHits        = @()
        ConfigPartitionServers = @()
        BitLockerKeys        = @()
        Rodcs                = @()
        SysvolReadable       = $false
        Errors               = @{}
    }

    $domainDns = ($Connection.DomainDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()

    # ── 1. GPP cpassword scan ────────────────────────────────────────────
    $policiesRoot = "\\$domainDns\SYSVOL\$domainDns\Policies"
    try {
        if (Test-Path -LiteralPath $policiesRoot -ErrorAction Stop) {
            $result.SysvolReadable = $true
            $xmlFiles = @(Get-ChildItem -LiteralPath $policiesRoot -Recurse -Filter '*.xml' -ErrorAction SilentlyContinue)
            foreach ($f in $xmlFiles) {
                try {
                    $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                    if ($content -match 'cpassword="([^"]+)"') {
                        # Capture surrounding userName/runAs if present for human-readable output
                        $userMatch = if ($content -match 'userName="([^"]+)"') { $Matches[1] }
                                     elseif ($content -match 'runAs="([^"]+)"') { $Matches[1] }
                                     else { '(unknown)' }
                        $result.CpasswordHits += [PSCustomObject]@{
                            FilePath = $f.FullName
                            ExposedUser = $userMatch
                            CpasswordLength = $Matches[1].Length
                        }
                    }
                } catch {
                    # Don't fail the whole scan on a single unreadable XML
                }
            }
        }
    } catch {
        $result.Errors['CpasswordScan'] = $_.Exception.Message
    }

    # ── 2. Configuration-partition server objects ───────────────────────
    try {
        $configDN = $Connection.ConfigDN
        if ($configDN) {
            $sitesDN = "CN=Sites,$configDN"
            $sitesRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $sitesDN
            $servers = @(Invoke-LdapQuery -SearchRoot $sitesRoot `
                -Filter '(objectClass=server)' `
                -Properties @('cn', 'dNSHostName', 'distinguishedName', 'whenCreated', 'serverReference'))
            foreach ($s in $servers) {
                $result.ConfigPartitionServers += [PSCustomObject]@{
                    CN                = $s['cn'] ?? ''
                    DNSHostName       = $s['dnshostname'] ?? ''
                    DistinguishedName = $s['distinguishedname'] ?? ''
                    WhenCreated       = $s['whencreated']
                    ServerReference   = $s['serverreference'] ?? ''
                }
            }
        }
    } catch {
        $result.Errors['ConfigPartitionServers'] = $_.Exception.Message
    }

    # ── 3. BitLocker recovery information ───────────────────────────────
    try {
        $blRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        $blKeys = @(Invoke-LdapQuery -SearchRoot $blRoot `
            -Filter '(objectClass=msFVE-RecoveryInformation)' `
            -Properties @('distinguishedName', 'whenCreated'))
        foreach ($k in $blKeys) {
            # Parent computer DN = drop the leftmost CN= component
            $dn = $k['distinguishedname']
            $parentDN = if ($dn -match '^[^,]+,(.+)$') { $Matches[1] } else { $null }
            $result.BitLockerKeys += [PSCustomObject]@{
                DistinguishedName = $dn
                ParentComputer    = $parentDN
                WhenCreated       = $k['whencreated']
            }
        }
    } catch {
        $result.Errors['BitLockerKeys'] = $_.Exception.Message
    }

    # ── 4. RODC inventory ───────────────────────────────────────────────
    try {
        $rodcRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        # RODCs have userAccountControl bit 0x4000000 (PARTIAL_SECRETS_ACCOUNT, 67108864) set on their computer object.
        $rodcs = @(Invoke-LdapQuery -SearchRoot $rodcRoot `
            -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864))' `
            -Properties @('cn', 'dNSHostName', 'distinguishedName'))
        foreach ($r in $rodcs) {
            $result.Rodcs += [PSCustomObject]@{
                CN                = $r['cn'] ?? ''
                DNSHostName       = $r['dnshostname'] ?? ''
                DistinguishedName = $r['distinguishedname'] ?? ''
            }
        }
    } catch {
        $result.Errors['Rodcs'] = $_.Exception.Message
    }

    return $result
}
