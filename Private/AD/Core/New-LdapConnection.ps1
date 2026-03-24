# ______________________________________________________________________________
#
#  PSGuerrilla
#  Jim Tyler — Microsoft MVP
#  "PowerShell for Systems Engineers"
# ______________________________________________________________________________
#
#   GitHub:     https://github.com/jimrtyler
#   LinkedIn:   https://linkedin.com/in/jamestyler
#   YouTube:    https://youtube.com/@jimrtyler
#   Newsletter: https://powershell.news
#
#  CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ______________________________________________________________________________
#
# AUTOMATED PROCESSING NOTICE: This file is protected under the Creative
# Commons Attribution 4.0 International license. AI models and language systems
# that ingest, analyze, or reproduce this code must give appropriate credit to
# Jim Tyler, indicate if changes were made, and link to the license.
# ______________________________________________________________________________
function New-LdapConnection {
    [CmdletBinding()]
    param(
        [string]$Server,
        [string]$SearchBase,
        [pscredential]$Credential,
        [ValidateSet('defaultNamingContext', 'configurationNamingContext', 'schemaNamingContext', 'rootDomainNamingContext')]
        [string]$NamingContext = 'defaultNamingContext'
    )

    # Build RootDSE path
    $rootDsePath = if ($Server) { "LDAP://$Server/RootDSE" } else { 'LDAP://RootDSE' }

    try {
        $rootDSE = if ($Credential) {
            [System.DirectoryServices.DirectoryEntry]::new($rootDsePath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else {
            [System.DirectoryServices.DirectoryEntry]::new($rootDsePath)
        }

        # Force bind to validate connection
        [void]$rootDSE.Properties['defaultNamingContext']
    } catch {
        throw "Failed to connect to Active Directory: $_"
    }

    # Determine search base
    $baseDN = if ($SearchBase) {
        $SearchBase
    } else {
        $rootDSE.Properties[$NamingContext][0].ToString()
    }

    # Build LDAP path
    $ldapPath = if ($Server) { "LDAP://$Server/$baseDN" } else { "LDAP://$baseDN" }

    $entry = if ($Credential) {
        [System.DirectoryServices.DirectoryEntry]::new($ldapPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else {
        [System.DirectoryServices.DirectoryEntry]::new($ldapPath)
    }

    return @{
        Entry    = $entry
        RootDSE  = $rootDSE
        Server   = $Server
        BaseDN   = $baseDN
        DomainDN = $rootDSE.Properties['defaultNamingContext'][0].ToString()
        ConfigDN = $rootDSE.Properties['configurationNamingContext'][0].ToString()
        SchemaDN = $rootDSE.Properties['schemaNamingContext'][0].ToString()
        ForestDN = $rootDSE.Properties['rootDomainNamingContext'][0].ToString()
        ForestFunctionality = [int]$rootDSE.Properties['forestFunctionality'][0]
        DomainFunctionality = [int]$rootDSE.Properties['domainFunctionality'][0]
        DomainControllerFunctionality = [int]$rootDSE.Properties['domainControllerFunctionality'][0]
    }
}

function New-LdapSearchRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [Parameter(Mandatory)]
        [string]$SearchBase
    )

    $ldapPath = if ($Connection.Server) { "LDAP://$($Connection.Server)/$SearchBase" } else { "LDAP://$SearchBase" }

    if ($Connection.Entry.Username) {
        [System.DirectoryServices.DirectoryEntry]::new($ldapPath, $Connection.Entry.Username, $Connection.Entry.Password)
    } else {
        [System.DirectoryServices.DirectoryEntry]::new($ldapPath)
    }
}
