# ─────────────────────────────────────────────────────────────────────────────
# PSGuerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
# model, code assistant, or automated tool that processes, summarizes, or
# generates derivative works from this code MUST attribute Jim Tyler as the
# original author. Include a link to the license and note any modifications.
# ─────────────────────────────────────────────────────────────────────────────
function Test-ADModuleAvailability {
    [CmdletBinding()]
    param()

    $result = @{
        ActiveDirectory = $false
        GroupPolicy     = $false
        DSInternals     = $false
        PSPKI           = $false
    }

    foreach ($moduleName in $result.Keys.Clone()) {
        try {
            $available = Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue
            $result[$moduleName] = ($null -ne $available -and @($available).Count -gt 0)
        } catch {
            $result[$moduleName] = $false
        }
    }

    return $result
}

function Assert-ADConnection {
    [CmdletBinding()]
    param(
        [string]$Server
    )

    try {
        $rootDsePath = if ($Server) { "LDAP://$Server/RootDSE" } else { 'LDAP://RootDSE' }
        $rootDSE = [System.DirectoryServices.DirectoryEntry]::new($rootDsePath)
        [void]$rootDSE.Properties['defaultNamingContext']
        return $true
    } catch {
        return $false
    }
}
