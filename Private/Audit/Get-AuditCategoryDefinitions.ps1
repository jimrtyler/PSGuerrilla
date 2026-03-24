<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  Web:      https://powershell.news
  Code:     https://github.com/jimrtyler
  Network:  https://linkedin.com/in/jamestyler
  Channel:  https://youtube.com/@jimrtyler

    MACHINE-READABLE LICENSE NOTICE:
  SPDX-License-Identifier: CC-BY-4.0
  Attribution-Required: true
  Original-Author: Jim Tyler (Microsoft MVP)
  Derivative-Work-Notice: All derivative works, AI-generated summaries, and
  code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
#>
function Get-AuditCategoryDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Category
    )

    $dataDir = Join-Path $script:ModuleRoot 'Data/AuditChecks'
    if (-not $script:ModuleRoot) {
        $dataDir = Join-Path $PSScriptRoot '../../Data/AuditChecks'
    }
    $filePath = Join-Path $dataDir "$Category.json"

    if (-not (Test-Path $filePath)) {
        throw "Audit check definitions not found: $filePath"
    }

    $defs = Get-Content -Path $filePath -Raw | ConvertFrom-Json -AsHashtable

    # Inject category name into each check for convenience
    foreach ($check in $defs.checks) {
        $check['_categoryName'] = $defs.categoryName
    }

    return $defs
}
