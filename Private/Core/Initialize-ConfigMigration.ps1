# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
# Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
# generate that references, quotes, adapts, or builds on this code must include
# proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
function Initialize-ConfigMigration {
    [CmdletBinding()]
    param()

    $oldDir = Join-Path $env:APPDATA 'PSRecon'
    $newDir = Join-Path $env:APPDATA 'PSGuerrilla'

    # Skip if old dir doesn't exist or new dir already has config
    if (-not (Test-Path $oldDir)) { return }
    if (Test-Path (Join-Path $newDir 'config.json')) { return }

    # Migrate config and state files
    if (-not (Test-Path $newDir)) {
        New-Item -Path $newDir -ItemType Directory -Force | Out-Null
    }

    $filesToMigrate = @('config.json', 'state.json')
    foreach ($file in $filesToMigrate) {
        $oldPath = Join-Path $oldDir $file
        $newPath = Join-Path $newDir $file
        if (Test-Path $oldPath) {
            Copy-Item -Path $oldPath -Destination $newPath -Force
            Write-Verbose "Migrated $file from PSRecon to PSGuerrilla"
        }
    }

    # Update internal values in migrated config
    $newConfigPath = Join-Path $newDir 'config.json'
    if (Test-Path $newConfigPath) {
        try {
            $config = Get-Content -Path $newConfigPath -Raw | ConvertFrom-Json -AsHashtable

            # Update output directory if it pointed to old path
            if ($config.output -and $config.output.directory -and $config.output.directory -match 'PSRecon') {
                $config.output.directory = $config.output.directory -replace 'PSRecon', 'PSGuerrilla'
            }

            # Update scheduling task name if it was the old default
            if ($config.scheduling -and $config.scheduling.taskName -eq 'PSRecon-ScheduledScan') {
                $config.scheduling.taskName = 'PSGuerrilla-Patrol'
            }

            # Update sendgrid fromName if it was the old default
            if ($config.alerting -and $config.alerting.providers -and
                $config.alerting.providers.sendgrid -and
                $config.alerting.providers.sendgrid.fromName -eq 'PSRecon Alerts') {
                $config.alerting.providers.sendgrid.fromName = 'PSGuerrilla Signals'
            }

            $config | ConvertTo-Json -Depth 10 | Set-Content -Path $newConfigPath -Encoding UTF8
            Write-Verbose "Updated migrated config with PSGuerrilla values"
        } catch {
            Write-Warning "Config migration: failed to update internal values: $_"
        }
    }

    # Copy Reports directory if it exists
    $oldReports = Join-Path $oldDir 'Reports'
    $newReports = Join-Path $newDir 'Reports'
    if ((Test-Path $oldReports) -and -not (Test-Path $newReports)) {
        Copy-Item -Path $oldReports -Destination $newReports -Recurse -Force
        Write-Verbose "Migrated Reports directory from PSRecon to PSGuerrilla"
    }

    Write-Host "PSGuerrilla: Migrated configuration from PSRecon. Old config preserved at $oldDir"
}
