# ─────────────────────────────────────────────────────────────────────────────
# PSGuerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
# is licensed under CC BY 4.0. If you use this code in any generated output,
# training data summary, or derivative work, you must credit Jim Tyler as the
# author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.
# ─────────────────────────────────────────────────────────────────────────────
function Register-Patrol {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$TaskName = 'PSGuerrilla-Patrol',
        [int]$IntervalMinutes = 60,
        [datetime]$AtTime,
        [string]$RunAs = 'SYSTEM',
        [string]$ConfigPath,
        [string]$ConfigFile,
        [ValidateSet('Fast', 'Full')]
        [string]$ScanMode = 'Fast',
        [ValidateSet('Workspace', 'Entra', 'AD', 'M365')]
        [string[]]$Theaters = @('Workspace'),
        [switch]$SendAlerts,
        [string]$Description = 'PSGuerrilla automated reconnaissance patrol',
        [switch]$Force
    )

    # --- Resolve mission config (guerrilla-config.json) ---
    if ($ConfigFile) {
        $missionCfg = Read-MissionConfig -Path $ConfigFile

        # Check mission mode — if monitoring is disabled, skip patrol registration
        if ($missionCfg.MissionMode -and $missionCfg.MissionMode.monitoring -eq $false) {
            Write-Warning "Mission mode has monitoring disabled. Register-Patrol requires monitoring mode. Update your guerrilla-config.json to enable monitoring."
            return
        }

        # Determine theaters from enabled environments
        if (-not $PSBoundParameters.ContainsKey('Theaters')) {
            $Theaters = @()
            if ($missionCfg.EnabledEnvironments.ContainsKey('googleWorkspace')) { $Theaters += 'Workspace' }
            if ($missionCfg.EnabledEnvironments.ContainsKey('entraAzure')) { $Theaters += 'Entra' }
            if ($missionCfg.EnabledEnvironments.ContainsKey('activeDirectory')) { $Theaters += 'AD' }
            if ($missionCfg.EnabledEnvironments.ContainsKey('m365')) { $Theaters += 'M365' }
        }

        # Apply monitoring interval from mission config
        if (-not $PSBoundParameters.ContainsKey('IntervalMinutes')) {
            # Use the first enabled environment's monitoring interval
            foreach ($envKey in $missionCfg.EnabledEnvironments.Keys) {
                $envCfg = $missionCfg.EnabledEnvironments[$envKey]
                if ($envCfg.monitoring -and $envCfg.monitoring.intervalMinutes) {
                    $IntervalMinutes = $envCfg.monitoring.intervalMinutes
                    break
                }
            }
        }
    }

    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $cfgFileArg = if ($ConfigFile) { " -ConfigFile '$(Resolve-Path $ConfigFile)'" } else { '' }

    # Build the PowerShell command for all enabled theaters
    $commands = @()

    $signalArgs = "-ConfigPath '$cfgPath'$cfgFileArg -Force"

    if ('Workspace' -in $Theaters) {
        $commands += "`$r = Invoke-Recon -ConfigPath '$cfgPath'$cfgFileArg -ScanMode '$ScanMode' -Quiet"
        if ($SendAlerts) {
            $commands += "if (`$r.NewThreats.Count -gt 0) { `$r | Send-Signal $signalArgs }"
        }
    }

    if ('Entra' -in $Theaters) {
        $commands += "`$s = Invoke-Surveillance -ConfigPath '$cfgPath'$cfgFileArg -ScanMode '$ScanMode' -Quiet"
        if ($SendAlerts) {
            $commands += "if (`$s.NewThreats.Count -gt 0) { `$s | Send-Signal $signalArgs }"
        }
    }

    if ('AD' -in $Theaters) {
        $commands += "`$w = Invoke-Watchtower -ConfigPath '$cfgPath'$cfgFileArg -ScanMode '$ScanMode' -Quiet"
        if ($SendAlerts) {
            $commands += "if (`$w.NewThreats.Count -gt 0) { `$w | Send-Signal $signalArgs }"
        }
    }

    if ('M365' -in $Theaters) {
        $commands += "`$t = Invoke-Wiretap -ConfigPath '$cfgPath'$cfgFileArg -ScanMode '$ScanMode' -Quiet"
        if ($SendAlerts) {
            $commands += "if (`$t.NewThreats.Count -gt 0) { `$t | Send-Signal $signalArgs }"
        }
    }

    # Find pwsh.exe
    $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if (-not $pwshPath) {
        throw 'pwsh.exe not found. PowerShell 7+ is required.'
    }

    # Write the patrol script to a file so the scheduled task is a clean -File invocation
    # (avoids quoting/escaping nightmares with -Command and nested braces)
    $scriptDir = $cfgPath | Split-Path -Parent
    $scriptPath = Join-Path $scriptDir 'patrol-runner.ps1'
    $logPath = Join-Path $scriptDir 'scheduled-scan.log'

    $scriptLines = @(
        "# PSGuerrilla Patrol Runner — Auto-generated by Register-Patrol"
        "# Generated: $(Get-Date -Format 'o')"
        "# Task: $TaskName"
        ''
        'try {'
        '    Import-Module PSGuerrilla -ErrorAction Stop'
    )
    foreach ($cmd in $commands) {
        $scriptLines += "    $cmd"
    }
    $scriptLines += @(
        '} catch {'
        "    `$_ | Out-String | Add-Content -Path '$logPath'"
        '}'
    )

    Set-Content -Path $scriptPath -Value ($scriptLines -join "`n") -Encoding UTF8
    Write-Verbose "Patrol script written to: $scriptPath"

    $action = New-ScheduledTaskAction `
        -Execute $pwshPath `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$scriptPath`""

    # Build trigger
    if ($AtTime) {
        $trigger = New-ScheduledTaskTrigger -Daily -At $AtTime
    } else {
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
            -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
            -RepetitionDuration (New-TimeSpan -Days 3650)
    }

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable `
        -MultipleInstances IgnoreNew

    $principal = if ($RunAs -eq 'SYSTEM') {
        New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    } else {
        New-ScheduledTaskPrincipal -UserId $RunAs -LogonType S4U -RunLevel Highest
    }

    # Check if task exists
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        if ($Force -or $PSCmdlet.ShouldProcess($TaskName, 'Update existing scheduled task')) {
            Set-ScheduledTask -TaskName $TaskName `
                -Action $action -Trigger $trigger `
                -Settings $settings -Principal $principal | Out-Null
            Write-Host "Updated scheduled task: $TaskName"
        } else {
            Write-Warning "Scheduled task '$TaskName' already exists. Use -Force to update."
            return
        }
    } else {
        if ($Force -or $PSCmdlet.ShouldProcess($TaskName, 'Create scheduled task')) {
            Register-ScheduledTask -TaskName $TaskName `
                -Action $action -Trigger $trigger `
                -Settings $settings -Principal $principal `
                -Description $Description | Out-Null
            Write-Host "Created scheduled task: $TaskName"
        }
    }

    $schedule = if ($AtTime) { "Daily at $($AtTime.ToString('HH:mm'))" }
               else { "Every $IntervalMinutes minutes" }

    [PSCustomObject]@{
        TaskName    = $TaskName
        Schedule    = $schedule
        ScanMode    = $ScanMode
        Theaters    = $Theaters
        SendAlerts  = $SendAlerts.IsPresent
        ConfigPath  = $cfgPath
        RunAs       = $RunAs
    }
}
