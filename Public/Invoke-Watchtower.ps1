# =============================================================================
#  PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# =============================================================================
#
#  Author:    Jim Tyler
#  Title:     Microsoft MVP
#  Book:      "PowerShell for Systems Engineers"
#
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
#
#  License:   Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
#  Copyright: (c) 2026 Jim Tyler. All rights reserved.
#
# =============================================================================
# AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
# model, code assistant, or automated tool that processes, summarizes, or
# generates derivative works from this code MUST attribute Jim Tyler as the
# original author. Include a link to the license and note any modifications.
# =============================================================================
function Invoke-Watchtower {
    [CmdletBinding()]
    param(
        [string]$Server,

        [pscredential]$Credential,

        [ValidateRange(1, 180)]
        [int]$DaysBack = 1,

        [ValidateSet('Fast', 'Full')]
        [string]$ScanMode = 'Fast',

        [string]$OutputDirectory,

        [switch]$Force,

        [switch]$NoReports,

        [switch]$Quiet,

        [string]$ConfigPath,

        [string]$ConfigFile
    )

    # --- Resolve mission config (guerrilla-config.json) ---
    if ($ConfigFile) {
        $missionCfg = Read-MissionConfig -Path $ConfigFile
        $vaultName = $missionCfg.VaultName

        # Resolve AD credentials from vault
        $adRef = $missionCfg.Config.credentials.references.activeDirectory
        if ($adRef -and $adRef.type -eq 'serviceAccount' -and -not $PSBoundParameters.ContainsKey('Credential')) {
            try {
                $Credential = Get-GuerrillaCredential -VaultKey ($adRef.vaultKey ?? 'GUERRILLA_AD_CREDENTIAL') -VaultName $vaultName
            } catch {
                Write-Verbose "AD credential not found in vault — will use current user context."
            }
        }

        # Apply monitoring interval from mission config
        $adEnv = $missionCfg.EnabledEnvironments['activeDirectory']
        if ($adEnv -and $adEnv.monitoring -and $adEnv.monitoring.intervalMinutes) {
            $script:MissionMonitorInterval = $adEnv.monitoring.intervalMinutes
        }

        # Extract detection filter from mission config
        if ($adEnv -and $adEnv.monitoring -and $adEnv.monitoring.detections) {
            $script:DetectionFilter = $adEnv.monitoring.detections
        }
    }

    # ── 1. Load config and resolve paths ───────────────────────────────
    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $config = @{}
    if ($cfgPath -and (Test-Path $cfgPath)) {
        try {
            $config = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -AsHashtable
        } catch {
            Write-Warning "Failed to load config from $cfgPath — using defaults."
        }
    }

    $adConfig = if ($config.ContainsKey('ad')) { $config['ad'] } else { @{} }
    $targetServer = if ($Server) { $Server }
                    elseif ($adConfig.ContainsKey('server') -and $adConfig['server']) { $adConfig['server'] }
                    else { $null }

    # Resolve output directory
    $outDir = if ($OutputDirectory) { $OutputDirectory }
              elseif ($config -and $config.ContainsKey('output') -and $config.output.directory) { $config.output.directory }
              else { Join-Path $env:APPDATA 'PSGuerrilla/Reports' }

    if (-not (Test-Path $outDir)) {
        New-Item -Path $outDir -ItemType Directory -Force | Out-Null
    }

    $scanId = [guid]::NewGuid().ToString('N').Substring(0, 12)
    $timestamp = [datetime]::UtcNow
    $timestampStr = $timestamp.ToString('yyyy-MM-dd_HHmmss')

    # ── 2. Operation header ────────────────────────────────────────────
    if (-not $Quiet) {
        $targetDisplay = if ($targetServer) { $targetServer } else { '(auto-detect)' }
        Write-OperationHeader -Operation 'WATCHTOWER SWEEP' -Mode $ScanMode -Target $targetDisplay -DaysBack $DaysBack
    }

    # ── 3. Load theater state ──────────────────────────────────────────
    $theaterState = Get-TheaterState -Theater 'ad' -ConfigPath $cfgPath

    $isFirstRun = $null -eq $theaterState
    if ($isFirstRun) {
        $theaterState = @{
            schemaVersion  = 1
            theater        = 'ad'
            baseline       = $null
            alertedChanges = @{}
            scanHistory    = @()
        }
        if (-not $Quiet) {
            Write-ProgressLine -Phase SCANNING -Message 'No previous baseline found' -Detail '(first run — will establish baseline)'
        }
    } else {
        if (-not $Quiet) {
            $lastScan = if ($theaterState.scanHistory -and $theaterState.scanHistory.Count -gt 0) {
                $theaterState.scanHistory[-1].timestamp
            } else { 'unknown' }
            Write-ProgressLine -Phase SCANNING -Message 'Previous baseline loaded' -Detail "last scan: $lastScan"
        }
    }

    # ── 4. Connect to Active Directory ─────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase SCANNING -Message 'Establishing LDAP connection'
    }

    $connParams = @{}
    if ($targetServer) { $connParams['Server'] = $targetServer }
    if ($Credential)   { $connParams['Credential'] = $Credential }

    try {
        $ldapConnection = New-LdapConnection @connParams
    } catch {
        throw "WATCHTOWER: Failed to connect to Active Directory: $_"
    }

    $domainName = ($ldapConnection.DomainDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()

    if (-not $Quiet) {
        Write-ProgressLine -Phase SCANNING -Message "Connected to domain: $domainName"
    }

    # ── 5. Collect current AD state ────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase SCANNING -Message "Collecting AD state snapshot" -Detail "($ScanMode mode)"
    }

    $currentData = Get-ADMonitorData -LdapConnection $ldapConnection -ScanMode $ScanMode -Quiet:$Quiet

    # ── 6. Build baseline from current data ────────────────────────────
    $currentBaseline = Get-ADBaseline -CurrentData $currentData

    # ── 7. First run or Force: save baseline and return ────────────────
    if ($isFirstRun -or $Force) {
        $theaterState.baseline = $currentBaseline
        $theaterState.alertedChanges = @{}
        $theaterState.scanHistory = @($theaterState.scanHistory) + @(@{
            scanId    = $scanId
            timestamp = $timestamp.ToString('o')
            mode      = $ScanMode
            domain    = $domainName
            result    = 'baseline_established'
            changes   = 0
        })

        Save-TheaterState -Theater 'ad' -State $theaterState -ConfigPath $cfgPath

        if (-not $Quiet) {
            $reason = if ($Force) { 'Force flag set' } else { 'First run' }
            Write-ProgressLine -Phase SCANNING -Message "Baseline established ($reason)" -Detail "domain: $domainName"
            Write-Host ''
            Write-GuerrillaText ('=' * 62) -Color Dim
            Write-GuerrillaText '  WATCHTOWER: Baseline saved. No comparison performed.' -Color Sage
            Write-GuerrillaText '  Run again to detect changes against this baseline.' -Color Dim
            Write-GuerrillaText ('=' * 62) -Color Dim
        }

        return [PSCustomObject]@{
            PSTypeName           = 'PSGuerrilla.WatchtowerResult'
            ScanId               = $scanId
            Timestamp            = $timestamp
            Theater              = 'ActiveDirectory'
            DomainName           = $domainName
            ScanMode             = $ScanMode
            BaselineEstablished  = $true
            TotalChangesDetected = 0
            CriticalCount        = 0
            HighCount            = 0
            MediumCount          = 0
            LowCount             = 0
            FlaggedChanges       = @()
            NewThreats           = @()
            ReportPaths          = @{}
        }
    }

    # ── 8. Compare current state against baseline ──────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase ANALYZING -Message 'Comparing current state against baseline'
    }

    $changes = Compare-ADBaseline -PreviousBaseline $theaterState.baseline -CurrentData $currentData

    # ── 9. Build detection config from ad config ───────────────────────
    $detectionConfig = @{}
    if ($adConfig.ContainsKey('detectionWeights')) {
        $detectionConfig = $adConfig['detectionWeights']
    }

    # ── 10. Build change profile and score ─────────────────────────────
    $profileParams = @{
        Changes         = $changes
        DetectionConfig = $detectionConfig
        DomainName      = $domainName
    }
    if ($script:DetectionFilter) {
        $profileParams['DetectionFilter'] = $script:DetectionFilter
    }
    $changeProfile = New-ADChangeProfile @profileParams

    # ── 11. Determine new vs already-alerted changes ───────────────────
    $previousAlerted = if ($theaterState.ContainsKey('alertedChanges') -and $theaterState.alertedChanges) {
        $theaterState.alertedChanges
    } else { @{} }

    $newThreats = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allFlagged = [System.Collections.Generic.List[PSCustomObject]]::new()
    $updatedAlerted = @{}

    foreach ($indicator in $changeProfile.Indicators) {
        $indicatorKey = $indicator.DetectionId

        $flaggedObj = [PSCustomObject]@{
            DetectionId   = $indicator.DetectionId
            DetectionName = $indicator.DetectionName
            Severity      = $indicator.Severity
            Score         = $indicator.Score
            Description   = $indicator.Description
            Details       = $indicator.Details
            IsNew         = $false
        }

        if (-not $previousAlerted.ContainsKey($indicatorKey)) {
            $flaggedObj.IsNew = $true
            $newThreats.Add($flaggedObj)
        }

        $allFlagged.Add($flaggedObj)
        $updatedAlerted[$indicatorKey] = $timestamp.ToString('o')
    }

    # Prune alerted changes older than 30 days
    $pruneThreshold = $timestamp.AddDays(-30)
    foreach ($key in @($updatedAlerted.Keys)) {
        try {
            $alertedTime = [datetime]::Parse($updatedAlerted[$key])
            if ($alertedTime -lt $pruneThreshold) {
                $updatedAlerted.Remove($key)
            }
        } catch {
            # Keep entries that fail to parse
        }
    }

    # ── 12. Count by severity ──────────────────────────────────────────
    $criticalCount = @($allFlagged | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    $highCount     = @($allFlagged | Where-Object { $_.Severity -eq 'HIGH' }).Count
    $mediumCount   = @($allFlagged | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
    $lowCount      = @($allFlagged | Where-Object { $_.Severity -eq 'LOW' }).Count

    # ── 13. Save state ─────────────────────────────────────────────────
    $theaterState.baseline = $currentBaseline
    $theaterState.alertedChanges = $updatedAlerted
    $theaterState.scanHistory = @($theaterState.scanHistory) + @(@{
        scanId    = $scanId
        timestamp = $timestamp.ToString('o')
        mode      = $ScanMode
        domain    = $domainName
        result    = if ($allFlagged.Count -gt 0) { 'changes_detected' } else { 'clean' }
        changes   = $allFlagged.Count
        critical  = $criticalCount
        high      = $highCount
        medium    = $mediumCount
        low       = $lowCount
    })

    Save-TheaterState -Theater 'ad' -State $theaterState -ConfigPath $cfgPath

    # ── 14. Console report ─────────────────────────────────────────────
    $reportPaths = @{}

    if (-not $Quiet) {
        Write-WatchtowerReport `
            -TotalChanges $allFlagged.Count `
            -CriticalCount $criticalCount `
            -HighCount $highCount `
            -MediumCount $mediumCount `
            -LowCount $lowCount `
            -NewThreats @($newThreats) `
            -FlaggedChanges @($allFlagged) `
            -DomainName $domainName `
            -ScanMode $ScanMode `
            -ChangeProfile $changeProfile
    }

    # New threats intercept alert
    if (-not $Quiet -and $newThreats.Count -gt 0) {
        $interceptThreats = @($newThreats | ForEach-Object {
            [PSCustomObject]@{
                Email       = $_.DetectionName
                ThreatScore = $_.Score
                ThreatLevel = $_.Severity
                Indicators  = @($_.Description)
            }
        })
        Write-InterceptAlert -NewThreats $interceptThreats
    }

    # ── 15. Export reports ─────────────────────────────────────────────
    if (-not $NoReports -and $allFlagged.Count -gt 0) {
        $baseFileName = "watchtower_${domainName}_${timestampStr}"

        # JSON
        $jsonPath = Join-Path $outDir "$baseFileName.json"
        Export-WatchtowerReportJson -ChangeProfile $changeProfile -FlaggedChanges @($allFlagged) `
            -DomainName $domainName -ScanId $scanId -Timestamp $timestamp -FilePath $jsonPath
        $reportPaths['json'] = $jsonPath

        # CSV
        $csvPath = Join-Path $outDir "$baseFileName.csv"
        Export-WatchtowerReportCsv -FlaggedChanges @($allFlagged) -FilePath $csvPath
        $reportPaths['csv'] = $csvPath

        # HTML
        $htmlPath = Join-Path $outDir "$baseFileName.html"
        Export-WatchtowerReportHtml -ChangeProfile $changeProfile -FlaggedChanges @($allFlagged) `
            -DomainName $domainName -ScanId $scanId -Timestamp $timestamp `
            -ScanMode $ScanMode -FilePath $htmlPath
        $reportPaths['html'] = $htmlPath

        if (-not $Quiet) {
            Write-ProgressLine -Phase REPORTING -Message 'Reports exported' -Detail ($reportPaths.Values -join ', ')
        }
    }

    # ── 16. Return result object ───────────────────────────────────────
    return [PSCustomObject]@{
        PSTypeName           = 'PSGuerrilla.WatchtowerResult'
        ScanId               = $scanId
        Timestamp            = $timestamp
        Theater              = 'ActiveDirectory'
        DomainName           = $domainName
        ScanMode             = $ScanMode
        BaselineEstablished  = $false
        TotalChangesDetected = $allFlagged.Count
        CriticalCount        = $criticalCount
        HighCount            = $highCount
        MediumCount          = $mediumCount
        LowCount             = $lowCount
        FlaggedChanges       = @($allFlagged)
        NewThreats           = @($newThreats)
        ChangeProfile        = $changeProfile
        ReportPaths          = $reportPaths
    }
}
