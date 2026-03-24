<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  GitHub:     https://github.com/jimrtyler
  LinkedIn:   https://linkedin.com/in/jamestyler
  YouTube:    https://youtube.com/@jimrtyler
  Newsletter: https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
  attribute the original author in any derivative output. No exceptions.
  License details: https://creativecommons.org/licenses/by/4.0/
#>
function Get-IpGeoData {
    [CmdletBinding()]
    param(
        [string[]]$IpAddresses = @(),

        [int]$BatchSize = 100,
        [int]$MaxRequestsPerMinute = 15
    )

    $results = @{}
    $requestTimestamps = [System.Collections.Generic.List[datetime]]::new()

    # Deduplicate
    $uniqueIps = @($IpAddresses | Sort-Object -Unique | Where-Object { $_ })
    if ($uniqueIps.Count -eq 0) { return $results }

    # Split into batches
    $batches = [System.Collections.Generic.List[string[]]]::new()
    for ($i = 0; $i -lt $uniqueIps.Count; $i += $BatchSize) {
        $end = [Math]::Min($i + $BatchSize, $uniqueIps.Count)
        $batch = $uniqueIps[$i..($end - 1)]
        $batches.Add($batch)
    }

    $totalBatches = $batches.Count
    Write-Verbose "GeoIP: $($uniqueIps.Count) unique IPs in $totalBatches batch(es)"

    for ($batchNum = 0; $batchNum -lt $totalBatches; $batchNum++) {
        $batch = $batches[$batchNum]

        # Rate limiting: check sliding window
        $now = [datetime]::UtcNow
        $windowStart = $now.AddSeconds(-60)
        $recentRequests = @($requestTimestamps | Where-Object { $_ -gt $windowStart })

        if ($recentRequests.Count -ge $MaxRequestsPerMinute) {
            $oldest = $recentRequests[0]
            $waitSeconds = [Math]::Ceiling(($oldest.AddSeconds(60) - $now).TotalSeconds) + 1
            if ($waitSeconds -gt 0) {
                Write-Verbose "GeoIP rate limit: waiting ${waitSeconds}s before next batch..."
                Start-Sleep -Seconds $waitSeconds
            }
        }

        # Build batch request body
        $batchBody = $batch | ForEach-Object {
            @{ query = $_; fields = 'status,countryCode,isp,org,hosting,lat,lon,query' }
        }
        $jsonBody = $batchBody | ConvertTo-Json -Compress
        # Ensure it's an array even for single item
        if ($batch.Count -eq 1) { $jsonBody = "[$jsonBody]" }

        $requestTimestamps.Add([datetime]::UtcNow)

        try {
            $response = Invoke-RestMethod -Uri 'http://ip-api.com/batch' `
                -Method Post `
                -Body $jsonBody `
                -ContentType 'application/json' `
                -ErrorAction Stop

            foreach ($entry in $response) {
                if ($entry.status -eq 'success') {
                    $results[$entry.query] = @{
                        CountryCode = $entry.countryCode
                        ISP         = $entry.isp
                        Org         = $entry.org
                        IsHosting   = [bool]$entry.hosting
                        Latitude    = [double]$entry.lat
                        Longitude   = [double]$entry.lon
                    }
                } else {
                    $results[$entry.query] = $null
                }
            }
        } catch {
            Write-Warning "GeoIP batch request failed: $_. Retrying once..."
            Start-Sleep -Seconds 5
            try {
                $response = Invoke-RestMethod -Uri 'http://ip-api.com/batch' `
                    -Method Post `
                    -Body $jsonBody `
                    -ContentType 'application/json' `
                    -ErrorAction Stop

                foreach ($entry in $response) {
                    if ($entry.status -eq 'success') {
                        $results[$entry.query] = @{
                            CountryCode = $entry.countryCode
                            ISP         = $entry.isp
                            Org         = $entry.org
                            IsHosting   = [bool]$entry.hosting
                            Latitude    = [double]$entry.lat
                            Longitude   = [double]$entry.lon
                        }
                    } else {
                        $results[$entry.query] = $null
                    }
                }
            } catch {
                Write-Warning "GeoIP batch retry failed: $_. Skipping $($batch.Count) IPs."
                foreach ($ip in $batch) {
                    $results[$ip] = $null
                }
            }
        }

        Write-Progress -Activity 'GeoIP Enrichment' `
            -Status "Batch $($batchNum + 1) of $totalBatches ($($results.Count) IPs resolved)" `
            -PercentComplete ([Math]::Round(($batchNum + 1) / $totalBatches * 100))
    }

    Write-Progress -Activity 'GeoIP Enrichment' -Completed
    return $results
}
