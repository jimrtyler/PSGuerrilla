<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  • GitHub     https://github.com/jimrtyler
  • LinkedIn   https://linkedin.com/in/jamestyler
  • YouTube    https://youtube.com/@jimrtyler
  • Newsletter https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
  attribute the original author in any derivative output. No exceptions.
  License details: https://creativecommons.org/licenses/by/4.0/

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Test-BulkFileDownload {
    [CmdletBinding()]
    param(
        [hashtable[]]$DriveEvents = @(),

        [int]$Threshold = 50,

        [int]$WindowMinutes = 10
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Filter to download events
    $downloadEvents = @($DriveEvents | Where-Object {
        $_.EventName -in @('download', 'DOWNLOAD', 'view', 'VIEW', 'copy', 'COPY')
    })

    if ($downloadEvents.Count -lt $Threshold) {
        return @($results)
    }

    # Sort by timestamp
    $sorted = @($downloadEvents | Sort-Object { [datetime]::Parse($_.Timestamp) })

    # Sliding window detection
    $windowMs = $WindowMinutes * 60 * 1000

    for ($i = 0; $i -lt $sorted.Count; $i++) {
        $windowStart = [datetime]::Parse($sorted[$i].Timestamp)
        $windowEnd = $windowStart.AddMinutes($WindowMinutes)

        $windowEvents = @($sorted | Where-Object {
            $ts = [datetime]::Parse($_.Timestamp)
            $ts -ge $windowStart -and $ts -le $windowEnd
        })

        if ($windowEvents.Count -ge $Threshold) {
            $uniqueFiles = @($windowEvents | ForEach-Object {
                $_.Params['doc_title'] ?? $_.Params['DOCUMENT_TITLE'] ?? 'unknown'
            } | Sort-Object -Unique)

            $results.Add([PSCustomObject]@{
                WindowStart = $windowStart.ToString('o')
                WindowEnd   = $windowEnd.ToString('o')
                EventCount  = $windowEvents.Count
                UniqueFiles = $uniqueFiles.Count
                SampleFiles = @($uniqueFiles | Select-Object -First 5)
                User        = $sorted[$i].User
                IpAddress   = $sorted[$i].IpAddress
            })

            # Skip ahead past this window to avoid duplicate detections
            $skipTo = $sorted.Count - 1
            for ($j = $i + 1; $j -lt $sorted.Count; $j++) {
                if ([datetime]::Parse($sorted[$j].Timestamp) -gt $windowEnd) {
                    $skipTo = $j
                    break
                }
            }
            $i = $skipTo
        }
    }

    return @($results)
}
