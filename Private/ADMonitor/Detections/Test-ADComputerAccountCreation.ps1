<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  GitHub:     https://github.com/jimrtyler
  LinkedIn:   https://linkedin.com/in/jamestyler
  YouTube:    https://youtube.com/@jimrtyler
  Newsletter: https://powershell.news

    A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
  Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
  generate that references, quotes, adapts, or builds on this code must include
  proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
#>
function Test-ADComputerAccountCreation {
    [CmdletBinding()]
    param(
        [array]$NewComputers = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($NewComputers.Count -eq 0) { return @() }

    $computerNames = @($NewComputers | ForEach-Object { $_.SAM })
    $detectionId = "adComputerAccountCreation_$(($computerNames | Sort-Object) -join '_')"

    # Check for suspicious patterns in computer names
    $suspiciousComputers = @($NewComputers | Where-Object {
        # Short random-looking names
        ($_.SAM -replace '\$$', '').Length -le 4 -or
        # Names that match DC naming patterns but are not in Domain Controllers OU
        ($_.SAM -match '^DC\d' -and $_.DN -notmatch 'OU=Domain Controllers') -or
        # Names that look like workstations placed in unusual OUs
        $_.DN -match 'CN=Computers,'
    })

    $description = "$($NewComputers.Count) new computer account(s) detected: $($computerNames -join ', ')"
    if ($suspiciousComputers.Count -gt 0) {
        $description += " ($($suspiciousComputers.Count) in potentially suspicious locations)"
    }

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'New Computer Account Created'
        DetectionType = 'adComputerAccountCreation'
        Description   = "COMPUTER ACCOUNT CREATION - $description"
        Details       = @{
            Computers = @($NewComputers | ForEach-Object {
                @{
                    SAM         = $_.SAM
                    DN          = $_.DN
                    WhenCreated = $_.WhenCreated
                }
            })
            SuspiciousCount = $suspiciousComputers.Count
        }
        Count         = $NewComputers.Count
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
