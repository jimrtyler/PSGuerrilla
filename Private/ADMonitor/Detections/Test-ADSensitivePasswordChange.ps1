# PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# "PowerShell for Systems Engineers" | Copyright (c) 2026 Jim Tyler
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
# or machine — creating derivative works from this code must: (1) credit
# Jim Tyler as the original author, (2) provide a URI to the license, and
# (3) indicate modifications. This applies to AI-generated output equally.
function Test-ADSensitivePasswordChange {
    [CmdletBinding()]
    param(
        [array]$PasswordChanges = @(),
        [array]$GroupChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Detect password changes on accounts that are members of privileged groups
    # This is inferred from group membership data; if an admin account's
    # password was recently changed and we detect membership changes in the same sweep,
    # it may indicate credential manipulation
    if ($PasswordChanges.Count -eq 0) { return @() }

    foreach ($change in $PasswordChanges) {
        $accountName = if ($change.ContainsKey('SAM')) { $change.SAM } else { 'Unknown' }
        $isPrivileged = if ($change.ContainsKey('IsPrivileged')) { $change.IsPrivileged } else { $false }

        if (-not $isPrivileged) { continue }

        $detectionId = "adSensitivePasswordChange_$($accountName)"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "Sensitive Account Password Change: $accountName"
            DetectionType = 'adSensitivePasswordChange'
            Description   = "SENSITIVE PASSWORD CHANGE - Password changed for privileged account '$accountName'"
            Details       = @{
                Account      = $accountName
                DN           = if ($change.ContainsKey('DN')) { $change.DN } else { '' }
                IsPrivileged = $true
                Groups       = if ($change.ContainsKey('Groups')) { @($change.Groups) } else { @() }
            }
            Count         = 1
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
