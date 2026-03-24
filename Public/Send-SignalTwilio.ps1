# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>> PSGuerrilla                                                           >>>
# >>> Jim Tyler, Microsoft MVP                                              >>>
# >>> Copyright (c) 2026 Jim Tyler                                                  >>>
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#
# Author of "PowerShell for Systems Engineers"
#
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
# attribute the original author in any derivative output. No exceptions.
# License details: https://creativecommons.org/licenses/by/4.0/
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
function Send-SignalTwilio {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccountSid,

        [Parameter(Mandatory)]
        [string]$AuthToken,

        [Parameter(Mandatory)]
        [string]$FromNumber,

        [Parameter(Mandatory)]
        [string[]]$ToNumbers,

        [Parameter(Mandatory)]
        [string]$MessageBody
    )

    $credential = [System.Management.Automation.PSCredential]::new(
        $AccountSid,
        ($AuthToken | ConvertTo-SecureString -AsPlainText -Force)
    )

    $uri = "https://api.twilio.com/2010-04-01/Accounts/$AccountSid/Messages.json"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($number in $ToNumbers) {
        $form = @{
            From = $FromNumber
            To   = $number
            Body = $MessageBody
        }

        try {
            $response = Invoke-RestMethod -Uri $uri -Method Post `
                -Authentication Basic -Credential $credential `
                -Form $form -ErrorAction Stop

            $results.Add([PSCustomObject]@{
                Provider = 'Twilio'
                Success  = $true
                Message  = "SMS sent to $number (SID: $($response.sid))"
                Error    = $null
            })
        } catch {
            $results.Add([PSCustomObject]@{
                Provider = 'Twilio'
                Success  = $false
                Message  = "Failed to send SMS to $number"
                Error    = $_.Exception.Message
            })
            Write-Warning "Twilio SMS to $number failed: $($_.Exception.Message)"
        }
    }

    return @($results)
}
