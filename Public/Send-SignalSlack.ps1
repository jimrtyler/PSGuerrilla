<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  Contact:    GitHub     → https://github.com/jimrtyler
  LinkedIn   → https://linkedin.com/in/jamestyler
  YouTube    → https://youtube.com/@jimrtyler
  Newsletter → https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
  Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
  generate that references, quotes, adapts, or builds on this code must include
  proper attribution to Jim Tyler and a link to the CC BY 4.0 license.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Send-SignalSlack {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WebhookUrl,

        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$Threats,

        [string]$TextBody
    )

    # Build Slack Block Kit payload
    $blocks = @(
        @{
            type = 'header'
            text = @{ type = 'plain_text'; text = $Subject; emoji = $true }
        }
        @{ type = 'divider' }
    )

    foreach ($t in ($Threats | Sort-Object -Property ThreatScore -Descending | Select-Object -First 10)) {
        $levelEmoji = switch ($t.ThreatLevel) {
            'CRITICAL' { ':red_circle:' }
            'HIGH'     { ':large_orange_circle:' }
            'MEDIUM'   { ':large_yellow_circle:' }
            default    { ':white_circle:' }
        }

        $indicators = if ($t.Indicators.Count -gt 0) {
            ($t.Indicators | Select-Object -First 3 | ForEach-Object { "  - $_" }) -join "`n"
        } else { '  - No specific indicators' }

        $blocks += @{
            type = 'section'
            text = @{
                type = 'mrkdwn'
                text = "$levelEmoji *$($t.Email)* — $($t.ThreatLevel) (Score: $($t.ThreatScore.ToString('N0')))`n$indicators"
            }
        }
    }

    if ($Threats.Count -gt 10) {
        $blocks += @{
            type = 'context'
            elements = @(@{ type = 'mrkdwn'; text = "_...and $($Threats.Count - 10) more threats_" })
        }
    }

    $body = @{
        blocks = $blocks
        text   = $TextBody ?? $Subject  # Fallback for notifications
    } | ConvertTo-Json -Depth 20 -Compress

    try {
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop
        return [PSCustomObject]@{
            Provider = 'Slack'
            Success  = $true
            Message  = "Slack webhook sent ($($Threats.Count) threat(s))"
            Error    = $null
        }
    } catch {
        Start-Sleep -Seconds 3
        try {
            Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop
            return [PSCustomObject]@{
                Provider = 'Slack'
                Success  = $true
                Message  = "Slack webhook sent on retry ($($Threats.Count) threat(s))"
                Error    = $null
            }
        } catch {
            return [PSCustomObject]@{
                Provider = 'Slack'
                Success  = $false
                Message  = 'Failed to send Slack webhook'
                Error    = $_.Exception.Message
            }
        }
    }
}
