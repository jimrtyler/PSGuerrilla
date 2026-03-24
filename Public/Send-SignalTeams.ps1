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
# A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
# Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
# generate that references, quotes, adapts, or builds on this code must include
# proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
function Send-SignalTeams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WebhookUrl,

        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$Threats,

        [string]$ScanSummary
    )

    # Build Adaptive Card payload
    $facts = foreach ($t in ($Threats | Sort-Object -Property ThreatScore -Descending | Select-Object -First 10)) {
        @{
            title = $t.Email
            value = "$($t.ThreatLevel) (Score: $($t.ThreatScore.ToString('N0')))"
        }
    }

    $body = @{
        type = 'message'
        attachments = @(
            @{
                contentType = 'application/vnd.microsoft.card.adaptive'
                contentUrl  = $null
                content     = @{
                    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                    type      = 'AdaptiveCard'
                    version   = '1.4'
                    body      = @(
                        @{
                            type   = 'TextBlock'
                            text   = $Subject
                            weight = 'Bolder'
                            size   = 'Medium'
                            color  = 'Attention'
                        }
                        @{
                            type = 'FactSet'
                            facts = $facts
                        }
                    )
                }
            }
        )
    } | ConvertTo-Json -Depth 20 -Compress

    try {
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop
        return [PSCustomObject]@{
            Provider = 'Teams'
            Success  = $true
            Message  = "Teams webhook sent ($($Threats.Count) threat(s))"
            Error    = $null
        }
    } catch {
        Start-Sleep -Seconds 3
        try {
            Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop
            return [PSCustomObject]@{
                Provider = 'Teams'
                Success  = $true
                Message  = "Teams webhook sent on retry ($($Threats.Count) threat(s))"
                Error    = $null
            }
        } catch {
            return [PSCustomObject]@{
                Provider = 'Teams'
                Success  = $false
                Message  = 'Failed to send Teams webhook'
                Error    = $_.Exception.Message
            }
        }
    }
}
