# [============================================================================]
# [  PSGuerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
# [============================================================================]
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
function Send-SignalSendGrid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ApiKey,

        [Parameter(Mandatory)]
        [string]$FromEmail,

        [Parameter(Mandatory)]
        [string[]]$ToEmails,

        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [string]$HtmlBody,

        [string]$TextBody,
        [string]$FromName = 'PSGuerrilla Signals'
    )

    $personalizations = @(@{
        to = @($ToEmails | ForEach-Object { @{ email = $_ } })
    })

    $content = @(@{ type = 'text/html'; value = $HtmlBody })
    if ($TextBody) {
        $content = @(@{ type = 'text/plain'; value = $TextBody }) + $content
    }

    $body = @{
        personalizations = $personalizations
        from             = @{ email = $FromEmail; name = $FromName }
        subject          = $Subject
        content          = $content
    } | ConvertTo-Json -Depth 10

    $headers = @{
        Authorization  = "Bearer $ApiKey"
        'Content-Type' = 'application/json'
    }

    try {
        $response = Invoke-RestMethod -Uri 'https://api.sendgrid.com/v3/mail/send' `
            -Method Post -Headers $headers -Body $body -ErrorAction Stop
        return [PSCustomObject]@{
            Provider = 'SendGrid'
            Success  = $true
            Message  = "Email sent to $($ToEmails -join ', ')"
            Error    = $null
        }
    } catch {
        # Retry once
        Start-Sleep -Seconds 3
        try {
            $response = Invoke-RestMethod -Uri 'https://api.sendgrid.com/v3/mail/send' `
                -Method Post -Headers $headers -Body $body -ErrorAction Stop
            return [PSCustomObject]@{
                Provider = 'SendGrid'
                Success  = $true
                Message  = "Email sent to $($ToEmails -join ', ') (on retry)"
                Error    = $null
            }
        } catch {
            return [PSCustomObject]@{
                Provider = 'SendGrid'
                Success  = $false
                Message  = "Failed to send email"
                Error    = $_.Exception.Message
            }
        }
    }
}
