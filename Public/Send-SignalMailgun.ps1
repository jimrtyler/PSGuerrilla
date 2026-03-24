# ─────────────────────────────────────────────────────────────────────────────
# PSGuerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
# ─────────────────────────────────────────────────────────────────────────────
function Send-SignalMailgun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ApiKey,

        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [string]$FromEmail,

        [Parameter(Mandatory)]
        [string[]]$ToEmails,

        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [string]$HtmlBody,

        [string]$TextBody
    )

    $uri = "https://api.mailgun.net/v3/$Domain/messages"
    $credential = [System.Management.Automation.PSCredential]::new(
        'api',
        ($ApiKey | ConvertTo-SecureString -AsPlainText -Force)
    )

    $form = @{
        from    = $FromEmail
        to      = $ToEmails -join ', '
        subject = $Subject
        html    = $HtmlBody
    }
    if ($TextBody) { $form['text'] = $TextBody }

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post `
            -Authentication Basic -Credential $credential `
            -Form $form -ErrorAction Stop

        return [PSCustomObject]@{
            Provider = 'Mailgun'
            Success  = $true
            Message  = "Email sent: $($response.id ?? 'OK')"
            Error    = $null
        }
    } catch {
        Start-Sleep -Seconds 3
        try {
            $response = Invoke-RestMethod -Uri $uri -Method Post `
                -Authentication Basic -Credential $credential `
                -Form $form -ErrorAction Stop

            return [PSCustomObject]@{
                Provider = 'Mailgun'
                Success  = $true
                Message  = "Email sent on retry: $($response.id ?? 'OK')"
                Error    = $null
            }
        } catch {
            return [PSCustomObject]@{
                Provider = 'Mailgun'
                Success  = $false
                Message  = 'Failed to send email'
                Error    = $_.Exception.Message
            }
        }
    }
}
