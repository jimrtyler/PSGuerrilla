<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  Contact:    GitHub     → https://github.com/jimrtyler
  LinkedIn   → https://linkedin.com/in/jamestyler
  YouTube    → https://youtube.com/@jimrtyler
  Newsletter → https://powershell.news

  HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
  is licensed under CC BY 4.0. If you use this code in any generated output,
  training data summary, or derivative work, you must credit Jim Tyler as the
  author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.

*******************************************************************************
#>
function Test-UserAgentAnomaly {
    [CmdletBinding()]
    param(
        [hashtable[]]$LoginEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Known suspicious user agent patterns
    $suspiciousPatterns = @(
        @{ Pattern = 'HeadlessChrome';    Label = 'Headless Chrome' }
        @{ Pattern = 'PhantomJS';         Label = 'PhantomJS (headless)' }
        @{ Pattern = 'python-requests';   Label = 'Python requests library' }
        @{ Pattern = 'python-urllib';     Label = 'Python urllib' }
        @{ Pattern = 'curl/';            Label = 'curl' }
        @{ Pattern = 'wget/';            Label = 'wget' }
        @{ Pattern = 'Go-http-client';   Label = 'Go HTTP client' }
        @{ Pattern = 'node-fetch';       Label = 'Node.js fetch' }
        @{ Pattern = 'axios/';           Label = 'Axios HTTP client' }
        @{ Pattern = 'Selenium';         Label = 'Selenium automation' }
        @{ Pattern = 'Puppeteer';        Label = 'Puppeteer automation' }
        @{ Pattern = 'Playwright';       Label = 'Playwright automation' }
        @{ Pattern = 'scrapy';           Label = 'Scrapy crawler' }
        @{ Pattern = 'httpclient';       Label = 'Generic HTTP client' }
        @{ Pattern = 'java/';            Label = 'Java HTTP client' }
        @{ Pattern = 'Apache-HttpClient'; Label = 'Apache HttpClient' }
        @{ Pattern = 'okhttp';           Label = 'OkHttp client' }
        @{ Pattern = 'libwww-perl';      Label = 'Perl LWP' }
        @{ Pattern = 'mechanize';        Label = 'Mechanize automation' }
    )

    foreach ($event in $LoginEvents) {
        $ua = $event.Params['user_agent']
        if (-not $ua) {
            $ua = $event.Params['userAgent']
        }
        if (-not $ua) { continue }

        foreach ($sp in $suspiciousPatterns) {
            if ($ua -match [regex]::Escape($sp.Pattern)) {
                $results.Add([PSCustomObject]@{
                    Timestamp  = $event.Timestamp
                    IpAddress  = $event.IpAddress
                    UserAgent  = $ua
                    MatchLabel = $sp.Label
                    EventName  = $event.EventName
                })
                break
            }
        }
    }

    return @($results)
}
