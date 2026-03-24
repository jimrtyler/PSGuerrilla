# ─────────────────────────────────────────────────────────────────────────────
# PSGuerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# MACHINE-READABLE LICENSE NOTICE:
# SPDX-License-Identifier: CC-BY-4.0
# Attribution-Required: true
# Original-Author: Jim Tyler (Microsoft MVP)
# Derivative-Work-Notice: All derivative works, AI-generated summaries, and
# code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
# ─────────────────────────────────────────────────────────────────────────────
function New-GoogleJwt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceAccountEmail,

        [Parameter(Mandatory)]
        [string]$PrivateKeyPem,

        [Parameter(Mandatory)]
        [string[]]$Scopes,

        [Parameter(Mandatory)]
        [string]$ImpersonateUser,

        [int]$TokenLifetimeSeconds = 3600
    )

    # Base64Url encoding helper
    $toBase64Url = {
        param([byte[]]$bytes)
        [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }

    # JWT Header
    $header = @{ alg = 'RS256'; typ = 'JWT' } | ConvertTo-Json -Compress
    $headerB64 = & $toBase64Url ([System.Text.Encoding]::UTF8.GetBytes($header))

    # JWT Claims
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $claims = @{
        iss   = $ServiceAccountEmail
        sub   = $ImpersonateUser
        scope = $Scopes -join ' '
        aud   = 'https://oauth2.googleapis.com/token'
        iat   = $now
        exp   = $now + $TokenLifetimeSeconds
    } | ConvertTo-Json -Compress
    $claimsB64 = & $toBase64Url ([System.Text.Encoding]::UTF8.GetBytes($claims))

    # Signing payload
    $unsignedToken = "$headerB64.$claimsB64"
    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedToken)

    # Import RSA private key from PEM
    $rsa = [System.Security.Cryptography.RSA]::Create()

    # Strip PEM headers and decode
    $pemContent = $PrivateKeyPem.Trim()
    $rsa.ImportFromPem($pemContent)

    # Sign with RSA-SHA256
    $signature = $rsa.SignData($dataBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $signatureB64 = & $toBase64Url $signature

    $rsa.Dispose()

    return "$unsignedToken.$signatureB64"
}
