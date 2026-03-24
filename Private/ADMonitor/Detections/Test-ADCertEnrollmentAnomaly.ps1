# ─────────────────────────────────────────────────────────────────────────────
# PSGuerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
# is licensed under CC BY 4.0. If you use this code in any generated output,
# training data summary, or derivative work, you must credit Jim Tyler as the
# author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.
# ─────────────────────────────────────────────────────────────────────────────
function Test-ADCertEnrollmentAnomaly {
    [CmdletBinding()]
    param(
        [array]$CertTemplateChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($CertTemplateChanges.Count -eq 0) { return @() }

    # Detect templates that were modified to enable ESC1/ESC2/ESC3 attack paths
    $dangerousChanges = @($CertTemplateChanges | Where-Object {
        $_.ChangeType -eq 'Modified' -and (
            ($_.ContainsKey('EnrolleeSuppliesSubject') -and $_.EnrolleeSuppliesSubject) -or
            ($_.ContainsKey('AllowsAuthentication') -and $_.AllowsAuthentication)
        )
    })

    # Also check for new templates with dangerous configurations
    $dangerousNew = @($CertTemplateChanges | Where-Object {
        $_.ChangeType -eq 'Added' -and
        $_.ContainsKey('EnrolleeSuppliesSubject') -and $_.EnrolleeSuppliesSubject -and
        $_.ContainsKey('AllowsAuthentication') -and $_.AllowsAuthentication
    })

    $allDangerous = @($dangerousChanges) + @($dangerousNew)

    if ($allDangerous.Count -eq 0) { return @() }

    foreach ($change in $allDangerous) {
        $riskFactors = [System.Collections.Generic.List[string]]::new()
        if ($change.ContainsKey('EnrolleeSuppliesSubject') -and $change.EnrolleeSuppliesSubject) {
            $riskFactors.Add('ENROLLEE_SUPPLIES_SUBJECT enabled (ESC1)')
        }
        if ($change.ContainsKey('AllowsAuthentication') -and $change.AllowsAuthentication) {
            $riskFactors.Add('allows domain authentication')
        }

        $riskStr = $riskFactors -join ', '
        $detectionId = "adCertEnrollmentAnomaly_$($change.Name -replace '\s+', '_')"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "Certificate Enrollment Anomaly: $($change.Name)"
            DetectionType = 'adCertEnrollmentAnomaly'
            Description   = "CERT ENROLLMENT ANOMALY - Template '$($change.Name)' has dangerous configuration: $riskStr. This could enable certificate-based privilege escalation."
            Details       = @{
                TemplateName            = $change.Name
                ChangeType              = $change.ChangeType
                RiskFactors             = @($riskFactors)
                EnrolleeSuppliesSubject = if ($change.ContainsKey('EnrolleeSuppliesSubject')) { $change.EnrolleeSuppliesSubject } else { $false }
                AllowsAuthentication    = if ($change.ContainsKey('AllowsAuthentication')) { $change.AllowsAuthentication } else { $false }
            }
            Count         = 1
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
