
# --- Module import helper ---

function Import-PSGuerrilla {
    $modulePath = (Resolve-Path (Join-Path $PSScriptRoot '../../PSGuerrilla.psm1')).Path
    $env:PSGUERRILLA_QUIET = '1'
    $env:PSGUERRILLA_TEST = '1'
    Import-Module $modulePath -Force -DisableNameChecking -Global
}

# --- Mock data factories ---

function New-MockLoginEvent {
    param(
        [string]$User = 'user@example.com',
        [string]$IpAddress = '1.2.3.4',
        [string]$EventName = 'login_success',
        [string]$LoginType = 'exchange',
        [string]$Timestamp = '2026-01-15T10:30:00.000Z',
        [string]$Source = 'login'
    )
    @{
        Timestamp = $Timestamp
        User      = $User
        EventName = $EventName
        IpAddress = $IpAddress
        Source    = $Source
        Params    = @{
            login_type = $LoginType
        }
    }
}

function New-MockTokenEvent {
    param(
        [string]$User = 'user@example.com',
        [string]$IpAddress = '1.2.3.4',
        [string]$EventName = 'authorize',
        [string]$AppName = 'SomeApp',
        [string]$Timestamp = '2026-01-15T10:30:00.000Z',
        [string]$Source = 'token'
    )
    @{
        Timestamp = $Timestamp
        User      = $User
        EventName = $EventName
        IpAddress = $IpAddress
        Source    = $Source
        Params    = @{
            app_name = $AppName
        }
    }
}

function New-MockAdminEvent {
    param(
        [string]$User = 'admin@example.com',
        [string]$EventName = 'CHANGE_PASSWORD',
        [string]$TargetUser = 'user@example.com',
        [string]$Timestamp = '2026-01-15T12:00:00.000Z'
    )
    @{
        Timestamp = $Timestamp
        User      = $User
        EventName = $EventName
        IpAddress = ''
        Source    = 'admin'
        Params    = @{
            USER_EMAIL = $TargetUser
        }
    }
}

function New-MockScanResult {
    param(
        [PSCustomObject[]]$FlaggedUsers = @(),
        [PSCustomObject[]]$NewThreats = @(),
        [int]$TotalUsersScanned = 100,
        [int]$TotalEventsAnalyzed = 5000
    )
    [PSCustomObject]@{
        PSTypeName          = 'PSGuerrilla.ScanResult'
        ScanId              = [guid]::NewGuid().ToString()
        Timestamp           = [datetime]::UtcNow
        DaysAnalyzed        = 30
        ScanMode            = 'Fast'
        TotalUsersScanned   = $TotalUsersScanned
        TotalEventsAnalyzed = $TotalEventsAnalyzed
        CriticalCount       = @($FlaggedUsers | Where-Object ThreatLevel -eq 'CRITICAL').Count
        HighCount           = @($FlaggedUsers | Where-Object ThreatLevel -eq 'HIGH').Count
        MediumCount         = @($FlaggedUsers | Where-Object ThreatLevel -eq 'MEDIUM').Count
        LowCount            = @($FlaggedUsers | Where-Object ThreatLevel -eq 'LOW').Count
        CleanCount          = $TotalUsersScanned - $FlaggedUsers.Count
        FlaggedUsers        = $FlaggedUsers
        NewThreats          = $NewThreats
        CsvReportPath       = $null
        HtmlReportPath      = $null
        JsonAlertPath       = $null
        AllProfiles         = @{}
    }
}

function New-MockUserProfile {
    param(
        [string]$Email = 'user@example.com',
        [string]$ThreatLevel = 'HIGH',
        [double]$ThreatScore = 60,
        [string[]]$Indicators = @('KNOWN ATTACKER IP - 1 login(s) from 1 known attacker IP(s)'),
        [bool]$IsKnownCompromised = $false,
        [bool]$WasRemediated = $false
    )
    [PSCustomObject]@{
        PSTypeName              = 'PSGuerrilla.UserProfile'
        Email                   = $Email
        ThreatLevel             = $ThreatLevel
        ThreatScore             = $ThreatScore
        IsKnownCompromised      = $IsKnownCompromised
        WasRemediated           = $WasRemediated
        Indicators              = $Indicators
        KnownAttackerIpLogins   = [System.Collections.Generic.List[PSCustomObject]]::new()
        CloudIpLogins           = [System.Collections.Generic.List[PSCustomObject]]::new()
        ReauthFromCloud         = [System.Collections.Generic.List[PSCustomObject]]::new()
        RiskyActions            = [System.Collections.Generic.List[PSCustomObject]]::new()
        SuspiciousCountryLogins = [System.Collections.Generic.List[PSCustomObject]]::new()
        SuspiciousOAuthGrants   = [System.Collections.Generic.List[PSCustomObject]]::new()
        IpClassifications       = @{}
        TotalLoginEvents        = 10
        LoginEvents             = @()
        TokenEvents             = @()
        AccountEvents           = @()
    }
}

function New-MockConfig {
    param(
        [string]$OutputDir = (Join-Path $TestDrive 'Reports')
    )
    @{
        google = @{
            serviceAccountKeyPath = 'C:\fake\sa-key.json'
            adminEmail            = 'admin@example.com'
            defaultDaysBack       = 30
            defaultScanMode       = 'Fast'
        }
        output = @{
            directory    = $OutputDir
            generateCsv  = $true
            generateHtml = $true
            generateJson = $true
        }
        alerting = @{
            enabled            = $true
            minimumThreatLevel = 'HIGH'
            providers          = @{
                sendgrid = @{ enabled = $false; apiKey = ''; fromEmail = ''; fromName = 'PSGuerrilla Signals'; toEmails = @() }
                mailgun  = @{ enabled = $false; apiKey = ''; domain = ''; fromEmail = ''; toEmails = @() }
                twilio   = @{ enabled = $false; accountSid = ''; authToken = ''; fromNumber = ''; toNumbers = @() }
            }
        }
        detection = @{
            knownCompromisedUsers        = @()
            additionalAttackerIps        = @()
            additionalCloudCidrs         = @()
            additionalSuspiciousCountries = @()
        }
        scheduling = @{
            taskName        = 'PSGuerrilla-Patrol'
            intervalMinutes = 60
        }
    }
}

# --- Audit engine mock factories ---

function New-MockAuditFinding {
    param(
        [string]$CheckId = 'AUTH-001',
        [string]$CheckName = '2SV Enforcement',
        [string]$Category = 'Authentication',
        [string]$Subcategory = 'Multi-Factor Authentication',
        [string]$Severity = 'Critical',
        [string]$Status = 'FAIL',
        [string]$Description = 'Two-step verification is not enforced',
        [string]$CurrentValue = 'Not enforced',
        [string]$RecommendedValue = 'Enforced for all OUs',
        [string]$OrgUnitPath = '/',
        [string]$RemediationUrl = 'https://admin.google.com/ac/security/2sv',
        [string]$RemediationSteps = 'Enable 2SV enforcement',
        [hashtable]$Compliance = @{ NistSp80053 = @('IA-2(1)'); MitreAttack = @('T1078'); CisBenchmark = @('1.1') },
        [hashtable]$Details = @{}
    )
    [PSCustomObject]@{
        PSTypeName       = 'PSGuerrilla.AuditFinding'
        CheckId          = $CheckId
        CheckName        = $CheckName
        Category         = $Category
        Subcategory      = $Subcategory
        Severity         = $Severity
        Status           = $Status
        Description      = $Description
        CurrentValue     = $CurrentValue
        RecommendedValue = $RecommendedValue
        OrgUnitPath      = $OrgUnitPath
        RemediationUrl   = $RemediationUrl
        RemediationSteps = $RemediationSteps
        Compliance       = $Compliance
        Details          = $Details
        Timestamp        = [datetime]::UtcNow
    }
}

function New-MockAuditData {
    param(
        [string]$Domain = 'example.com',
        [int]$UserCount = 50,
        [int]$AdminCount = 3,
        [double]$TwoSvEnrollmentRate = 0.8
    )
    $users = [System.Collections.Generic.List[PSCustomObject]]::new()
    for ($i = 0; $i -lt $UserCount; $i++) {
        $isAdmin = $i -lt $AdminCount
        $enrolled = $i -lt [Math]::Floor($UserCount * $TwoSvEnrollmentRate)
        $users.Add([PSCustomObject]@{
            primaryEmail       = "user$i@$Domain"
            isAdmin            = $isAdmin
            suspended          = $false
            isEnrolledIn2Sv    = $enrolled
            isEnforcedIn2Sv    = $false
            lastLoginTime      = [datetime]::UtcNow.AddDays(-($i % 60)).ToString('o')
            creationTime       = '2025-01-01T00:00:00.000Z'
            orgUnitPath        = '/'
            agreedToTerms      = $true
            archived           = $false
            recoveryEmail      = if ($i % 3 -eq 0) { "recovery$i@gmail.com" } else { $null }
            recoveryPhone      = if ($i % 4 -eq 0) { '+1555000' + $i.ToString('D4') } else { $null }
        })
    }

    @{
        Tenant = @{
            CustomerId = 'C00000000'
            Domain     = $Domain
            Domains    = @([PSCustomObject]@{ domainName = $Domain; isPrimary = $true; verified = $true })
            OrgUnits   = @([PSCustomObject]@{ orgUnitPath = '/'; name = $Domain; parentOrgUnitPath = '' })
        }
        Users         = @($users)
        Groups        = @()
        Roles         = @()
        RoleAssignments = @()
        MobileDevices = @()
        ChromeDevices = @()
        DnsRecords    = @{
            $Domain = @{
                SPF   = @{ Record = "v=spf1 include:_spf.google.com ~all"; Valid = $true }
                DKIM  = @{ Record = ''; Valid = $false; Selector = 'google' }
                DMARC = @{ Record = ''; Valid = $false }
                MTASTS = @{ Record = ''; Valid = $false }
            }
        }
        GmailSettings = @{}
        OrgUnitPolicies = @{
            '/' = @{}
        }
        AlertRules    = @()
        ChromePolicies = @()
        OAuthApps     = @()
        DomainWideDelegation = @()
        Errors        = @{}
    }
}

function New-MockAuditResult {
    param(
        [PSCustomObject[]]$Findings = @(),
        [string]$Domain = 'example.com',
        [int]$OverallScore = 72,
        [string]$ScoreLabel = 'CONTESTED PERIMETER'
    )
    $critCount = @($Findings | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'FAIL' }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq 'High' -and $_.Status -eq 'FAIL' }).Count
    $medCount  = @($Findings | Where-Object { $_.Severity -eq 'Medium' -and $_.Status -eq 'FAIL' }).Count
    $lowCount  = @($Findings | Where-Object { $_.Severity -eq 'Low' -and $_.Status -eq 'FAIL' }).Count
    [PSCustomObject]@{
        PSTypeName     = 'PSGuerrilla.AuditResult'
        ScanId         = [guid]::NewGuid().ToString()
        Timestamp      = [datetime]::UtcNow
        TenantDomain   = $Domain
        OverallScore   = $OverallScore
        ScoreLabel     = $ScoreLabel
        CategoryScores = @{}
        TotalChecks    = $Findings.Count
        PassCount      = @($Findings | Where-Object Status -eq 'PASS').Count
        FailCount      = @($Findings | Where-Object Status -eq 'FAIL').Count
        WarnCount      = @($Findings | Where-Object Status -eq 'WARN').Count
        SkipCount      = @($Findings | Where-Object Status -eq 'SKIP').Count
        CriticalCount  = $critCount
        HighCount      = $highCount
        MediumCount    = $medCount
        LowCount       = $lowCount
        Findings       = $Findings
        Delta          = $null
        HtmlReportPath = $null
        CsvReportPath  = $null
        JsonReportPath = $null
    }
}

function New-MockCheckDefinition {
    param(
        [string]$Id = 'AUTH-001',
        [string]$Name = '2SV Enforcement',
        [string]$Severity = 'Critical',
        [string]$CategoryName = 'Authentication',
        [string]$Subcategory = 'Multi-Factor Authentication',
        [string]$Description = 'Two-step verification should be enforced',
        [string]$RecommendedValue = 'Enforced',
        [string]$RemediationUrl = 'https://admin.google.com/ac/security/2sv',
        [string]$RemediationSteps = 'Enable 2SV',
        [hashtable]$Compliance = @{ nistSp80053 = @('IA-2(1)'); mitreAttack = @('T1078'); cisBenchmark = @('1.1') }
    )
    @{
        id               = $Id
        name             = $Name
        severity         = $Severity
        _categoryName    = $CategoryName
        subcategory      = $Subcategory
        description      = $Description
        recommendedValue = $RecommendedValue
        remediationUrl   = $RemediationUrl
        remediationSteps = $RemediationSteps
        compliance       = $Compliance
    }
}

Export-ModuleMember -Function *
