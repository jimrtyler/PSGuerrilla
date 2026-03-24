
# --- AD Mock Data Factories for Pester Tests ---

function New-MockADUser {
    param(
        [string]$SamAccountName = 'jsmith',
        [string]$Name = 'John Smith',
        [string]$DistinguishedName = 'CN=John Smith,OU=Users,DC=contoso,DC=com',
        [string]$ObjectClass = 'user',
        [int]$UserAccountControl = 0x200,  # NORMAL_ACCOUNT
        [bool]$Enabled = $true,
        [nullable[datetime]]$PwdLastSet = [datetime]::UtcNow.AddDays(-30),
        [nullable[datetime]]$LastLogonTimestamp = [datetime]::UtcNow.AddDays(-1),
        [int]$AdminCount = 0,
        [string[]]$MemberOf = @(),
        [string[]]$ServicePrincipalName = @(),
        [string]$ObjectSid = 'S-1-5-21-1234567890-1234567890-1234567890-1001',
        [int]$SupportedEncryptionTypes = 28  # AES128+AES256+RC4
    )

    $uacFlags = @{
        ACCOUNTDISABLE                 = ($UserAccountControl -band 0x0002) -ne 0
        PASSWD_NOTREQD                 = ($UserAccountControl -band 0x0020) -ne 0
        NORMAL_ACCOUNT                 = ($UserAccountControl -band 0x0200) -ne 0
        DONT_EXPIRE_PASSWORD           = ($UserAccountControl -band 0x10000) -ne 0
        SMARTCARD_REQUIRED             = ($UserAccountControl -band 0x40000) -ne 0
        TRUSTED_FOR_DELEGATION         = ($UserAccountControl -band 0x80000) -ne 0
        NOT_DELEGATED                  = ($UserAccountControl -band 0x100000) -ne 0
        USE_DES_KEY_ONLY               = ($UserAccountControl -band 0x200000) -ne 0
        DONT_REQ_PREAUTH               = ($UserAccountControl -band 0x400000) -ne 0
        ENCRYPTED_TEXT_PWD_ALLOWED      = ($UserAccountControl -band 0x0080) -ne 0
        TRUSTED_TO_AUTH_FOR_DELEGATION = ($UserAccountControl -band 0x1000000) -ne 0
    }

    @{
        samaccountname           = $SamAccountName
        name                     = $Name
        distinguishedname        = $DistinguishedName
        objectclass              = @($ObjectClass)
        useraccountcontrol       = $UserAccountControl
        UACFlags                 = $uacFlags
        Enabled                  = $Enabled
        pwdlastset               = $PwdLastSet
        lastlogontimestamp       = $LastLogonTimestamp
        admincount               = $AdminCount
        memberof                 = $MemberOf
        serviceprincipalname     = $ServicePrincipalName
        objectsid                = $ObjectSid
        'msds-supportedencryptiontypes' = $SupportedEncryptionTypes
        SupportedEncryptionTypes = $SupportedEncryptionTypes
    }
}

function New-MockADComputer {
    param(
        [string]$Name = 'DC01',
        [string]$SamAccountName = 'DC01$',
        [string]$DistinguishedName = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com',
        [string]$OperatingSystem = 'Windows Server 2022 Datacenter',
        [string]$OperatingSystemVersion = '10.0 (20348)',
        [nullable[datetime]]$LastLogonTimestamp = [datetime]::UtcNow.AddDays(-1),
        [bool]$IsGlobalCatalog = $true,
        [bool]$IsRODC = $false,
        [bool]$ObsoleteOS = $false,
        [bool]$UnsupportedOS = $false,
        [string]$DnsHostName = 'DC01.contoso.com',
        [string[]]$ServicePrincipalName = @('ldap/DC01.contoso.com', 'HOST/DC01.contoso.com'),
        [int]$UserAccountControl = 0x2000  # SERVER_TRUST_ACCOUNT
    )

    @{
        Name               = $Name
        name               = $Name
        samaccountname     = $SamAccountName
        distinguishedname  = $DistinguishedName
        objectclass        = @('computer')
        operatingsystem    = $OperatingSystem
        operatingsystemversion = $OperatingSystemVersion
        lastlogontimestamp = $LastLogonTimestamp
        IsGlobalCatalog    = $IsGlobalCatalog
        IsRODC             = $IsRODC
        ObsoleteOS         = $ObsoleteOS
        UnsupportedOS      = $UnsupportedOS
        FQDN               = $DnsHostName
        dnshostname        = $DnsHostName
        serviceprincipalname = $ServicePrincipalName
        useraccountcontrol = $UserAccountControl
    }
}

function New-MockADGroup {
    param(
        [string]$Name = 'Domain Admins',
        [string]$SamAccountName = 'Domain Admins',
        [string]$DistinguishedName = 'CN=Domain Admins,CN=Users,DC=contoso,DC=com',
        [hashtable[]]$Members = @()
    )

    @{
        Name              = $Name
        samaccountname    = $SamAccountName
        distinguishedname = $DistinguishedName
        objectclass       = @('group')
        Members           = @($Members)
    }
}

function New-MockADTrust {
    param(
        [string]$TrustedDomain = 'partner.com',
        [string]$TrustDN = 'CN=partner.com,CN=System,DC=contoso,DC=com',
        [string]$TrustDirection = 'Bidirectional',
        [string]$TrustType = 'Forest',
        [bool]$IsTransitive = $true,
        [bool]$IsSIDFilteringEnabled = $true,
        [bool]$IsQuarantined = $false,
        [bool]$SelectiveAuthentication = $false,
        [bool]$IsAzureADTrust = $false,
        [bool]$IsForestTransitive = $true,
        [bool]$IsCrossOrganization = $false,
        [int]$TrustAttributes = 8,
        [nullable[datetime]]$WhenChanged = [datetime]::UtcNow.AddDays(-30)
    )

    @{
        TrustedDomain          = $TrustedDomain
        TrustDN                = $TrustDN
        TrustDirection         = $TrustDirection
        TrustType              = $TrustType
        IsTransitive           = $IsTransitive
        IsSIDFilteringEnabled  = $IsSIDFilteringEnabled
        IsQuarantined          = $IsQuarantined
        SelectiveAuthentication = $SelectiveAuthentication
        IsAzureADTrust         = $IsAzureADTrust
        IsForestTransitive     = $IsForestTransitive
        IsCrossOrganization    = $IsCrossOrganization
        TrustAttributes        = $TrustAttributes
        TrustPartnerDC         = "dc1.$TrustedDomain"
        TrustCreated           = [datetime]::UtcNow.AddYears(-2)
        TrustModified          = $WhenChanged
        WhenChanged            = $WhenChanged
        SIDFilteringEnabled    = $IsSIDFilteringEnabled
    }
}

function New-MockADGPO {
    param(
        [string]$DisplayName = 'Default Domain Policy',
        [string]$GUID = '{31B2F340-016D-11D2-945F-00C04FB984F9}',
        [string]$DN = 'CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=contoso,DC=com',
        [int]$Flags = 0,
        [int]$VersionUser = 1,
        [int]$VersionComputer = 1,
        [bool]$IsLinked = $true,
        [bool]$HasContent = $true,
        [string[]]$Links = @('DC=contoso,DC=com'),
        [hashtable]$SYSVOLContent = @{}
    )

    @{
        DisplayName     = $DisplayName
        GUID            = $GUID
        DN              = $DN
        Flags           = $Flags
        VersionUser     = $VersionUser
        VersionComputer = $VersionComputer
        IsLinked        = $IsLinked
        HasContent      = $HasContent
        Links           = $Links
        GPCFileSysPath  = "\\contoso.com\SYSVOL\contoso.com\Policies\$GUID"
        WMIFilter       = $null
        CreatedTime     = [datetime]::UtcNow.AddYears(-3)
        ModifiedTime    = [datetime]::UtcNow.AddDays(-7)
    }
}

function New-MockADCertTemplate {
    param(
        [string]$Name = 'User',
        [string]$DisplayName = 'User',
        [string]$DN = 'CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com',
        [int]$SchemaVersion = 2,
        [int]$msPKICertificateNameFlag = 0,
        [string[]]$pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2'),
        [int]$msPKIRASignature = 0,
        [bool]$HasSANFlag = $false,
        [bool]$HasAnyPurposeEKU = $false,
        [bool]$HasNoEKU = $false,
        [bool]$IsPublished = $true,
        [hashtable[]]$EnrollmentACEs = @()
    )

    @{
        Name                          = $Name
        DisplayName                   = $DisplayName
        DN                            = $DN
        TemplateDN                    = $DN
        SchemaVersion                 = $SchemaVersion
        msPKICertificateNameFlag      = $msPKICertificateNameFlag
        msPKIEnrollmentFlag           = 0
        pKIExtendedKeyUsage           = $pKIExtendedKeyUsage
        msPKIRASignature              = $msPKIRASignature
        msPKICertificateApplicationPolicy = @()
        msPKITemplateSchemaVersion    = $SchemaVersion
        HasSANFlag                    = $HasSANFlag
        HasAnyPurposeEKU              = $HasAnyPurposeEKU
        HasNoEKU                      = $HasNoEKU
        IsPublished                   = $IsPublished
        EnrollmentACEs                = @($EnrollmentACEs)
        ManagerApproval               = $false
        AuthorizedSignatures          = $msPKIRASignature
        SecurityDescriptor            = @{ ACEs = @() }
    }
}

function New-MockDomainInfo {
    param(
        [int]$ForestFunctionalLevel = 7,
        [string]$ForestFunctionalLevelName = 'Windows Server 2016',
        [int]$DomainFunctionalLevel = 7,
        [string]$DomainFunctionalLevelName = 'Windows Server 2016',
        [int]$SchemaVersion = 88,
        [string]$SchemaVersionName = 'Windows Server 2019',
        [bool]$RecycleBinEnabled = $true,
        [int]$TombstoneLifetime = 180,
        [string]$DomainDN = 'DC=contoso,DC=com',
        [string]$DomainName = 'contoso.com'
    )

    @{
        ForestFunctionalLevel     = $ForestFunctionalLevel
        ForestFunctionalLevelName = $ForestFunctionalLevelName
        DomainFunctionalLevel     = $DomainFunctionalLevel
        DomainFunctionalLevelName = $DomainFunctionalLevelName
        SchemaVersion             = $SchemaVersion
        SchemaVersionName         = $SchemaVersionName
        RecycleBinEnabled         = $RecycleBinEnabled
        TombstoneLifetime         = $TombstoneLifetime
        DomainDN                  = $DomainDN
        DomainName                = $DomainName
        FSMORoles = @{
            SchemaMaster         = 'DC01.contoso.com'
            DomainNamingMaster   = 'DC01.contoso.com'
            PDCEmulator          = 'DC01.contoso.com'
            RIDMaster            = 'DC01.contoso.com'
            InfrastructureMaster = 'DC02.contoso.com'
        }
        Sites = @(
            @{ Name = 'Default-First-Site-Name'; Subnets = @('10.0.0.0/24'); SiteLinks = @('DEFAULTIPSITELINK') }
        )
        SiteLinks = @(
            @{ Name = 'DEFAULTIPSITELINK'; Sites = @('Default-First-Site-Name'); Cost = 100; ReplicationInterval = 180 }
        )
        DnsZones = @(
            @{ Name = 'contoso.com'; DynamicUpdate = 'Secure' }
        )
    }
}

function New-MockPasswordPolicy {
    param(
        [int]$MinPwdLength = 14,
        [bool]$ComplexityEnabled = $true,
        [int]$PwdHistoryLength = 24,
        [int]$MaxPwdAgeDays = 180,
        [int]$MinPwdAgeDays = 1,
        [int]$LockoutThreshold = 5,
        [int]$LockoutDurationMinutes = 30,
        [int]$LockoutObservationMinutes = 30
    )

    @{
        MinPwdLength            = $MinPwdLength
        PwdProperties           = if ($ComplexityEnabled) { 1 } else { 0 }
        ComplexityEnabled       = $ComplexityEnabled
        PwdHistoryLength        = $PwdHistoryLength
        MaxPwdAge               = [timespan]::FromDays($MaxPwdAgeDays)
        MinPwdAge               = [timespan]::FromDays($MinPwdAgeDays)
        LockoutThreshold        = $LockoutThreshold
        LockoutDuration         = [timespan]::FromMinutes($LockoutDurationMinutes)
        LockoutObservationWindow = [timespan]::FromMinutes($LockoutObservationMinutes)
        ReversibleEncryption    = $false
    }
}

function New-MockKrbtgtAccount {
    param(
        [nullable[datetime]]$PwdLastSet = [datetime]::UtcNow.AddDays(-90),
        [int]$PwdAgeDays = 90,
        [int]$KeyVersionNumber = 2
    )

    @{
        SamAccountName    = 'krbtgt'
        DistinguishedName = 'CN=krbtgt,CN=Users,DC=contoso,DC=com'
        PwdLastSet        = $PwdLastSet
        PwdAgeDays        = $PwdAgeDays
        KeyVersionNumber  = $KeyVersionNumber
        Enabled           = $false
        UserAccountControl = 0x0202  # ACCOUNTDISABLE + NORMAL_ACCOUNT
        UACFlags = @{
            ACCOUNTDISABLE       = $true
            NORMAL_ACCOUNT       = $true
            DONT_EXPIRE_PASSWORD = $false
        }
    }
}

function New-MockReconData {
    param(
        [string]$DomainName = 'contoso.com',
        [string]$DomainDN = 'DC=contoso,DC=com',
        [int]$UserCount = 100,
        [int]$DomainAdminCount = 3,
        [bool]$IncludeTrusts = $false,
        [bool]$IncludeADCS = $false
    )

    $domainSid = 'S-1-5-21-1234567890-1234567890-1234567890'

    # Build privileged groups with sample members
    $daMembers = @()
    for ($i = 1; $i -le $DomainAdminCount; $i++) {
        $daMembers += New-MockADUser -SamAccountName "admin$i" -Name "Admin User $i" `
            -DistinguishedName "CN=Admin User $i,OU=Admins,$DomainDN" `
            -AdminCount 1 -PwdLastSet ([datetime]::UtcNow.AddDays(-60))
    }

    $privGroups = @{
        'Domain Admins'     = $daMembers
        'Enterprise Admins' = @($daMembers[0])
        'Schema Admins'     = @()
        'Account Operators' = @()
        'Server Operators'  = @()
        'Backup Operators'  = @()
        'Print Operators'   = @()
        'DnsAdmins'         = @()
    }

    # Build DCs
    $dcs = @(
        (New-MockADComputer -Name 'DC01' -DnsHostName 'DC01.contoso.com' -IsGlobalCatalog $true)
        (New-MockADComputer -Name 'DC02' -DnsHostName 'DC02.contoso.com' -IsGlobalCatalog $true `
            -DistinguishedName "CN=DC02,OU=Domain Controllers,$DomainDN")
    )

    # Build users
    $allUsers = @()
    for ($i = 1; $i -le $UserCount; $i++) {
        $allUsers += New-MockADUser -SamAccountName "user$i" -Name "User $i" `
            -DistinguishedName "CN=User $i,OU=Users,$DomainDN" `
            -PwdLastSet ([datetime]::UtcNow.AddDays(-($i * 5)))
    }

    $data = @{
        Domain              = New-MockDomainInfo -DomainDN $DomainDN -DomainName $DomainName
        DomainControllers   = $dcs
        Trusts              = @()
        PrivilegedAccounts  = @{
            PrivilegedGroups  = $privGroups
            AllPrivilegedUsers = $daMembers
        }
        AdminSDHolder       = @{
            DN = "CN=AdminSDHolder,CN=System,$DomainDN"
            DangerousACEs = @()
        }
        AdminCountOrphans   = @()
        KrbtgtAccount       = New-MockKrbtgtAccount
        ProtectedUsersMembers = @($daMembers[0])
        AllUsers            = $allUsers
        PasswordPolicies    = @{
            DefaultPolicy = New-MockPasswordPolicy
            FGPPs = @()
        }
        UsersPasswordNeverExpires = @()
        LAPSConfig = @{
            LegacyLAPSSchema  = $false
            WindowsLAPSSchema = $true
            LAPSComputers     = @()
            NonLAPSComputers  = @()
        }
        BitLockerKeys       = 0
        PasswordAnalysis    = $null
        Kerberos = @{
            KerberoastableAccounts      = @()
            ASREPRoastableAccounts      = @()
            UnconstrainedDelegation     = @()
            ConstrainedDelegation       = @()
            RBCD                        = @()
            ProtocolTransition          = @()
            EncryptionTypes = @{
                DESOnly = @(); RC4Only = @(); AES128 = @(); AES256 = @(); NoEncType = @()
                DomainControllers = @()
            }
            KerberosPolicy              = @{
                MaxTicketAge  = 10
                MaxRenewAge   = 7
                MaxServiceAge = 600
                MaxClockSkew  = 5
            }
            ComputerSPNs                = @()
        }
        ObjectACLs = @{
            CriticalObjects = @{
                DomainRoot = @{
                    DN = $DomainDN
                    Owner = "$domainSid-512"
                    OwnerSid = "$domainSid-512"
                    DangerousACEs = @()
                }
                AdminSDHolder = @{
                    DN = "CN=AdminSDHolder,CN=System,$DomainDN"
                    Owner = "$domainSid-512"
                    OwnerSid = "$domainSid-512"
                    DangerousACEs = @()
                }
                DomainControllersOU = @{
                    DN = "OU=Domain Controllers,$DomainDN"
                    Owner = "$domainSid-512"
                    OwnerSid = "$domainSid-512"
                    DangerousACEs = @()
                }
            }
            MachineAccountQuota = 0
            DomainRootOwner     = "$domainSid-512"
            GPOPermissions      = @()
            OUDelegation        = @()
        }
        GroupPolicy = @{
            GPOs             = @((New-MockADGPO))
            SYSVOLContent    = @{}
            GPOPermissions   = @()
            WMIFilters       = @()
            VersionMismatches = @()
        }
        LogonScripts = @{
            Scripts              = @()
            NETLOGONPermissions  = @()
            SYSVOLPermissions    = @()
            CredentialFindings   = @()
            LOLBinFindings       = @()
            UNCPaths             = @()
            WorldWritableScripts = @()
            ExternalResources    = @()
        }
        CertificateServices = if ($IncludeADCS) {
            @{
                CertificateAuthorities = @(@{
                    CAName             = 'contoso-CA'
                    DN                 = "CN=contoso-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN"
                    DNSName            = 'CA01.contoso.com'
                    CertificateTemplates = @('User', 'Computer', 'WebServer')
                    Flags              = 0
                })
                CertificateTemplates = @(
                    (New-MockADCertTemplate -Name 'User' -DisplayName 'User')
                    (New-MockADCertTemplate -Name 'Computer' -DisplayName 'Computer' `
                        -pKIExtendedKeyUsage @('1.3.6.1.5.5.7.3.2'))
                    (New-MockADCertTemplate -Name 'WebServer' -DisplayName 'Web Server' `
                        -pKIExtendedKeyUsage @('1.3.6.1.5.5.7.3.1'))
                )
                PKIObjectACLs        = @{}
                NTAuthCertificates   = @()
                OIDObjects           = @()
                EnrollmentServices   = @()
            }
        } else { $null }
        StaleObjects = @{
            InactiveUsers          = @()
            InactiveComputers      = @()
            DisabledWithGroups     = @()
            ExpiredPasswordsEnabled = @()
            ObsoleteOSComputers    = @()
            UnsupportedOSComputers = @()
            OrphanedFSPs           = @()
            OrphanedSIDHistory     = @()
            AbandonedOUs           = @()
            PrinterObjects         = @()
            StaleDNSRecords        = @()
        }
        ModuleAvailability = @{
            ActiveDirectory = $false
            GroupPolicy     = $false
            DSInternals     = $false
            PSPKI           = $false
        }
        Errors = @{}
    }

    if ($IncludeTrusts) {
        $data.Trusts = @(
            (New-MockADTrust -TrustedDomain 'partner.com' -TrustDirection 'Bidirectional' -TrustType 'Forest')
        )
    }

    return $data
}

function New-MockReconResult {
    param(
        [PSCustomObject[]]$Findings = @(),
        [string]$DomainName = 'contoso.com',
        [int]$OverallScore = 72,
        [string]$ScoreLabel = 'CONTESTED PERIMETER'
    )

    $failFindings = @($Findings | Where-Object Status -eq 'FAIL')
    $critCount = @($failFindings | Where-Object Severity -eq 'Critical').Count
    $highCount = @($failFindings | Where-Object Severity -eq 'High').Count
    $medCount  = @($failFindings | Where-Object Severity -eq 'Medium').Count
    $lowCount  = @($failFindings | Where-Object Severity -eq 'Low').Count

    [PSCustomObject]@{
        PSTypeName     = 'PSGuerrilla.ReconResult'
        ScanId         = [guid]::NewGuid().ToString()
        Timestamp      = [datetime]::UtcNow
        DomainName     = $DomainName
        OverallScore   = $OverallScore
        ScoreLabel     = $ScoreLabel
        CategoryScores = @{}
        TotalChecks    = $Findings.Count
        PassCount      = @($Findings | Where-Object Status -eq 'PASS').Count
        FailCount      = @($Findings | Where-Object Status -eq 'FAIL').Count
        WarnCount      = @($Findings | Where-Object Status -eq 'WARN').Count
        SkipCount      = @($Findings | Where-Object Status -in @('SKIP', 'ERROR')).Count
        CriticalCount  = $critCount
        HighCount      = $highCount
        MediumCount    = $medCount
        LowCount       = $lowCount
        Findings       = @($Findings)
        Delta          = $null
        HtmlReportPath = $null
        CsvReportPath  = $null
        JsonReportPath = $null
    }
}

function New-MockADCheckDefinition {
    param(
        [string]$Id = 'ADDOM-001',
        [string]$Name = 'Forest Functional Level',
        [string]$Severity = 'High',
        [string]$CategoryName = 'AD Domain & Forest Configuration',
        [string]$Subcategory = 'Forest Configuration',
        [string]$Description = 'Forest functional level should be current',
        [string]$RecommendedValue = 'Windows Server 2016 or higher',
        [string]$RemediationSteps = 'Raise forest functional level',
        [hashtable]$Compliance = @{
            nistSp80053  = @('CM-6')
            mitreAttack  = @('T1210')
            cisBenchmark = @()
            anssi        = @()
            nsaAsd       = @()
            cisAd        = @()
        }
    )

    @{
        id               = $Id
        name             = $Name
        severity         = $Severity
        _categoryName    = $CategoryName
        subcategory      = $Subcategory
        description      = $Description
        recommendedValue = $RecommendedValue
        remediationSteps = $RemediationSteps
        compliance       = $Compliance
    }
}

Export-ModuleMember -Function *
