# PSGuerrilla

**By [Jim Tyler](https://github.com/jimrtyler), Microsoft MVP**

Security assessment, threat detection, and continuous monitoring for Google Workspace, Active Directory, Entra ID, Azure, Intune, and Microsoft 365. PowerShell 7.0+.

[![GitHub](https://img.shields.io/badge/GitHub-jimrtyler-181717?logo=github)](https://github.com/jimrtyler) [![LinkedIn](https://img.shields.io/badge/LinkedIn-jamestyler-0A66C2?logo=linkedin)](https://linkedin.com/in/jamestyler) [![YouTube](https://img.shields.io/badge/YouTube-jimrtyler-FF0000?logo=youtube)](https://youtube.com/@jimrtyler)

## Coverage

| Theater | Capability | Checks |
|---------|-----------|--------|
| Google Workspace | Compromise assessment, 23 detection signals, 8 audit categories | 64 |
| Active Directory | 10-category security reconnaissance | 200+ |
| Entra ID / Azure / Intune / M365 | Infiltration audit across 14 categories | 159 |
| All theaters | Continuous monitoring with baseline drift detection | Real-time |

**Total: 420+ security checks** across authentication, email security, drive/SharePoint, OAuth, admin management, conditional access, PIM, Kerberos, certificate services, group policy, Intune endpoint compliance, and more.

## Requirements

- PowerShell 7.0+
- [PwshSpectreConsole](https://github.com/ShaunLawrie/PwshSpectreConsole) (optional, for rich terminal output)
- Google Workspace: Service account with domain-wide delegation
- Active Directory: Domain-joined machine or RSAT tools
- Microsoft Cloud: App registration with appropriate Graph API permissions

## Quick Start

```powershell
Import-Module ./PSGuerrilla.psd1

# Store credentials in the encrypted vault
Set-Safehouse -Setup

# Google Workspace scan
Set-Safehouse -ServiceAccountKeyPath './sa-key.json' -AdminEmail 'admin@domain.com'
$gws = Invoke-Recon

# Active Directory audit
$ad = Invoke-Reconnaissance -Category All

# Entra ID / M365 infiltration audit
$entra = Invoke-Infiltration

# Unified campaign across all theaters
$campaign = Invoke-Campaign

# Review findings
$ad | Get-DeadDrop -MinimumThreatLevel HIGH

# Send alerts
$campaign | Send-Signal
```

## Core Functions

### Assessments

| Function | Description |
|----------|-------------|
| `Invoke-Recon` | Google Workspace compromise assessment with 23 behavioral detection signals |
| `Invoke-Fortification` | Google Workspace security configuration audit (8 categories) |
| `Invoke-Reconnaissance` | Active Directory security audit across 10 categories |
| `Invoke-Infiltration` | Entra ID, Azure, Intune, and M365 security assessment (159 checks) |
| `Invoke-Campaign` | Unified audit across all theaters in a single run |

### Continuous Monitoring

| Function | Description |
|----------|-------------|
| `Invoke-Surveillance` | Entra ID sign-in risk and directory change monitoring via Graph API |
| `Invoke-Watchtower` | Active Directory baseline monitoring with drift detection |
| `Invoke-Wiretap` | M365 audit log monitoring (Exchange, SharePoint, Teams, Defender, Power Platform) |

### Credential & Configuration Management

| Function | Description |
|----------|-------------|
| `Set-Safehouse` | Manage encrypted vault, credentials, rotation, and module configuration |
| `Get-Safehouse` | View vault status, stored credentials, and current configuration |

### Alerting

Dispatch alerts through 9 providers. Each has a dedicated function or use `Send-Signal` to route automatically.

| Function | Provider |
|----------|----------|
| `Send-Signal` | Auto-route to configured provider(s) |
| `Send-SignalSendGrid` | SendGrid email |
| `Send-SignalMailgun` | Mailgun email |
| `Send-SignalTwilio` | Twilio SMS |
| `Send-SignalTeams` | Microsoft Teams (Adaptive Cards) |
| `Send-SignalSlack` | Slack (Block Kit) |
| `Send-SignalWebhook` | Generic webhook / SIEM ingestion |
| `Send-SignalPagerDuty` | PagerDuty with severity mapping |
| `Send-SignalSyslog` | Syslog in CEF or LEEF format |
| `Send-SignalEventLog` | Windows Event Log |
| `Send-SignalDigest` | Aggregated daily/weekly digest |

### Scoring & Analysis

| Function | Description |
|----------|-------------|
| `Get-GuerrillaScore` | Composite security score (0-100) with tier labels |
| `Get-QuickWins` | Highest impact, lowest effort fixes ranked by ROI |
| `Get-ComplianceCrosswalk` | Map findings to FERPA, COPPA, CIPA, NIST 800-171, state ed-tech |
| `Set-RiskAcceptance` | Accept risk on specific checks with justification and expiry |
| `Get-RiskAcceptance` | List active/expired risk acceptances |
| `Get-TrendReport` | Score-over-time trend analysis from scan history |

### Reports

| Function | Description |
|----------|-------------|
| `Export-ExecutiveSummary` | Board-ready one-pager (HTML) |
| `Export-TechnicalReport` | Full findings with current vs recommended values and remediation |
| `Export-RemediationPlaybook` | Step-by-step guide organized by phase and priority |
| `Export-RemediationScripts` | Generate runnable PowerShell fix scripts from findings |
| `Export-BudgetJustification` | Cost justification document for leadership |
| `Export-Dashboard` | Unified HTML dashboard across all theaters |
| `Export-ReportPdf` | Convert HTML reports to PDF via Edge/Chrome headless |

### Scheduling

| Function | Description |
|----------|-------------|
| `Register-Patrol` | Create scheduled scan tasks with interval and alert dispatch |
| `Unregister-Patrol` | Remove scheduled tasks |
| `Get-Patrol` | View task status, last run, next run |

## Security Score Tiers

| Score | Tier |
|-------|------|
| 90-100 | FORTRESS |
| 75-89 | DEFENDED POSITION |
| 60-74 | CONTESTED GROUND |
| 40-59 | EXPOSED FLANK |
| 20-39 | UNDER SIEGE |
| 0-19 | OVERRUN |

## Configuration

PSGuerrilla uses a JSON config file generated by the [PSGuerrilla Configuration Website](https://guerrilla.army) or manually created. The config controls which environments to audit, monitoring intervals, report formats, alerting channels, and compliance framework mappings.

```powershell
# Load a config file
Invoke-Campaign -ConfigFile './guerrilla-config.json'

# All public functions accept -ConfigFile
Invoke-Reconnaissance -ConfigFile './guerrilla-config.json' -Category PrivilegedAccounts, Kerberos
```

Credentials are stored in an encrypted vault using Microsoft SecretManagement and SecretStore:

```powershell
# Initial vault setup
Set-Safehouse -Setup

# Store credentials
Set-Safehouse -ServiceAccountKeyPath './sa-key.json' -AdminEmail 'admin@domain.com'
Set-Safehouse -GraphClientId 'app-id' -GraphTenantId 'tenant-id' -GraphClientSecret $secret

# Rotate credentials
Set-Safehouse -RotateVaultPassword

# View what's stored (without revealing secrets)
Get-Safehouse
```

## Module Structure

```
PSGuerrilla/
  PSGuerrilla.psd1              # Module manifest
  PSGuerrilla.psm1              # Root module (loader)
  PSGuerrilla.format.ps1xml     # Custom table formatters
  Config/                        # JSON schema and defaults
  Data/                          # Threat intel, audit check definitions, compliance crosswalks
    AuditChecks/                 # 32 JSON files defining all security checks
  Public/                        # 40 exported functions
  Private/                       # 222 internal functions
    AD/                          # Active Directory collection and checks
    ADMonitor/                   # AD continuous monitoring and detections
    Audit/                       # Shared audit framework
    Console/                     # Themed terminal output and Spectre integration
    Core/                        # Detection engine, IP classification, state management
    Entra/                       # Entra ID / Azure / Intune / M365 checks
    EntraMonitor/                # Entra ID continuous monitoring
    Export/                      # Report generation (HTML, CSV, JSON)
    Google/                      # Google Workspace API integration
    Graph/                       # Microsoft Graph API integration
    M365Monitor/                 # M365 audit log monitoring
    Vault/                       # SecretManagement vault integration
  Tests/                         # Pester 5 unit and integration tests
```

## Migration from PSRecon

PSGuerrilla automatically migrates your PSRecon configuration on first load. All old command names (`Invoke-GoogleRecon`, `Get-ReconAlerts`, `Send-ReconAlert`, `Set-ReconConfig`, etc.) continue to work as aliases with deprecation warnings.

## Author

**Jim Tyler** — Microsoft MVP

- GitHub: [github.com/jimrtyler](https://github.com/jimrtyler)
- LinkedIn: [linkedin.com/in/jamestyler](https://linkedin.com/in/jamestyler)
- YouTube: [youtube.com/@jimrtyler](https://youtube.com/@jimrtyler)

## License

[MIT](LICENSE)
