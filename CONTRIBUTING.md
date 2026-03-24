# Contributing to PSGuerrilla

## Project Structure

```
PSGuerrilla/
  PSGuerrilla.psm1          # Module loader (auto-loads all Private/ functions recursively)
  PSGuerrilla.psd1          # Module manifest
  PSGuerrilla.format.ps1xml # Custom format views

  Public/                   # Exported cmdlets
    Invoke-Recon.ps1        # Phase 1 — Google Workspace compromise assessment
    Invoke-Reconnaissance.ps1 # Phase 2 — Active Directory security audit
    Invoke-Infiltration.ps1 # Phase 3 — Entra ID / Azure / Intune / M365 audit
    Invoke-Campaign.ps1     # Unified — combined report across all theaters

  Private/
    Core/                   # Detection engine, state management, IP classification
    Google/                 # Google Workspace API integration
    AD/                     # Active Directory data collection & checks
    Graph/                  # Microsoft Graph & Azure RM API integration
      Get-GraphAccessToken.ps1        # MSAL-based token acquisition (client secret, cert, device code)
      Invoke-GraphApi.ps1             # Graph REST wrapper (pagination, throttling, batch)
      Invoke-AzureRMApi.ps1           # Azure Resource Manager REST wrapper
      Test-GraphModuleAvailability.ps1 # Check for MSAL.PS, EXO, Teams, PnP modules
    Entra/                  # Entra ID / Azure / Intune / M365 checks
      Core/                 # Data collection functions (10 collectors)
        Get-InfiltrationData.ps1              # Main orchestrator
        Get-EntraConditionalAccessData.ps1    # CA policies + named locations
        Get-EntraAuthMethodsData.ps1          # Auth methods, MFA, SSPR
        Get-EntraPIMData.ps1                  # Role assignments, PIM config
        Get-EntraApplicationData.ps1          # Apps, SPs, consent grants
        Get-EntraFederationData.ps1           # Federated domains, sync config
        Get-EntraTenantData.ps1               # Org settings, security defaults
        Get-AzureIAMData.ps1                  # Azure subscription IAM
        Get-IntuneData.ps1                    # Device management policies
        Get-M365ServiceData.ps1               # EXO, SPO, Teams, Defender, Audit
      Checks/               # Check execution (14 check files, ~159 checks)
        Invoke-EntraCAChecks.ps1              # 16 Conditional Access checks
        Invoke-EntraAuthChecks.ps1            # 17 Authentication Methods checks
        Invoke-EntraPIMChecks.ps1             # 14 PIM checks
        Invoke-EntraAppChecks.ps1             # 19 Application Security checks
        Invoke-EntraFedChecks.ps1             # 12 Federation checks
        Invoke-EntraTenantChecks.ps1          # 13 Tenant Configuration checks
        Invoke-AzureIAMChecks.ps1             # 10 Azure IAM checks
        Invoke-IntuneChecks.ps1               # 22 Intune/Endpoint checks
        Invoke-M365ExchangeChecks.ps1         # 12 Exchange Online checks
        Invoke-M365SharePointChecks.ps1       # 5 SharePoint/OneDrive checks
        Invoke-M365TeamsChecks.ps1            # 8 Teams checks
        Invoke-M365DefenderChecks.ps1         # 3 Defender for O365 checks
        Invoke-M365AuditChecks.ps1            # 3 Unified Audit checks
        Invoke-M365PowerPlatformChecks.ps1    # 3 Power Platform checks
    Audit/                  # Shared audit framework
    Export/                 # Report generation (CSV, HTML, JSON, alert formatting)
    Console/                # ANSI-themed console output helpers

  Data/
    AuditChecks/            # JSON check definition files (AD, Entra, Azure, M365)
  Tests/
    Unit/                   # Unit tests mirroring source structure
    Integration/            # End-to-end pipeline tests
    Helpers/                # Mock factories and test utilities
```

## Naming Conventions

### Guerrilla-themed names (public-facing)

| Concept | Name Pattern | Examples |
|---------|-------------|----------|
| Google scan | `Invoke-Recon` | The reconnaissance sweep |
| AD audit | `Invoke-Reconnaissance` | AD fortification assessment |
| Cloud audit | `Invoke-Infiltration` | Entra/Azure/Intune/M365 infiltration audit |
| **Unified audit** | **`Invoke-Campaign`** | **Combined report across all theaters** |
| Alerts | `Send-Signal` / `Send-Signal*` | Dispatching intel signals |
| Alert retrieval | `Get-DeadDrop` | Picking up dead drop intel |
| Configuration | `Set-Safehouse` / `Get-Safehouse` | Safehouse = config location |
| Scheduled tasks | `Register-Patrol` / `Get-Patrol` | Patrol = recurring sweep |
| Reports | `Export-FieldReport*` | Field reports from the field |
| AD reports | `Export-FortificationReport*` | AD fortification reports |
| Cloud reports | `Export-InfiltrationReport*` | Infiltration assessment reports |
| **Unified reports** | **`Export-CampaignReport*`** | **Combined campaign reports** |
| Alert content | `Format-SignalContent` | Formatting signal dispatches |
| Score labels | `Get-GuerrillaScoreLabel` | Org-wide posture label |

### Technical names (private/internal)

Private functions that perform technical operations keep descriptive names:
- `Get-ThreatScore`, `Get-CloudIpClassification`, `New-UserCompromiseProfile`
- Google API functions keep `Google` prefix: `Get-GoogleAccessToken`, `New-GoogleJwt`
- Graph API functions keep `Graph` prefix: `Get-GraphAccessToken`, `Invoke-GraphApi`
- Azure ARM functions: `Invoke-AzureRMApi`
- Data collectors: `Get-Entra*Data`, `Get-AzureIAMData`, `Get-IntuneData`, `Get-M365ServiceData`
- Check functions: `Test-Infiltration{CheckId}` (e.g., `Test-InfiltrationEIDCA001`)

### Type names

- `PSGuerrilla.ScanResult` — output of `Invoke-Recon`
- `PSGuerrilla.UserProfile` — per-user compromise profile
- `PSGuerrilla.AlertResult` — output of `Send-Signal`
- `PSGuerrilla.ReconnaissanceResult` — output of `Invoke-Reconnaissance` (AD audit)
- `PSGuerrilla.InfiltrationResult` — output of `Invoke-Infiltration` (cloud audit)
- `PSGuerrilla.AuditFinding` — individual check result (used by Phase 2 and Phase 3)
- `PSGuerrilla.CampaignResult` — output of `Invoke-Campaign` (unified audit)

## Writing Tests

### Requirements

- Every new function needs a corresponding `.Tests.ps1` file
- Tests use Pester 5 syntax (`Describe`, `Context`, `It`, `Should`)
- Use mock factories from `Tests/Helpers/TestHelpers.psm1`

### Test file template

```powershell
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Function-Name' {
    Context 'Scenario' {
        It 'expected behavior' {
            # Arrange
            # Act
            # Assert
        }
    }
}
```

### Mock factories available

- `New-MockLoginEvent` — login event hashtable
- `New-MockTokenEvent` — OAuth token event hashtable
- `New-MockAdminEvent` — admin action event hashtable
- `New-MockScanResult` — PSGuerrilla.ScanResult object
- `New-MockUserProfile` — PSGuerrilla.UserProfile object
- `New-MockConfig` — full config hashtable
- `New-MockAuditFinding` — PSGuerrilla.AuditFinding object (Phase 2/3)
- `New-MockGraphToken` — Graph API access token (Phase 3)
- `New-MockEntraData` — Entra ID data collection hashtable (Phase 3)

### Running tests

```powershell
# All tests
Invoke-Pester ./Tests -Output Detailed

# Specific test file
Invoke-Pester ./Tests/Unit/Private/Core/Get-ThreatScore.Tests.ps1 -Output Detailed

# With code coverage
Invoke-Pester ./Tests -CodeCoverage ./Private/*, ./Public/*
```

## Code Quality

### PSScriptAnalyzer

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .PSScriptAnalyzerSettings.psd1
```

Excluded rules:
- `PSAvoidUsingWriteHost` — intentional for themed console UI
- `PSAvoidUsingConvertToSecureStringWithPlainText` — needed for API auth tokens

### Console output

All user-facing console output should use the themed helpers in `Private/Console/`:
- `Write-GuerrillaText` — colored text with ANSI codes
- `Write-ProgressLine` — timestamped phase lines
- `Write-OperationHeader` — operation start box
- `Write-FieldReport` — scan results summary
- `Write-InterceptAlert` — new threat alerts

Do not use raw `Write-Host` in public functions. Use `-Quiet` parameter to suppress output.

### Color palette

| Name | Use |
|------|-----|
| Olive | Primary text |
| Amber | Alerts, warnings |
| Sage | OK status, passing |
| Parchment | Headers |
| Gold | Scores, metrics |
| Dim | Timestamps, secondary |
| DeepOrange | HIGH threat level |
| DarkRed | CRITICAL threat level |

## Adding New Detection Signals

1. Create a `Test-*` function in `Private/Core/`
2. Add the signal weight to `Get-ThreatScore`
3. Add profile fields to `New-UserCompromiseProfile`
4. Write unit tests for the new signal
5. Update `Set-Safehouse` if the signal needs configuration

## Adding New Alert Providers

1. Create `Send-Signal<Provider>` in `Public/`
2. Add provider routing in `Send-Signal.ps1`
3. Add provider config in `Set-Safehouse.ps1`
4. Write unit tests
5. Update the module manifest `FunctionsToExport`

## Phase 3: Infiltration Audit Architecture

### Overview

Phase 3 (`Invoke-Infiltration`) audits Microsoft cloud identity and service configurations:

| Category | Check Count | Check ID Prefix | Data Source |
|----------|------------|-----------------|-------------|
| Conditional Access | 16 | EIDCA | `Get-EntraConditionalAccessData` |
| Authentication Methods | 17 | EIDAUTH | `Get-EntraAuthMethodsData` |
| Privileged Identity Mgmt | 14 | EIDPIM | `Get-EntraPIMData` |
| Application Security | 19 | EIDAPP | `Get-EntraApplicationData` |
| Federation & Hybrid | 12 | EIDFED | `Get-EntraFederationData` |
| Tenant Configuration | 13 | EIDTNT | `Get-EntraTenantData` |
| Azure IAM | 10 | AZIAM | `Get-AzureIAMData` |
| Intune/Endpoint | 22 | INTUNE | `Get-IntuneData` |
| M365 Services | 34 | M365EXO/SPO/TEAMS/DEF/AUDIT/PP | `Get-M365ServiceData` |

### Authentication

Uses `Get-GraphAccessToken` with MSAL.PS for Microsoft Graph API. Supports:
- **Client secret** — App-only with client credentials
- **Certificate** — App-only with X.509 certificate
- **Device code** — Delegated interactive flow
- **MSAL.PS** — Automatic flow selection via MSAL library

Azure IAM checks use separate `Invoke-AzureRMApi` wrapper for ARM endpoints.

### Adding a New Infiltration Check

1. Add the check definition to the appropriate `Data/AuditChecks/{Category}Checks.json`:
```json
{
    "id": "EIDCA-017",
    "name": "Check name",
    "description": "Detailed description of what is checked and why",
    "severity": "High",
    "subcategory": "Policy Configuration",
    "recommendedValue": "What the secure configuration looks like",
    "remediationSteps": "Step-by-step remediation guidance",
    "compliance": {
        "nistSp80053": ["AC-2"],
        "mitreAttack": ["T1078"],
        "cisBenchmark": ["1.1"],
        "cisM365": ["2.1"],
        "cisAzure": ["1.1"]
    }
}
```

2. Create the check function in the appropriate `Invoke-*Checks.ps1` file:
```powershell
function Test-InfiltrationEIDCA017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $ca = $AuditData.ConditionalAccess
    if (-not $ca -or -not $ca.Policies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'CA data not available'
    }

    # Evaluation logic here
    $status = if ($condition) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Human-readable summary" `
        -Details @{ Key = 'structured data' }
}
```

3. The check is automatically dispatched by the orchestrator — no registration needed.

### Compliance Framework Mappings

All check definitions support these compliance frameworks:

| Framework | JSON Key | Example Values |
|-----------|----------|---------------|
| NIST SP 800-53 | `nistSp80053` | `AC-2`, `IA-2(1)`, `CM-6` |
| MITRE ATT&CK | `mitreAttack` | `T1078.004`, `T1556` |
| CIS Benchmarks | `cisBenchmark` | `1.1.1`, `5.2.1` |
| CIS M365 Foundations | `cisM365` | `1.1`, `2.1`, `5.1.1` |
| CIS Azure | `cisAzure` | `1.1`, `2.1.1` |
| ANSSI | `anssi` | Rule references |
| NSA ASD | `nsaAsd` | Guidance references |
| CIS AD | `cisAd` | AD benchmark references |

### Data Collection Pattern

Data collectors follow the established pattern from `Get-ReconnaissanceData`:
- Each `Get-*Data` function returns a hashtable with named data and an `Errors` dictionary
- All Graph API calls are wrapped in try/catch with errors stored in `$data.Errors`
- The `Get-InfiltrationData` orchestrator calls collectors based on selected categories
- Progress output uses `Write-ProgressLine -Phase INFILTRATE`

### Reporting

Phase 3 generates reports matching the existing Phase 2 pattern:
- `Export-InfiltrationReportHtml` — Scored HTML with SVG progress ring and category cards
- `Export-InfiltrationReportCsv` — Flat CSV with all compliance framework columns
- `Export-InfiltrationReportJson` — Nested JSON with metadata and findings
- `Write-InfiltrationReport` — Themed console summary output

## Unified Campaign Audit

`Invoke-Campaign` runs any combination of the three audit phases and produces one combined report. Each phase is a "theater":

| Theater | Phase Function | Auth Required |
|---------|---------------|---------------|
| `Workspace` | `Invoke-Fortification` | Google service account key + admin email |
| `AD` | `Invoke-Reconnaissance` | AD domain access (optional server/credential) |
| `Cloud` | `Invoke-Infiltration` | Entra tenant ID + app client ID + secret/cert/device code |

### Usage

```powershell
# All three theaters
Invoke-Campaign -ServiceAccountKeyPath $key -AdminEmail $admin `
    -TenantId $tenant -ClientId $appId -DeviceCode

# Cloud + AD only (skip Google)
Invoke-Campaign -Theaters AD, Cloud -TenantId $t -ClientId $c -ClientSecret $s

# Single theater
Invoke-Campaign -Theaters Cloud -TenantId $t -ClientId $c -DeviceCode
```

### How It Works

1. Auto-detects theaters from provided credentials (or use explicit `-Theaters`)
2. Calls each phase function with `-NoReports -Quiet`
3. Tags findings with `Theater` NoteProperty (`Google Workspace`, `Active Directory`, `Microsoft Cloud`)
4. Merges all findings, scores with `Get-AuditPostureScore`
5. Generates unified HTML/CSV/JSON reports with theater sections

Individual phase commands (`Invoke-Fortification`, `Invoke-Reconnaissance`, `Invoke-Infiltration`) remain unchanged and produce their own separate reports.
