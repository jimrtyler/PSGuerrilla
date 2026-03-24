# Changelog

## [2.0.0] - 2026-02-27

### Changed
- **Renamed module from PSRecon to PSGuerrilla** with guerrilla warfare-themed cmdlet names
- `Invoke-GoogleRecon` -> `Invoke-Recon`
- `Get-ReconAlerts` -> `Get-DeadDrop`
- `Send-ReconAlert` -> `Send-Signal`
- `Send-ReconAlertSendGrid` -> `Send-SignalSendGrid`
- `Send-ReconAlertMailgun` -> `Send-SignalMailgun`
- `Send-ReconAlertTwilio` -> `Send-SignalTwilio`
- `Set-ReconConfig` -> `Set-Safehouse`
- `Get-ReconConfig` -> `Get-Safehouse`
- `Register-ReconScheduledTask` -> `Register-Patrol`
- `Unregister-ReconScheduledTask` -> `Unregister-Patrol`
- `Get-ReconScheduledTask` -> `Get-Patrol`
- Reorganized Private functions into subdirectories: `Core/`, `Google/`, `Export/`, `Console/`
- Updated all type names: `PSRecon.*` -> `PSGuerrilla.*`
- Updated config/state paths: `$APPDATA/PSRecon` -> `$APPDATA/PSGuerrilla`
- Updated scheduled task name: `PSRecon-ScheduledScan` -> `PSGuerrilla-Patrol`
- Updated all branding strings and alert content

### Added
- Backward-compatible aliases for all 11 old PSRecon function names
- Automatic config migration from `$APPDATA/PSRecon` to `$APPDATA/PSGuerrilla`
- MIT License
- This changelog

## [1.0.0] - 2026-02-01

### Added
- Initial release as PSRecon
- Google Workspace compromise assessment via Admin Reports API
- 7 threat detection signals (known attacker IPs, cloud IP logins, reauth from cloud, risky actions, suspicious country logins, OAuth from cloud, cloud-only logins)
- Threat scoring engine with CRITICAL/HIGH/MEDIUM/LOW/Clean levels
- Incremental scanning with watermark-based state tracking
- HTML, CSV, and JSON report generation
- Alert dispatching via SendGrid, Mailgun, and Twilio SMS
- Scheduled task registration for automated scanning
- GeoIP enrichment via ip-api.com batch API
- CIDR-based cloud provider IP classification (AWS + general cloud/hosting)
- Known attacker IP database with exact-match detection
- Suspicious country login detection (19 countries)
- Config management with JSON persistence
