# PSGuerrilla — Live Validation Handoff (v2.12.0)

**For:** the validation Claude Code agent on the live-tenant server.
**Goal:** validate the Google Workspace work shipped in v2.11.0 → v2.12.0 against a real tenant, and send back the two things that can only be confirmed live: **(A) the real enum strings**, and **(B) whether more placeholders are convertible** (the full schema dump).

This release is **read-only** against Google Workspace — running everything below makes **no changes** to the tenant.

---

## 0. What changed since the last validation

- **GWS-1 conversions: now 33 real Cloud Identity policy checks** (was 26). v2.11.1 added EMAIL-018/019, DRIVE-010, ADMIN-010/011, COLLAB-004/008.
- **New cmdlet `Invoke-Lookout`** — Google Workspace configuration-drift monitor (baseline + drift), the GWS sibling of Watchtower/Surveillance/Wiretap.

---

## 1. Update & sanity

```powershell
Update-Module PSGuerrilla            # or: Install-Module PSGuerrilla -RequiredVersion 2.12.0 -Force
Import-Module PSGuerrilla -Force
(Get-Module PSGuerrilla).Version       # expect 2.12.0
Get-Command Invoke-Lookout             # expect it to resolve
```

## 2. Offline regression suites (no tenant needed)

```powershell
Get-ChildItem .\Tests\verify-gws1-*.ps1, .\Tests\verify-lookout.ps1 | ForEach-Object {
    "{0}: {1}" -f $_.Name, (pwsh -File $_.FullName | Select-Object -Last 1)
}
```
Expect every line to read `RESULT: N / N passed` (auth 20, admin 12, admin-p2 9, collab 17, collab-p2 12, drive 11, drive-p2 6, email 15, email-p2 7, device 4, logging 10, oauth 16, policy-collector 8, lookout 16).

## 3. Live Fortification — verify the 33 converted checks

```powershell
$f = Invoke-Fortification -ConfigFile .\guerrilla-config.json     # or vault-based
$ids = 'AUTH-003','AUTH-004','AUTH-005','AUTH-006','AUTH-008','AUTH-011',
       'EMAIL-013','EMAIL-015','EMAIL-016','EMAIL-017','EMAIL-018','EMAIL-019','EMAIL-020','EMAIL-021',
       'COLLAB-001','COLLAB-002','COLLAB-003','COLLAB-004','COLLAB-005','COLLAB-006','COLLAB-008',
       'DRIVE-001','DRIVE-004','DRIVE-008','DRIVE-010','OAUTH-001','OAUTH-006','OAUTH-007',
       'LOG-004','LOG-005','ADMIN-010','ADMIN-011','ADMIN-012'
$f.Findings | Where-Object CheckId -in $ids |
    Select-Object CheckId, Status, CurrentValue | Sort-Object CheckId | Format-Table -Wrap
```
**Pass criteria:** none still says *"verify in Admin Console"*; none returns `ERROR`; GWS total count is still **98**. Send the full table back.

## 4. ⭐ CRITICAL — confirm the enum strings (Item A)

These checks grade *known* values as PASS/FAIL but any *unrecognized* enum as **WARN** (never PASS). For each, report the **literal `setting.value` enum string** the tenant returns so the mappings can be tightened from WARN → clean PASS/FAIL.

| Check | Setting type | Field |
|---|---|---|
| AUTH-003 | `security.two_step_verification_enforcement_factor` | `allowedSignInFactorSet` |
| DRIVE-001 | `drive_and_docs.external_sharing` | `externalSharingMode` |
| COLLAB-002 | `meet.meet_joining` | `allowedAudience` |
| COLLAB-003 | `meet.safety_domain` | `usersAllowedToJoin` |
| COLLAB-004 | `chat.external_chat_restriction` | `externalChatRestriction` |
| COLLAB-008 | `calendar.primary_calendar_max_allowed_external_sharing` | `maxAllowedExternalSharing` |
| OAUTH-001 | `api_controls.unconfigured_third_party_apps` | `accessLevel` |
| OAUTH-006 | `api_controls.app_approval_requests` | `allowedForAll` |
| OAUTH-007 | `workspace_marketplace.apps_access_options` | `accessLevel` |
| ADMIN-011 | `groups_for_business.groups_sharing` | `createGroupsAccessLevel` |

Quick way to dump the actual values:
```powershell
$pol = (Get-FortificationData -ServiceAccountKeyPath <sa> -AdminEmail <admin>).CloudIdentityPolicies
foreach ($t in 'security.two_step_verification_enforcement_factor','drive_and_docs.external_sharing',
               'meet.meet_joining','meet.safety_domain','chat.external_chat_restriction',
               'calendar.primary_calendar_max_allowed_external_sharing',
               'api_controls.unconfigured_third_party_apps','api_controls.app_approval_requests',
               'workspace_marketplace.apps_access_options','groups_for_business.groups_sharing') {
    "$t => " + ((Get-GooglePolicySetting -Policies $pol -Type $t) | ConvertTo-Json -Depth 4 -Compress)
}
```
Report each type's raw value object.

## 5. ⭐ Find more convertibles — grep the full schema dump (Item B)

The local `raw/gws-policy-schemas.txt` (full 173 setting types) wasn't available when these were mapped. Grep it for setting types that would let us convert the **still-manual** placeholders, and report any matches (type + field shapes):

```powershell
Select-String -Path .\raw\gws-policy-schemas.txt -Pattern 'mobile|device|mdm|screen|encrypt|jailb|endpoint' # DEVICE-002..006/010
Select-String -Path .\raw\gws-policy-schemas.txt -Pattern 'directory|contact_sharing|profile'                # ADMIN-008/009
Select-String -Path .\raw\gws-policy-schemas.txt -Pattern 'chat.*app|app_install|appointment|invitation'     # COLLAB-007/009/010
Select-String -Path .\raw\gws-policy-schemas.txt -Pattern 'shared_drive|target_audience|offline'             # DRIVE-005/011/013
```

## 6. Live `Invoke-Lookout` test (the new monitor)

```powershell
# First run — establishes the baseline (read-only; no tenant changes)
$b = Invoke-Lookout -ConfigFile .\guerrilla-config.json
$b.BaselineEstablished   # expect True; $b.NewThreats should be empty

# Immediate second run — nothing changed, so no drift
$d = Invoke-Lookout -ConfigFile .\guerrilla-config.json
$d.BaselineEstablished   # expect False
$d | Select-Object TotalChangesDetected, @{n='NewThreats';e={$_.NewThreats.Count}}, ScoreChange, CurrentScore
# Expect TotalChangesDetected = 0 (no config changed between runs)

# (Optional, if you have a disposable OU) flip one benign setting in Admin Console, re-run,
# confirm exactly that control shows up in $d.NewFailures / $d.NewThreats, then revert.

# Re-baseline on demand
Invoke-Lookout -ConfigFile .\guerrilla-config.json -Force | Select-Object BaselineEstablished
```
**Pass criteria:** first run baselines, second run reports zero drift without error, `-Force` re-baselines. Confirm it wrote nothing to the tenant (it shouldn't — it only calls the read-only Fortification collection).

## 7. Graceful degradation

If you can point at a tenant/service-account **without** the `cloud-identity.policies.readonly` scope, confirm all 33 policy-backed checks return `SKIP` with the "scope not delegated" message (not ERROR, and the rest of the Google scan still runs).

---

## Report back

1. The §3 table (33 checks: CheckId / Status / CurrentValue).
2. **§4 enum strings** (the literal values) — this is the highest-value item.
3. **§5 schema-dump matches** — any types that unlock more conversions.
4. §6 Lookout results (baseline → second-run drift = 0; optional change-detection).
5. Any check returning `ERROR`, and the §7 SKIP behavior if you tested it.
