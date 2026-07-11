# Effective state and audit-log inference

Status: idea record. Written at the removal of the behavioral monitoring subsystem
(Surveillance, Watchtower, Wiretap, Lookout, Recon, Signal, Patrol). Guerrilla is a
point-in-time assessment tool with a best-in-class report; it does not run in the
background. The one monitoring capability that survives is run-over-run comparison,
as a report feature. This page preserves the ideas from the removed code that are
worth building later, and records where the code went.

Removal commit: 272bca4 ("Remove the behavioral monitoring subsystem: assess,
score, compare, report"). Everything referenced below as removed lives at the
parent of that commit; `git show 272bca4^:<path>` exhumes any file.

## Idea 1: audit-log evidence for controls with no configuration API

Some controls cannot be read from any config API (the Gemini class in Google
Workspace). The living template is `ConvertTo-GeminiDerivedSettings` plus section
12b of `Get-GWSAuditData.ps1`: replay `CHANGE_*_SETTING` admin audit events, take
the most recent `NEW_VALUE` per setting, and honor an explicit honesty contract.
Inference is not a config read: a setting unseen within log retention is ABSENT and
the check verdict is SKIP (surfaced as Not Assessed), never a guess. Two hard-won
tenant facts live in that file: Google abbreviates the Gemini family as `gen_ai_*`,
and setting events can fire under `CHANGE_CHROME_OS_USER_SETTING`, so the event
match must be broad. Future work extends this pattern to more API-less controls
rather than reintroducing resident monitoring.

## Idea 2: config-declared vs. actually-happened reconciliation

The unbuilt join. The removed `Test-WorkspaceSettingChange` captured OLD_VALUE,
NEW_VALUE, and ORG_UNIT_NAME per admin settings change; the removed
`Test-M365AuditLogDisablement` classified audit-control property transitions into
disabled, reduced (retention shortened, cmdlet audit scope narrowed), and bypass.
Nothing ever joined a config snapshot to these observed transitions. A future
assessment enrichment: for a check that reads declared config, also scan the audit
log for recent changes to that setting and report "declared X, changed from Y three
days ago by actor Z". Same collectors, no scheduler, still point-in-time.

## Idea 3: visibility loss is a finding

The removed `Test-EntraAuditLogGap` flagged inter-event silence of 24 hours or more
in a log that should never be quiet: absence of evidence as the finding itself.
This idea now ships in reduced form as the run-comparison NEWLY NOT ASSESSED
transition class (a check that went dark is never rendered as no change). The full
form, gap detection inside audit logs plus attributable logging-sabotage detection
from property transitions, remains future work on the assessment side.

## Exhumation index: the 15 GWS behavioral detectors

Pure functions (events in, findings out) removed with the subsystem; the logic is
worth exhuming, not the architecture. Effective-state readers: Test-2svDisablement
(2SV turned off, admin-vs-self), Test-AdminAction (sensitive role grants),
Test-DomainWideDelegation (dangerous-scope DWD grants), Test-EmailForwarding
(forwarding/routing persistence), Test-UserSuspension (incl. UNDELETE_USER
anti-forensics), Test-DriveExternalSharing (effective external sharing vs. domain),
Test-WorkspaceSettingChange (see idea 2), Test-HighRiskOAuthApp (three-tier consent
risk). Anomaly scorers: Test-ImpossibleTravel (Haversine, min-hop 100 km, clamped
delta-t, default 900 km/h), Test-BruteForce (sliding window, the SuccessAfter flag
that separates compromise from noise), Test-AfterHoursLogin, Test-ConcurrentSessions
(sorted-IP-set dedup key), Test-BulkFileDownload (fired-window skip),
Test-NewDevice (device_id/user-agent fingerprint baseline persisted across runs),
Test-UserAgentAnomaly (automation UA blocklist). The Reports API plumbing they rode
on (`Invoke-GoogleReportsApi`, pagination, backoff, param flattening) survives on
the audit side.

## Margin note: the localization stub

`Get-LocalizedString` and `Data/Localization/en-US.json` died in the same removal
as unreachable code. What existed: dot-notation key lookup into a cached per-locale
table with en-US fallback and return-the-key-itself on miss, 125 keys covering
report headings, common verdict labels, score, risk, remediation, PDF, and module
names. No report code ever called it. If report i18n is rebuilt, start from that
key inventory in git history rather than re-deriving the surface.
