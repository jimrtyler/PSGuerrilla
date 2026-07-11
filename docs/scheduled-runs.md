# Running Guerrilla on a cadence

Guerrilla does not run in the background. There is no agent, no service, no
scheduler inside the module, and nothing resident. You run it, and the report
tells you what changed: every completed assessment is recorded to a local,
per-user run history on your machine (no accounts, no telemetry, no network),
and the next run's report opens with the comparison, including newly failing
checks, confirmed remediations, and any check that went dark.

If you want that comparison on a rhythm, use your operating system's
scheduler. The examples below run a full campaign weekly; swap in
`Invoke-ADAudit`, `Invoke-EntraAudit`, or `Invoke-GWSAudit` for a single
platform. Credentials come from the Safehouse vault (`Set-Safehouse`), so the
scheduled command needs no secrets on its command line.

## Windows (Task Scheduler)

```powershell
$action = New-ScheduledTaskAction -Execute 'pwsh.exe' `
    -Argument '-NoProfile -Command "Import-Module Guerrilla; Invoke-Campaign -Quiet"'
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
Register-ScheduledTask -TaskName 'Guerrilla Weekly Assessment' `
    -Action $action -Trigger $trigger
```

Run it as the same user who ran `Set-Safehouse`: the vault and the run history
are per-user. Remove it any time with
`Unregister-ScheduledTask -TaskName 'Guerrilla Weekly Assessment'`.

## macOS and Linux (cron)

```
# crontab -e
# Every Monday at 06:00
0 6 * * 1 pwsh -NoProfile -Command "Import-Module Guerrilla; Invoke-Campaign -Quiet" >> "$HOME/guerrilla-cron.log" 2>&1
```

macOS users who prefer launchd can wrap the same command in a LaunchAgent; the
module does not care how it is invoked.

## What you get

Each scheduled run writes its reports to the configured output directory and
appends one small record to the run history. Open the newest HTML report and
the "What Changed Since Last Run" section is at the top: newly failing checks
first, then anything that lost visibility, then confirmed remediations, with
the score delta overall and per Zero Trust pillar. A crashed or partial run is
never recorded, so it can never poison the comparison baseline.

That is the whole story. Guerrilla stays a point-in-time assessment tool; the
cadence belongs to you and your scheduler.
