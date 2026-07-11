# Contributing to Guerrilla

Guerrilla is a community project. The contributors it needs most are often
practitioners who will never open a pull request: the administrator who notices
a verdict is wrong, the responder who just cleaned up an incident no baseline
names yet, the engineer whose tenant is shaped in a way no fixture covers. Those
contributions are worth as much as code, and **every rung on this ladder is
credited in the release notes.** You do not have to write PowerShell to make
Guerrilla better.

This guide is a ladder, not a pull-request manual. Start at whatever rung fits
the time and the tools you have.

---

## Rung 1: Run Guerrilla and report a wrong verdict

The single most valuable thing you can do is tell us when a check is wrong. A
check that passes a tenant it should fail, fails one it should pass, or reports a
score on something it could not actually see: that is a bug, and we want it.

You do not need a repro script or a stack trace. You need the story:
- which check (the ID from the report, like `EIDCA-003`, or just what it was
  about),
- what it said,
- what the real state of your tenant is,
- and how you know.

Open a **[Report a wrong verdict](../../issues/new?template=report-wrong-verdict.yml)**
issue and tell it in plain language. A maintainer turns your report into a
fixture (see [the fixture framework](https://guerrilla.army/docs/validation)),
which both proves the fix and makes sure the verdict never regresses. You are
credited for the catch.

## Rung 2: Propose a check, with the incident that motivated it

If you have seen an attack path or a misconfiguration Guerrilla does not catch,
propose it. The best proposals come with a story: the real-world incident, the
red-team finding, or the audit gap that made you wish the tool had flagged it.
That story is what tells a maintainer the check is worth building and what
"known-bad" actually looks like.

Open a **[Propose a check](../../issues/new?template=propose-a-check.yml)** issue.
Describe what should be checked, why it matters, what a passing tenant looks
like, what a failing one looks like, and the incident behind it. You do not need
to know how to implement it. Proposals that become checks are credited.

## Rung 3: Contribute fixture data from an unusual tenant shape

Guerrilla is only as honest as the tenant states it has been tested against, and
real tenants are stranger than any maintainer invents. If your environment has a
shape we probably have not modeled, a federation topology, a licensing edge, a
policy set that behaves unexpectedly, that shape is valuable as a fixture.

A fixture is a small, sanitized snapshot of the relevant configuration with the
verdict you expect written down. You can contribute the raw shape and the
expected answer even if you do not write the fixture file yourself: open a
**[Contribute fixture data](../../issues/new?template=contribute-fixture.yml)**
issue, describe the shape, and paste the relevant (scrubbed) configuration.
Remove anything sensitive: real names, tenant IDs, secrets. We only need the
structure and the values that drive the verdict.

This rung is the on-ramp to rung 4. Once you have a tenant shape and an expected
verdict, [the fixture walkthrough](https://guerrilla.army/docs/validation) shows
exactly how it becomes a fixture file, step by step, with a real example.

## Rung 4: Write the check and its fixtures

If you want to write the check yourself, welcome. A contributed check ships with
its fixtures. That requirement is not bureaucracy: it is the thing that lets a
maintainer accept a check from someone they have never met. The fixtures prove
the verdict logic is right without the maintainer needing your tenant in front of
them. A check without fixtures cannot be reviewed, so it cannot be merged.

The shape of a check contribution:

1. **Define the check** in the right `Data/AuditChecks/*.json` file:

   ```json
   {
     "id": "EIDCA-021",
     "name": "Short human title",
     "description": "What is evaluated and, briefly, why.",
     "severity": "High",
     "subcategory": "Policy Configuration",
     "zeroTrustPillar": "Identity",
     "zeroTrustWeight": 2,
     "recommendedValue": "What the secure state looks like.",
     "remediationSteps": "Numbered, concrete remediation.",
     "compliance": {
       "nistSp80053": ["AC-2"],
       "mitreAttack": ["T1078"],
       "scuba": ["MS.AAD.3.1v1"]
     }
   }
   ```

   Every check must declare a `zeroTrustPillar` and `zeroTrustWeight`; the Zero
   Trust schema test enforces it. Only claim a `compliance` mapping the check
   actually implements against the current published control.

2. **Write the check function**. It receives the collected audit data and the
   definition, and returns a finding. The three outcomes are not optional:
   clean input returns `PASS`, the misconfiguration returns `FAIL` (or `WARN`
   where the control warns), and input it could not collect returns `SKIP`,
   which the report renders as **Not Assessed**. Never return a pass for data
   you could not read.

   ```powershell
   function Test-EIDCA021 {
       [CmdletBinding()]
       param([hashtable]$AuditData, [hashtable]$CheckDefinition)

       $ca = $AuditData.ConditionalAccess
       if (-not $ca -or -not $ca.Policies) {
           return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
               -CurrentValue 'Conditional Access data not available'
       }
       $status = if ($secureCondition) { 'PASS' } else { 'FAIL' }
       return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
           -CurrentValue 'Human-readable summary of what was found'
   }
   ```

3. **Write the fixtures.** At minimum: a clean case that must `PASS`, a
   known-bad case that must `FAIL` (or `WARN`), and an uncollectable case that
   must be `Not Assessed`. Each is a JSON file under `Tests/Fixtures/`:

   ```json
   {
     "checkId": "EIDCA-021",
     "scenario": "known-bad",
     "expectedStatus": "FAIL",
     "description": "One line on what this shape represents",
     "auditData": { "ConditionalAccess": { "Policies": [ /* the shape */ ] } }
   }
   ```

   The walkthrough at [guerrilla.army/docs/validation](https://guerrilla.army/docs/validation)
   works a real check through all three, line by line.

4. **Run the suite** and confirm your fixtures pass:

   ```powershell
   pwsh Tests/Invoke-FixtureTests.ps1
   ```

   The same suite gates every release; it must be green.

---

## Why every check ships with fixtures

The fixture is what makes a stranger's check safe to accept. It is a synthetic
tenant state driven through the real check function with the expected verdict
written down in advance, so anyone can prove the logic is right without access to
your environment, and so a later change that breaks the verdict turns the build
red before it can merge. It is also what lets the website state, per check, that
the verdict is tested rather than merely asserted. A check with no fixtures is a
claim with no evidence, and Guerrilla does not ship those.

## Credit

Every rung is credited in the release notes: the wrong-verdict report, the check
proposal, the contributed tenant shape, and the code. If you would prefer not to
be named, say so in the issue.

---

## Developer reference

For rung-4 contributors, the details behind the shapes above.

### Where things live

```
Public/                 Exported cmdlets (Invoke-ADAudit, Invoke-EntraAudit, ...)
Private/
  AD/                   Active Directory collection and checks
  Entra/                Entra ID / Azure / Intune / M365 collectors and checks
  Google/  Graph/       API integration (Google Workspace, Microsoft Graph, Azure RM)
  Audit/                Shared audit framework (New-AuditFinding, scoring)
  Console/              Themed console output (Write-GuerrillaText, etc.)
  Export/               Report generation (HTML, CSV, JSON)
Data/AuditChecks/       JSON check definitions (the source of truth for metadata)
Tests/
  Fixtures/             Golden fixtures, one file per check per scenario
  Unit/                 Pester 5 unit tests (ZeroTrustSchema, collector contracts)
  Invoke-FixtureTests.ps1   The golden-fixture gate
```

### Conventions

- Public cmdlets use the platform vocabulary (`Invoke-ADAudit`,
  `Invoke-EntraAudit`, `Invoke-GWSAudit`, `Invoke-Campaign`,
  `Set-Safehouse`).
- Check functions are named `Test-<Platform><CheckId>` and are dispatched
  automatically; no registration step.
- Findings are built with `New-AuditFinding`; do not construct result objects by
  hand.
- Public functions do not call raw `Write-Host`; use the themed helpers in
  `Private/Console/` and honor `-Quiet`.

### The gate

Three suites run in CI before every release and a red run blocks the merge:

1. the golden fixtures (verdict logic, `Tests/Invoke-FixtureTests.ps1`),
2. the collector query-contract tests (that each collector requests the exact API
   endpoints and parameters its check reads),
3. the Zero Trust schema test (that every check declares a pillar and weight).

Run PSScriptAnalyzer before you push:

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .PSScriptAnalyzerSettings.psd1
```

### AI-assisted contributions

If you used an AI assistant to help write a contribution, see
[AI-USAGE.md](./AI-USAGE.md) for the attribution this project asks for.
</content>
