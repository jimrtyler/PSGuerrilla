#requires -version 7.0
<#
.SYNOPSIS
    Publish golden-fixture test results to a local SQLite database for historical
    tracking (offline replacement for the retired Supabase publisher).

.DESCRIPTION
    Appends one guerrilla_test_runs summary row and one guerrilla_test_results row
    per check/scenario to a local SQLite file via the `sqlite3` CLI. The database is
    created (with schema) on first use, so a fresh machine works with no setup. The
    default path is outside the repo; nothing here talks to the network.

    Schema mirrors the former Supabase tables (guerrilla_test_runs + guerrilla_test_results)
    so the migrated history and new runs live in one file.

.PARAMETER Summary
    Run-level metadata + totals (suite, git_sha, git_branch, host, runner, total,
    passed, failed, duration_ms, module_version).

.PARAMETER Results
    Per-check result objects (CheckId, Family, Theater, Scenario, Severity,
    ExpectedStatus, ActualStatus, Passed, FixtureFile, Description).

.PARAMETER DbPath
    SQLite file to append to. Defaults to
    ~/Documents/PSGuerrilla-Data/psguerrilla_supabase_backup.sqlite (the migrated
    local copy), so publishing continues that history.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][hashtable]$Summary,
    [Parameter(Mandatory)][object[]]$Results,
    [string]$DbPath = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Documents' 'PSGuerrilla-Data' 'psguerrilla_supabase_backup.sqlite')
)

$ErrorActionPreference = 'Stop'

$sqlite = Get-Command sqlite3 -ErrorAction SilentlyContinue
if (-not $sqlite) { throw "sqlite3 CLI not found on PATH. Install it (macOS ships it at /usr/bin/sqlite3) or pass a machine that has it." }

$dbDir = Split-Path -Parent $DbPath
if ($dbDir -and -not (Test-Path $dbDir)) { New-Item -ItemType Directory -Path $dbDir -Force | Out-Null }

# --- SQL value escaping ---
function Convert-SqlText($v) { if ($null -eq $v -or "$v" -eq '') { 'NULL' } else { "'" + ("$v" -replace "'", "''") + "'" } }
function Convert-SqlInt($v)  { if ($null -eq $v -or "$v" -eq '') { 'NULL' } else { [string][int64]$v } }
function Convert-SqlBool($v) { if ($v) { '1' } else { '0' } }

$schema = @'
CREATE TABLE IF NOT EXISTS guerrilla_test_runs (
  id TEXT PRIMARY KEY, created_at TEXT NOT NULL, suite TEXT NOT NULL DEFAULT 'golden-fixtures',
  git_sha TEXT, git_branch TEXT, host TEXT, runner TEXT,
  total INTEGER NOT NULL, passed INTEGER NOT NULL, failed INTEGER NOT NULL,
  duration_ms INTEGER, module_version TEXT
);
CREATE TABLE IF NOT EXISTS guerrilla_test_results (
  id INTEGER PRIMARY KEY, run_id TEXT NOT NULL, created_at TEXT NOT NULL,
  check_id TEXT NOT NULL, family TEXT NOT NULL, theater TEXT, scenario TEXT NOT NULL,
  severity TEXT, expected_status TEXT NOT NULL, actual_status TEXT NOT NULL,
  passed INTEGER NOT NULL, fixture_file TEXT, description TEXT
);
CREATE INDEX IF NOT EXISTS idx_gtr_run_id   ON guerrilla_test_results (run_id);
CREATE INDEX IF NOT EXISTS idx_gtr_check_id ON guerrilla_test_results (check_id);
'@

# Ensure schema exists, then read the current max result id (for stable explicit ids).
& $sqlite.Source $DbPath $schema
$maxId = [int64](& $sqlite.Source $DbPath 'SELECT COALESCE(MAX(id),0) FROM guerrilla_test_results;')

$runId = [guid]::NewGuid().ToString()
$now   = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

if (-not $PSCmdlet.ShouldProcess($DbPath, "insert run $runId + $($Results.Count) result rows")) { return }

$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('BEGIN;')
[void]$sb.AppendLine((
    "INSERT INTO guerrilla_test_runs (id,created_at,suite,git_sha,git_branch,host,runner,total,passed,failed,duration_ms,module_version) VALUES (" +
    (@(
        (Convert-SqlText $runId), (Convert-SqlText $now), (Convert-SqlText ($Summary.suite ?? 'golden-fixtures')),
        (Convert-SqlText $Summary.git_sha), (Convert-SqlText $Summary.git_branch), (Convert-SqlText $Summary.host),
        (Convert-SqlText $Summary.runner), (Convert-SqlInt $Summary.total), (Convert-SqlInt $Summary.passed),
        (Convert-SqlInt $Summary.failed), (Convert-SqlInt $Summary.duration_ms), (Convert-SqlText $Summary.module_version)
    ) -join ',') + ");"
))

# Bulk-insert result rows in chunks with explicit incrementing ids.
$id = $maxId
$cols = 'INSERT INTO guerrilla_test_results (id,run_id,created_at,check_id,family,theater,scenario,severity,expected_status,actual_status,passed,fixture_file,description) VALUES'
$chunk = [System.Collections.Generic.List[string]]::new()
$flush = {
    if ($chunk.Count) { [void]$sb.AppendLine("$cols`n" + ($chunk -join ",`n") + ';'); $chunk.Clear() }
}
foreach ($r in $Results) {
    $id++
    $chunk.Add('(' + (@(
        [string]$id, (Convert-SqlText $runId), (Convert-SqlText $now),
        (Convert-SqlText $r.CheckId), (Convert-SqlText $r.Family), (Convert-SqlText $r.Theater),
        (Convert-SqlText $r.Scenario), (Convert-SqlText $r.Severity), (Convert-SqlText $r.ExpectedStatus),
        (Convert-SqlText $r.ActualStatus), (Convert-SqlBool $r.Passed), (Convert-SqlText $r.FixtureFile),
        (Convert-SqlText $r.Description)
    ) -join ',') + ')')
    if ($chunk.Count -ge 400) { & $flush }
}
& $flush
[void]$sb.AppendLine('COMMIT;')

# Run the whole transaction from a temp SQL file (avoids arg-length limits).
$tmp = [System.IO.Path]::GetTempFileName()
try {
    Set-Content -Path $tmp -Value $sb.ToString() -Encoding utf8
    Get-Content -Raw $tmp | & $sqlite.Source $DbPath
    if ($LASTEXITCODE -ne 0) { throw "sqlite3 insert failed (exit $LASTEXITCODE) for $DbPath" }
} finally {
    Remove-Item $tmp -ErrorAction SilentlyContinue
}

Write-Host "Inserted run $runId"
Write-Host "Published $($Results.Count) result rows to $DbPath (guerrilla_test_results)."
[PSCustomObject]@{ RunId = $runId; RowCount = $Results.Count; DbPath = $DbPath }
