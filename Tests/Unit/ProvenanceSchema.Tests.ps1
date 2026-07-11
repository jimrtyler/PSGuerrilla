#requires -version 7.0
# Schema gate: every check declares its provenance at authoring time, and the
# provenance-specific fields are consistent. This is what lets the website's
# build-ahead register and Guerrilla-original section read from data instead of
# a hand-maintained list. An invalid or inconsistent provenance is a RED build.
#
#   baseline    : implements a control a published baseline already defines.
#   original    : an attack path no baseline models yet; carries no official_id.
#   build-ahead : derived from a published roadmap ahead of the control; MUST
#                 record source_url and source_read_date, and gains official_id
#                 later when the baseline catches up.

Describe 'Provenance check-definition schema' {
    It 'every check declares a valid provenance with consistent provenance fields' {
        $valid = @('baseline', 'original', 'build-ahead')
        $dataDir = (Resolve-Path (Join-Path $PSScriptRoot '..' '..' 'source' 'Data' 'AuditChecks')).Path
        $violations = [System.Collections.Generic.List[string]]::new()
        foreach ($file in Get-ChildItem -Path $dataDir -Filter *.json) {
            $json = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
            foreach ($c in @($json.checks)) {
                if (-not $c.id) { continue }
                # provenance / source_url / source_read_date / official_id must exist as fields.
                if (-not ($c.PSObject.Properties.Name -contains 'provenance')) {
                    $violations.Add("$($c.id): missing provenance field"); continue
                }
                $p = $c.provenance
                if ($p -notin $valid) {
                    $violations.Add("$($c.id): invalid provenance '$p'"); continue
                }
                if ($p -eq 'original' -and -not [string]::IsNullOrEmpty($c.official_id)) {
                    $violations.Add("$($c.id): provenance 'original' must not carry an official_id")
                }
                if ($p -eq 'build-ahead') {
                    if ([string]::IsNullOrEmpty($c.source_url)) {
                        $violations.Add("$($c.id): provenance 'build-ahead' requires source_url")
                    }
                    if ([string]::IsNullOrEmpty($c.source_read_date)) {
                        $violations.Add("$($c.id): provenance 'build-ahead' requires source_read_date")
                    }
                }
            }
        }
        if ($violations.Count) {
            throw "Provenance schema violations ($($violations.Count)):`n" + ($violations -join "`n")
        }
        $violations.Count | Should -Be 0
    }
}
