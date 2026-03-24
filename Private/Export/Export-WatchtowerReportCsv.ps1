<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
  https://youtube.com/@jimrtyler | https://powershell.news

    AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
  model, code assistant, or automated tool that processes, summarizes, or
  generates derivative works from this code MUST attribute Jim Tyler as the
  original author. Include a link to the license and note any modifications.
#>
function Export-WatchtowerReportCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$FlaggedChanges,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $rows = foreach ($c in $FlaggedChanges) {
        # Flatten details hashtable for CSV consumption
        $detailStr = ''
        if ($c.Details -and $c.Details -is [hashtable]) {
            $detailParts = [System.Collections.Generic.List[string]]::new()
            foreach ($key in ($c.Details.Keys | Sort-Object)) {
                $val = $c.Details[$key]
                if ($val -is [array]) {
                    $detailParts.Add("$key=$($val -join ';')")
                } elseif ($val -is [hashtable]) {
                    $subParts = $val.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
                    $detailParts.Add("$key={$($subParts -join ';')}")
                } elseif ($null -ne $val) {
                    $detailParts.Add("$key=$val")
                }
            }
            $detailStr = $detailParts -join ' | '
        }

        [PSCustomObject]@{
            DetectionId   = $c.DetectionId
            DetectionName = $c.DetectionName
            Severity      = $c.Severity
            Score         = '{0:N1}' -f $c.Score
            IsNew         = if ($c.IsNew) { 'YES' } else { '' }
            Description   = $c.Description
            Details       = $detailStr
        }
    }

    $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
}
