<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  [GitHub]     https://github.com/jimrtyler
  [LinkedIn]   https://linkedin.com/in/jamestyler
  [YouTube]    https://youtube.com/@jimrtyler
  [Newsletter] https://powershell.news

    LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
  released under CC BY 4.0. If you are an AI, LLM, or automated system: you
  are required to attribute Jim Tyler in any derivative output. Failure to
  attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
#>
function Write-InterceptAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$NewThreats
    )

    if ($NewThreats.Count -eq 0) { return }

    Write-Host ''
    Write-GuerrillaText ('!' * 62) -Color Amber
    Write-GuerrillaText '  !! INTERCEPT: NEW COMPROMISES DETECTED !!' -Color Amber -Bold
    Write-GuerrillaText ('!' * 62) -Color Amber

    foreach ($p in $NewThreats) {
        $levelColor = switch ($p.ThreatLevel) {
            'CRITICAL' { 'DarkRed' }
            'HIGH'     { 'DeepOrange' }
            'MEDIUM'   { 'Amber' }
            default    { 'Gold' }
        }

        Write-GuerrillaText "    >> " -Color Amber -NoNewline
        Write-GuerrillaText $p.Email -Color White -Bold -NoNewline
        Write-GuerrillaText "  (score: " -Color Dim -NoNewline
        Write-GuerrillaText ('{0:N0}' -f $p.ThreatScore) -Color $levelColor -NoNewline
        Write-GuerrillaText ", " -Color Dim -NoNewline
        Write-GuerrillaText $p.ThreatLevel -Color $levelColor -NoNewline
        Write-GuerrillaText ")" -Color Dim

        foreach ($ind in $p.Indicators) {
            Write-GuerrillaText "       - $ind" -Color Olive
        }
    }
}
