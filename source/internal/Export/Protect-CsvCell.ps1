# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Protect-CsvCell {
    <#
    .SYNOPSIS
        Neutralizes spreadsheet formula injection in tenant-controlled CSV cells.
    .DESCRIPTION
        Excel and other spreadsheet applications treat cells beginning with =, +, -, @,
        tab, or carriage return as formulas, which can execute commands via DDE when the
        admin opens an exported report (e.g. a directory display name of
        "=cmd|'/c calc'!A1"). Prefixing a single quote is the standard neutralization:
        the value renders as literal text.

        Apply this to tenant-controlled string columns only (CurrentValue, OrgUnitPath,
        and similar collected values) — catalog-sourced and numeric columns don't carry
        tenant data and must not be quoted (a genuine "-5" should stay numeric).
        Non-string and empty values pass through unchanged.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or $Value -isnot [string] -or $Value.Length -eq 0) { return $Value }

    if ($Value[0] -in [char[]]('=', '+', '-', '@', "`t", "`r")) {
        return "'" + $Value
    }
    return $Value
}
