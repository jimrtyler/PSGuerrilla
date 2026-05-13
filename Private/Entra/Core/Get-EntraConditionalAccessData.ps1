# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-EntraConditionalAccessData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        Policies       = @()
        NamedLocations = @()
        Errors         = @{}
    }

    # ── Conditional Access Policies ────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Conditional Access policies'
    }
    try {
        $data.Policies = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/identity/conditionalAccess/policies' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['Policies'] = $_.Exception.Message
        Write-Warning "Failed to collect CA policies: $($_.Exception.Message)"
    }

    # ── Named Locations ───────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting named locations'
    }
    try {
        $data.NamedLocations = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/identity/conditionalAccess/namedLocations' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['NamedLocations'] = $_.Exception.Message
        Write-Warning "Failed to collect named locations: $($_.Exception.Message)"
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message "Collected $($data.Policies.Count) CA policies, $($data.NamedLocations.Count) named locations"
    }

    return $data
}
