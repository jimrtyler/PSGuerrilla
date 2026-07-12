# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# Verifies that scan cmdlets fall back to the safehouse vault (default keys) for
# credentials when no -ConfigFile / parameters / config.json values are supplied.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'Vault credential fallback' {

    Context 'Invoke-GWSAudit (Google Workspace)' {
        It 'resolves the service account + admin email from the vault default keys' {
            InModuleScope Guerrilla {
                Mock Get-SafehouseSecret {
                    switch ($VaultKey) {
                        'GUERRILLA_GWS_SA'             { '{"type":"service_account","client_email":"sa@x.iam","private_key":"k"}' }
                        'GUERRILLA_GWS_SA_ADMIN_EMAIL' { 'admin@test.com' }
                        default                        { $null }
                    }
                }
                Mock Get-GWSScopes { @('scope1') }
                Mock Write-OperationHeader {}
                Mock Write-ProgressLine {}
                # First real call after credential validation — throwing here proves
                # validation passed with the vault-resolved creds.
                Mock Get-GoogleAccessToken { throw 'SENTINEL_AUTH_REACHED' }

                $missing = Join-Path ([IO.Path]::GetTempPath()) "psg-noexist-$([guid]::NewGuid()).json"
                { Invoke-GWSAudit -Quiet -ConfigPath $missing } | Should -Throw '*SENTINEL_AUTH_REACHED*'
                Should -Invoke Get-SafehouseSecret -ParameterFilter { $VaultKey -eq 'GUERRILLA_GWS_SA' }
            }
        }

        It 'still throws the required-parameter error when the vault is empty' {
            InModuleScope Guerrilla {
                Mock Get-SafehouseSecret { $null }
                Mock Write-OperationHeader {}
                Mock Write-ProgressLine {}
                $missing = Join-Path ([IO.Path]::GetTempPath()) "psg-noexist-$([guid]::NewGuid()).json"
                { Invoke-GWSAudit -Quiet -ConfigPath $missing } | Should -Throw '*ServiceAccountKeyPath is required*'
            }
        }

        It 'does not consult the vault when ServiceAccountKeyPath is passed explicitly' {
            InModuleScope Guerrilla {
                Mock Get-SafehouseSecret { $null }
                Mock Get-GWSScopes { @('scope1') }
                Mock Write-OperationHeader {}
                Mock Write-ProgressLine {}
                Mock Get-GoogleAccessToken { throw 'SENTINEL_AUTH_REACHED' }
                $missing = Join-Path ([IO.Path]::GetTempPath()) "psg-noexist-$([guid]::NewGuid()).json"
                { Invoke-GWSAudit -ServiceAccountKeyPath 'C:\k.json' -AdminEmail 'a@b.com' -Quiet -ConfigPath $missing } |
                    Should -Throw '*SENTINEL_AUTH_REACHED*'
                Should -Invoke Get-SafehouseSecret -Times 0
            }
        }
    }

    Context 'Invoke-EntraAudit (Entra / Azure / M365)' {
        It 'resolves tenant/client/secret from the vault default keys' {
            InModuleScope Guerrilla {
                Mock Get-SafehouseSecret {
                    switch ($VaultKey) {
                        'GUERRILLA_GRAPH_TENANT'   { 'tenant-guid' }
                        'GUERRILLA_GRAPH_CLIENTID' { 'client-guid' }
                        'GUERRILLA_GRAPH_SECRET'   { 'super-secret' }
                        default                    { $null }
                    }
                }
                Mock Write-OperationHeader {}
                Mock Write-ProgressLine {}
                Mock Get-GraphAccessToken { throw 'SENTINEL_GRAPH_REACHED' }

                $missing = Join-Path ([IO.Path]::GetTempPath()) "psg-noexist-$([guid]::NewGuid()).json"
                { Invoke-EntraAudit -Quiet -ConfigPath $missing } | Should -Throw '*SENTINEL_GRAPH_REACHED*'
                Should -Invoke Get-SafehouseSecret -ParameterFilter { $VaultKey -eq 'GUERRILLA_GRAPH_TENANT' }
            }
        }

        It 'still throws the required-parameter error when the vault is empty' {
            InModuleScope Guerrilla {
                Mock Get-SafehouseSecret { $null }
                Mock Write-OperationHeader {}
                Mock Write-ProgressLine {}
                $missing = Join-Path ([IO.Path]::GetTempPath()) "psg-noexist-$([guid]::NewGuid()).json"
                { Invoke-EntraAudit -Quiet -ConfigPath $missing } | Should -Throw '*TenantId is required*'
            }
        }
    }

    Context 'Invoke-Campaign (all platforms)' {
        It 'feeds vault-resolved creds into the Workspace and Cloud platforms' {
            InModuleScope Guerrilla {
                Mock Get-SafehouseSecret {
                    switch ($VaultKey) {
                        'GUERRILLA_GWS_SA'             { '{"type":"service_account","client_email":"sa@x","private_key":"k"}' }
                        'GUERRILLA_GWS_SA_ADMIN_EMAIL' { 'admin@test.com' }
                        'GUERRILLA_GRAPH_TENANT'       { 'tenant-guid' }
                        'GUERRILLA_GRAPH_CLIENTID'     { 'client-guid' }
                        'GUERRILLA_GRAPH_SECRET'       { 'super-secret' }
                        default                        { $null }
                    }
                }
                $finding = [pscustomobject]@{ CheckId = 'T-1'; Severity = 'Low'; Status = 'PASS'; Category = 'Test' }
                Mock Invoke-GWSAudit { [pscustomobject]@{ Findings = @($finding); OverallScore = 50 } }
                Mock Invoke-EntraAudit { [pscustomobject]@{ Findings = @($finding); OverallScore = 50 } }
                Mock Get-AuditPostureScore { [pscustomobject]@{ OverallScore = 50; CategoryScores = @{} } }
                Mock Get-AuditScoreLabel { 'Elevated Risk' }
                Mock Write-OperationHeader {}
                Mock Write-ProgressLine {}
                Mock Write-CampaignReport {}
                Mock Export-CampaignReportHtml {}
                Mock Export-CampaignReportCsv {}
                Mock Export-CampaignReportJson {}

                $missing = Join-Path ([IO.Path]::GetTempPath()) "psg-noexist-$([guid]::NewGuid()).json"
                Invoke-Campaign -Platforms Workspace, Cloud -Quiet -ConfigPath $missing | Out-Null

                Should -Invoke Invoke-GWSAudit -Times 1 -ParameterFilter {
                    $ServiceAccountKeyPath -and $AdminEmail -eq 'admin@test.com'
                }
                Should -Invoke Invoke-EntraAudit -Times 1 -ParameterFilter {
                    $TenantId -eq 'tenant-guid' -and $ClientId -eq 'client-guid'
                }
            }
        }
    }
}
