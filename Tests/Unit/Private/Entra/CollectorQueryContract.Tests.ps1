# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Collector query-contract tests.
#
# These pin the *shape of the data the collectors fetch from Graph* — the one
# thing the golden-fixture harness structurally cannot check. Golden fixtures
# feed a hand-built $AuditData straight to a check function; the collector is
# never invoked, so a collector that queries the wrong endpoint (or omits an
# $expand) sails past every fixture while producing false verdicts on a live
# tenant. Each assertion below corresponds to a confirmed live verdict defect:
#
#   EIDTNT-005  false PASS   — container fetched, /default never collected
#   INTUNE-005  false FAIL   — deviceConfigurations fetched without $expand=assignments
#   EIDPIM-010  false FAIL   — scheduleInstances queried instead of schedules
#
# We mock Invoke-GraphApi and assert the exact URIs/parameters requested.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' '..' 'Helpers' 'TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Collector query contracts' {

    Context 'Get-EntraTenantData — cross-tenant access' {
        BeforeAll {
            Mock -ModuleName PSGuerrilla Invoke-GraphApi {
                if ($Uri -like '*crossTenantAccessPolicy/default') {
                    return [pscustomobject]@{
                        b2bCollaborationInbound  = [pscustomobject]@{ usersAndGroups = [pscustomobject]@{ accessType = 'blocked'; targets = @() } }
                        b2bCollaborationOutbound = [pscustomobject]@{ usersAndGroups = [pscustomobject]@{ accessType = 'blocked'; targets = @() } }
                    }
                }
                if ($Uri -like '*crossTenantAccessPolicy') { return [pscustomobject]@{ id = 'default' } }
                return $null
            }
            $script:tenant = InModuleScope PSGuerrilla { Get-EntraTenantData -AccessToken 'x' -Quiet }
        }

        It 'fetches the /default cross-tenant access policy (not just the container)' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 1 -Exactly -ParameterFilter {
                $Uri -eq '/policies/crossTenantAccessPolicy/default'
            }
        }

        It 'exposes the default policy under .CrossTenantAccess.default so EIDTNT-005 can read b2bCollaboration*' {
            $tenant.CrossTenantAccess.default | Should -Not -BeNullOrEmpty
            $tenant.CrossTenantAccess.default.b2bCollaborationInbound | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Get-IntuneData — device configuration profiles' {
        BeforeAll {
            Mock -ModuleName PSGuerrilla Invoke-GraphApi { return @() }
            InModuleScope PSGuerrilla { Get-IntuneData -AccessToken 'x' -Quiet } | Out-Null
        }

        It 'requests deviceConfigurations with $expand=assignments (else INTUNE-005 false-FAILs)' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 1 -Exactly -ParameterFilter {
                $Uri -eq '/deviceManagement/deviceConfigurations' -and
                $QueryParameters -and $QueryParameters['$expand'] -eq 'assignments'
            }
        }
    }

    Context 'Get-EntraPIMData — eligible role assignments' {
        BeforeAll {
            Mock -ModuleName PSGuerrilla Invoke-GraphApi { return @() }
            InModuleScope PSGuerrilla { Get-EntraPIMData -AccessToken 'x' -Quiet } | Out-Null
        }

        It 'queries roleEligibilitySchedules (definitions), which carry standing eligibility' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 1 -Exactly -ParameterFilter {
                $Uri -eq '/roleManagement/directory/roleEligibilitySchedules'
            }
        }

        It 'does NOT use roleEligibilityScheduleInstances for the eligibility source (0 instances => false "PIM not configured")' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 0 -Exactly -ParameterFilter {
                $Uri -eq '/roleManagement/directory/roleEligibilityScheduleInstances'
            }
        }
    }
}
