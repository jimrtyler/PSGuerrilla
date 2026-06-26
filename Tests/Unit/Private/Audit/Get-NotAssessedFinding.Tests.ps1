# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Guards the "absence of evidence != compliance" contract: a check whose source
# data failed to collect must report Not Assessed (SKIP), never PASS.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla

    $script:Def = @{ id = 'ADTRUST-001'; name = 'Trust Relationships'; severity = 'High' }
}

Describe 'Get-NotAssessedFinding' {
    It 'returns a SKIP finding when the source key failed to collect' {
        $f = Get-NotAssessedFinding -CheckDefinition $script:Def `
            -ErrorMap @{ TrustRelationships = 'LDAP bind failed' } `
            -SourceKey 'TrustRelationships' -Subject 'trust relationships'
        $f | Should -Not -BeNullOrEmpty
        $f.Status | Should -Be 'SKIP'
        $f.CurrentValue | Should -Match 'Not Assessed'
        $f.CurrentValue | Should -Match 'LDAP bind failed'
        $f.Details.NotAssessed | Should -BeTrue
        $f.Details.FailedSource | Should -Be 'TrustRelationships'
    }

    It 'returns $null when the source was collected (no error recorded)' {
        $f = Get-NotAssessedFinding -CheckDefinition $script:Def `
            -ErrorMap @{} -SourceKey 'TrustRelationships' -Subject 'trust relationships'
        $f | Should -BeNullOrEmpty
    }

    It 'returns $null for an unrelated error key' {
        $f = Get-NotAssessedFinding -CheckDefinition $script:Def `
            -ErrorMap @{ DomainInfo = 'x' } -SourceKey 'TrustRelationships' -Subject 'trust relationships'
        $f | Should -BeNullOrEmpty
    }

    It 'inspects multiple error maps and trips on any of them' {
        $f = Get-NotAssessedFinding -CheckDefinition $script:Def `
            -ErrorMap @($null, @{ Domains = 'graph 429' }) `
            -SourceKey @('Organization', 'Domains') -Subject 'tenant config'
        $f.Status | Should -Be 'SKIP'
    }

    It 'matches per-entity error keys by prefix (Google dynamic keys)' {
        $f = Get-NotAssessedFinding -CheckDefinition $script:Def `
            -ErrorMap @{ 'GmailSettings:user@x' = 'graph 500' } `
            -SourceKeyPrefix 'GmailSettings:' -Subject 'mailbox settings'
        $f.Status | Should -Be 'SKIP'
    }

    It 'does not trip a prefix that no key matches' {
        $f = Get-NotAssessedFinding -CheckDefinition $script:Def `
            -ErrorMap @{ 'Users' = 'x' } `
            -SourceKeyPrefix 'GmailSettings:' -Subject 'mailbox settings'
        $f | Should -BeNullOrEmpty
    }

    It 'ignores non-dictionary (array-style) Errors without throwing' {
        $f = Get-NotAssessedFinding -CheckDefinition $script:Def `
            -ErrorMap @(, @('some string error')) `
            -SourceKey 'TrustRelationships' -Subject 'trust relationships'
        $f | Should -BeNullOrEmpty
    }
}

Describe 'AD trust checks honour collection failure' {
    It 'SKIPs (Not Assessed) instead of PASS when trust enumeration failed' {
        $audit = @{ Trusts = @(); Errors = @{ TrustRelationships = 'LDAP enumeration failed' } }
        $f = Test-ReconADTRUST001 -AuditData $audit -CheckDefinition $script:Def
        $f.Status | Should -Be 'SKIP'
    }

    It 'still PASSes when collection succeeded and there are genuinely zero trusts' {
        $audit = @{ Trusts = @(); Errors = @{} }
        $f = Test-ReconADTRUST001 -AuditData $audit -CheckDefinition $script:Def
        $f.Status | Should -Be 'PASS'
    }
}

Describe 'Invoke-GraphApi fail-loud contract' {
    It 'THROWS on retry-exhausted failure by default (so the collector records it)' {
        Mock Invoke-RestMethod -ModuleName PSGuerrilla { throw 'network down' }
        { Invoke-GraphApi -AccessToken 'x' -Uri '/organization' -MaxRetries 1 } |
            Should -Throw
    }

    It 'returns $null on the same failure when -ReturnNullOnError is set (monitor path)' {
        Mock Invoke-RestMethod -ModuleName PSGuerrilla { throw 'network down' }
        $r = Invoke-GraphApi -AccessToken 'x' -Uri '/organization' -MaxRetries 1 -ReturnNullOnError -WarningAction SilentlyContinue
        $r | Should -BeNullOrEmpty
    }
}

Describe 'Scorer excludes Not-Assessed categories' {
    It 'does not credit an all-SKIP category as 100' {
        $findings = @(
            New-AuditFinding -CheckDefinition @{ id = 'A'; name = 'a'; severity = 'High'; _categoryName = 'Trusts' } -Status 'SKIP'
            New-AuditFinding -CheckDefinition @{ id = 'B'; name = 'b'; severity = 'High'; _categoryName = 'Trusts' } -Status 'SKIP'
        )
        $score = Get-AuditPostureScore -Findings $findings
        $score.CategoryScores['Trusts'].Evaluated | Should -BeFalse
    }
}
