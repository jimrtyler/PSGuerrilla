@{
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # Intentional: Write-Host used for themed console UI output
        'PSAvoidUsingWriteHost',
        # Allow ConvertTo-SecureString for API auth tokens (not user passwords)
        'PSAvoidUsingConvertToSecureStringWithPlainText'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('7.0')
        }
    }
}
