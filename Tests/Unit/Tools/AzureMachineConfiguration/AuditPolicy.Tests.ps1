BeforeAll {
    . "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\AuditPackage.ps1"
    . "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\AuditPolicy.ps1"

    function New-TestAuditPackage
    {
        param
        (
            [Parameter(Mandatory = $true)]
            [string]
            $Path,

            [Parameter()]
            [string]
            $Type = 'Audit',

            [Parameter()]
            [string]
            $Version = '1.0.0'
        )

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        if (Test-Path -LiteralPath $Path)
        {
            Remove-Item -LiteralPath $Path -Force
        }

        $archive = [System.IO.Compression.ZipFile]::Open(
            $Path,
            [System.IO.Compression.ZipArchiveMode]::Create
        )

        try
        {
            $packageName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
            $metadataEntry = $archive.CreateEntry("$packageName.metaconfig.json")
            $metadataStream = $metadataEntry.Open()
            $writer = [System.IO.StreamWriter]::new($metadataStream)

            try
            {
                $writer.Write((@{
                    Type    = $Type
                    Version = $Version
                } | ConvertTo-Json -Compress))
            }
            finally
            {
                $writer.Dispose()
                $metadataStream.Dispose()
            }

            $configurationEntry = $archive.CreateEntry("$packageName.mof")
            $configurationStream = $configurationEntry.Open()
            $writer = [System.IO.StreamWriter]::new($configurationStream)

            try
            {
                $writer.Write('/* compiled configuration */')
            }
            finally
            {
                $writer.Dispose()
                $configurationStream.Dispose()
            }
        }
        finally
        {
            $archive.Dispose()
        }
    }

    function New-TestAuditPolicyDefinition
    {
        param
        (
            [Parameter(Mandatory = $true)]
            [string]
            $Path,

            [Parameter(Mandatory = $true)]
            [string]
            $ContentUri,

            [Parameter(Mandatory = $true)]
            [guid]
            $PolicyId,

            [Parameter(Mandatory = $true)]
            [string]
            $ContentHash,

            [Parameter()]
            [string]
            $Effect = 'auditIfNotExists'
        )

        @{
            name       = $PolicyId.ToString()
            properties = @{
                metadata   = @{
                    guestConfiguration = @{
                        name                    = 'SampleAudit'
                        version                 = '1.0.0'
                        contentType             = 'Custom'
                        contentUri              = $ContentUri
                        contentHash             = $ContentHash
                        contentManagedIdentity = 'system'
                    }
                }
                policyRule = @{
                    then = @{
                        effect  = $Effect
                        details = @{
                            type               = 'Microsoft.GuestConfiguration/guestConfigurationAssignments'
                            existenceCondition = @{
                                field  = 'Microsoft.GuestConfiguration/guestConfigurationAssignments/complianceStatus'
                                equals = 'Compliant'
                            }
                        }
                    }
                }
            }
        } | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path
    }
}

Describe 'Test-PowerStigAuditPolicyDefinition' {
    BeforeEach {
        $script:packagePath = Join-Path -Path $TestDrive -ChildPath 'SampleAudit.zip'
        $script:policyPath = Join-Path -Path $TestDrive -ChildPath 'SampleAudit_AuditIfNotExists.json'
        $script:contentUri = 'https://storage.example.invalid/packages/SampleAudit.zip'
        $script:policyId = [guid]'5a5ea870-561e-4e88-b675-b5bb4f4369d5'
        New-TestAuditPackage -Path $script:packagePath
        $package = Test-PowerStigAuditPackage -PackagePath $script:packagePath
        New-TestAuditPolicyDefinition `
            -Path $script:policyPath `
            -ContentUri $script:contentUri `
            -PolicyId $script:policyId `
            -ContentHash $package.PackageSha256
    }

    It 'accepts an AuditIfNotExists definition bound to the exact package hash and URI' {
        $result = Test-PowerStigAuditPolicyDefinition `
            -PolicyPath $script:policyPath `
            -PackagePath $script:packagePath `
            -ContentUri $script:contentUri `
            -ExpectedPolicyId $script:policyId

        $result.Effect | Should -Be 'auditIfNotExists'
        $result.AssignmentType | Should -Be 'Audit'
        $result.PackageSha256 | Should -Be (Get-FileHash -LiteralPath $script:packagePath -Algorithm SHA256).Hash
        $result.ContentIdentity | Should -Be 'system'
    }

    It 'rejects a policy definition with an apply effect' {
        $package = Test-PowerStigAuditPackage -PackagePath $script:packagePath
        New-TestAuditPolicyDefinition `
            -Path $script:policyPath `
            -ContentUri $script:contentUri `
            -PolicyId $script:policyId `
            -ContentHash $package.PackageSha256 `
            -Effect 'deployIfNotExists'

        {
            Test-PowerStigAuditPolicyDefinition `
                -PolicyPath $script:policyPath `
                -PackagePath $script:packagePath `
                -ContentUri $script:contentUri `
                -ExpectedPolicyId $script:policyId
        } | Should -Throw '*Policy effect must be auditIfNotExists*'
    }

    It 'rejects a definition with a package hash that differs from the ZIP' {
        New-TestAuditPolicyDefinition `
            -Path $script:policyPath `
            -ContentUri $script:contentUri `
            -PolicyId $script:policyId `
            -ContentHash ('0' * 64)

        {
            Test-PowerStigAuditPolicyDefinition `
                -PolicyPath $script:policyPath `
                -PackagePath $script:packagePath `
                -ContentUri $script:contentUri `
                -ExpectedPolicyId $script:policyId
        } | Should -Throw '*content hash does not match*'
    }

    It 'rejects non-HTTPS and query-token package URIs' {
        {
            Test-PowerStigAuditPolicyDefinition `
                -PolicyPath $script:policyPath `
                -PackagePath $script:packagePath `
                -ContentUri 'http://storage.example.invalid/SampleAudit.zip' `
                -ExpectedPolicyId $script:policyId
        } | Should -Throw '*HTTPS URI*'

        {
            Test-PowerStigAuditPolicyDefinition `
                -PolicyPath $script:policyPath `
                -PackagePath $script:packagePath `
                -ContentUri 'https://storage.example.invalid/SampleAudit.zip?sig=secret' `
                -ExpectedPolicyId $script:policyId
        } | Should -Throw '*query tokens*'
    }
}

Describe 'New-PowerStigAuditPolicyDefinition' {
    BeforeEach {
        $script:packagePath = Join-Path -Path $TestDrive -ChildPath 'SampleAudit.zip'
        $script:outputPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $script:contentUri = 'https://storage.example.invalid/packages/SampleAudit.zip'
        $script:policyId = [guid]'d99d3941-18a8-498c-84d9-ae8ab8459b3a'
        New-TestAuditPackage -Path $script:packagePath
    }

    It 'does not replace an existing policy definition without Force' {
        $null = New-Item -Path $script:outputPath -ItemType Directory -Force
        $policyPath = Join-Path -Path $script:outputPath -ChildPath 'SampleAudit_AuditIfNotExists.json'
        Set-Content -LiteralPath $policyPath -Value 'preserve this file' -NoNewline

        {
            New-PowerStigAuditPolicyDefinition `
                -PackagePath $script:packagePath `
                -ContentUri $script:contentUri `
                -DisplayName 'Sample Audit' `
                -Description 'Audit the sample configuration.' `
                -PolicyId $script:policyId `
                -OutputPath $script:outputPath
        } | Should -Throw '*Policy definition already exists*'

        Get-Content -LiteralPath $policyPath -Raw | Should -Be 'preserve this file'
    }

    It 'rejects a package URI containing a query token before module loading' {
        {
            New-PowerStigAuditPolicyDefinition `
                -PackagePath $script:packagePath `
                -ContentUri 'https://storage.example.invalid/SampleAudit.zip?sig=secret' `
                -DisplayName 'Sample Audit' `
                -Description 'Audit the sample configuration.' `
                -PolicyId $script:policyId `
                -OutputPath $script:outputPath
        } | Should -Throw '*query tokens*'
    }

    $guestConfigurationInstalled = @(
        Get-Module -ListAvailable -Name GuestConfiguration |
            Where-Object -FilterScript { $PSItem.Version -eq [version]'4.10.0' }
    ).Count -gt 0

    It 'generates and validates an offline AuditIfNotExists policy using the pinned module' -Skip:(-not $guestConfigurationInstalled) {
        $result = New-PowerStigAuditPolicyDefinition `
            -PackagePath $script:packagePath `
            -ContentUri $script:contentUri `
            -DisplayName 'Sample Audit' `
            -Description 'Audit the sample configuration.' `
            -PolicyId $script:policyId `
            -OutputPath $script:outputPath

        $result.Effect | Should -Be 'auditIfNotExists'
        $result.AssignmentType | Should -Be 'Audit'
        $result.PolicyId | Should -Be $script:policyId
        Test-Path -LiteralPath $result.PolicyPath -PathType Leaf | Should -BeTrue
    }
}
