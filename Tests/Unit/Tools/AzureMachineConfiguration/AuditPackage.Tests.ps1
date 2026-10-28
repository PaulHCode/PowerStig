BeforeAll {
    . "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\AuditPackage.ps1"

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
}

Describe 'Test-PowerStigAuditPackage' {
    BeforeEach {
        $script:packagePath = Join-Path -Path $TestDrive -ChildPath 'SampleAudit.zip'
        New-TestAuditPackage -Path $script:packagePath
    }

    It 'accepts a structurally valid Audit package and returns its hash and sizes' {
        $result = Test-PowerStigAuditPackage -PackagePath $script:packagePath -ExpectedVersion '1.0.0'

        $result.Type | Should -Be 'Audit'
        $result.Version | Should -Be '1.0.0'
        $result.PackageSha256 | Should -Match '^[A-F0-9]{64}$'
        $result.ExpandedSizeBytes | Should -BeGreaterThan 0
        $result.EntryCount | Should -Be 2
        $result.ConfigurationMofName | Should -Be 'SampleAudit.mof'
        $result.ConfigurationMofSha256 | Should -Match '^[A-F0-9]{64}$'
    }

    It 'rejects packages that include AuditAndSet metadata' {
        New-TestAuditPackage -Path $script:packagePath -Type 'AuditAndSet'

        {
            Test-PowerStigAuditPackage -PackagePath $script:packagePath
        } | Should -Throw '*Package type must be Audit*'
    }

    It 'rejects a package with a missing compiled MOF' {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open(
            $script:packagePath,
            [System.IO.Compression.ZipArchiveMode]::Update
        )

        try
        {
            $null = $archive.GetEntry('SampleAudit.mof').Delete()
        }
        finally
        {
            $archive.Dispose()
        }

        {
            Test-PowerStigAuditPackage -PackagePath $script:packagePath
        } | Should -Throw '*missing its compiled configuration*'
    }

    It 'rejects packages over the configured expanded-size limit' {
        {
            Test-PowerStigAuditPackage -PackagePath $script:packagePath -MaximumExpandedBytes 1
        } | Should -Throw '*Expanded package size exceeds*'
    }
}

Describe 'New-PowerStigAuditPackage' {
    BeforeEach {
        $script:mofPath = Join-Path -Path $TestDrive -ChildPath 'Configuration.mof'
        Set-Content -LiteralPath $script:mofPath -Value '/* compiled configuration */'
        $script:outputPath = Join-Path -Path $TestDrive -ChildPath 'output'
    }

    It 'requests an Audit package from the pinned GuestConfiguration version and validates it' {
        Mock Import-PowerStigGuestConfiguration {}
        Mock Invoke-PowerStigGuestConfigurationPackage {
            $packageParameters = $PackageParameters
            New-TestAuditPackage `
                -Path (Join-Path -Path $packageParameters.Path -ChildPath "$($packageParameters.Name).zip") `
                -Version $packageParameters.Version
        }

        $result = New-PowerStigAuditPackage `
            -Name 'SampleAudit' `
            -ConfigurationMofPath $script:mofPath `
            -OutputPath $script:outputPath

        $result.Type | Should -Be 'Audit'
        $result.Version | Should -Be '1.0.0'
        Should -Invoke Import-PowerStigGuestConfiguration -ParameterFilter {
            $Version -eq '4.10.0'
        } -Times 1
        Should -Invoke Invoke-PowerStigGuestConfigurationPackage -ParameterFilter {
            $Version -eq '4.10.0' -and
            $PackageParameters.Type -eq 'Audit' -and
            $PackageParameters.Name -eq 'SampleAudit' -and
            $PackageParameters.Version -eq '1.0.0' -and
            $PackageParameters.Configuration -eq $script:mofPath
        } -Times 1
    }

    Describe 'Pinned GuestConfiguration package command dispatch' {
        BeforeAll {
            function Invoke-TestPinnedPackage { $script:selectedCommand = 'Pinned' }
            function Invoke-TestOtherPackage { $script:selectedCommand = 'OtherVersion' }
            function New-GuestConfigurationPackage { $script:selectedCommand = 'UnqualifiedShadow' }
        }

        BeforeEach {
            $script:selectedCommand = $null
            $script:loadedPackageModules = @(
                [pscustomobject]@{
                    Version = [version]'4.10.0'
                    ExportedCommands = @{ 'New-GuestConfigurationPackage' = Get-Command Invoke-TestPinnedPackage }
                },
                [pscustomobject]@{
                    Version = [version]'1.19.4'
                    ExportedCommands = @{ 'New-GuestConfigurationPackage' = Get-Command Invoke-TestOtherPackage }
                }
            )
            Mock Get-Module { $script:loadedPackageModules } -ParameterFilter { $Name -eq 'GuestConfiguration' }
        }

        It 'invokes the exact pinned module export even when another version and a shadow command are present' {
            Invoke-PowerStigGuestConfigurationPackage -PackageParameters @{} -Version '4.10.0'
            $script:selectedCommand | Should -BeExactly 'Pinned'
        }

        It 'honors an explicitly requested tool version' {
            Invoke-PowerStigGuestConfigurationPackage -PackageParameters @{} -Version '1.19.4'
            $script:selectedCommand | Should -BeExactly 'OtherVersion'
        }

        It 'rejects a missing or ambiguous pinned module without falling back' -TestCases @(
            @{ Case = 'missing' }
            @{ Case = 'ambiguous' }
        ) {
            param ($Case)
            if ($Case -ceq 'missing') { $script:loadedPackageModules = @($script:loadedPackageModules[1]) }
            else { $script:loadedPackageModules += $script:loadedPackageModules[0] }
            { Invoke-PowerStigGuestConfigurationPackage -PackageParameters @{} -Version '4.10.0' } |
                Should -Throw '*exactly one loaded GuestConfiguration*'
            $script:selectedCommand | Should -BeNullOrEmpty
        }

        It 'rejects an absent command export without resolving a global command' {
            $script:loadedPackageModules[0].ExportedCommands.Clear()
            { Invoke-PowerStigGuestConfigurationPackage -PackageParameters @{} -Version '4.10.0' } |
                Should -Throw '*does not export*'
            $script:selectedCommand | Should -BeNullOrEmpty
        }
    }

    It 'rejects an existing package unless Force is specified' {
        $null = New-Item -Path $script:outputPath -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path -Path $script:outputPath -ChildPath 'SampleAudit.zip') -Value 'existing'
        Mock Import-PowerStigGuestConfiguration {}
        Mock Invoke-PowerStigGuestConfigurationPackage {}

        {
            New-PowerStigAuditPackage `
                -Name 'SampleAudit' `
                -ConfigurationMofPath $script:mofPath `
                -OutputPath $script:outputPath
        } | Should -Throw '*Package already exists*'

        Should -Invoke Invoke-PowerStigGuestConfigurationPackage -Times 0
    }

    It 'rejects a non-MOF configuration input' {
        $textPath = Join-Path -Path $TestDrive -ChildPath 'Configuration.ps1'
        Set-Content -LiteralPath $textPath -Value 'Configuration Example {}'

        {
            New-PowerStigAuditPackage `
                -Name 'SampleAudit' `
                -ConfigurationMofPath $textPath `
                -OutputPath $script:outputPath
        } | Should -Throw '*compiled .mof file*'
    }
}
