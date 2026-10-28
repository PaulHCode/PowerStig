BeforeAll {
    . "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\Coverage.ps1"
    $script:root = (Resolve-Path "$PSScriptRoot\..\..\..\..").Path
}

Describe 'Get-PowerStigMachineConfigurationCoverage' {
    It 'pins the archived <Processed> inventory without claiming runtime qualification' -TestCases @(
        @{ Archive = 'Windows.Client\U_MS_Windows_11_STIG_V2R7_Manual-xccdf.xml'; Processed = 'WindowsClient-11-2.7.xml'; Count = 262 }
        @{ Archive = 'Windows.Server.2022\U_MS_Windows_Server_2022_MS_STIG_V2R8_Manual-xccdf.xml'; Processed = 'WindowsServer-2022-MS-2.8.xml'; Count = 238 }
        @{ Archive = 'Linux.Ubuntu\U_CAN_Ubuntu_18-04_LTS_STIG_V2R15_Manual-xccdf.xml'; Processed = 'Ubuntu-18.04-2.15.xml'; Count = 176 }
    ) {
        param ($Archive, $Processed, $Count)
        $result = Get-PowerStigMachineConfigurationCoverage `
            -BenchmarkPath "$script:root\source\StigData\Archive\$Archive" `
            -ProcessedPath "$script:root\source\StigData\Processed\$Processed"
        $result.SourceMatches | Should -BeTrue
        $result.RequirementCount | Should -Be $Count
        $result.RuntimeQualified | Should -BeFalse
    }

    It 'accounts for every source RHEL requirement, preserving split and duplicate components' {
        $result = Get-PowerStigMachineConfigurationCoverage `
            -BenchmarkPath "$script:root\source\StigData\Archive\Linux.RHEL\U_RHEL_9_STIG_V2R8_Manual-xccdf.xml" `
            -ProcessedPath "$script:root\source\StigData\Processed\RHEL-9-2.8.xml"
        $result.SourceMatches | Should -BeTrue
        $result.BenchmarkVersion | Should -BeExactly '2.8'
        $result.RequirementCount | Should -Be 446
        @($result.Rules | Where-Object CoverageState -EQ 'Manual').Count | Should -Be 346
        @($result.Rules | Where-Object CoverageState -EQ 'LegacyLinux').Count | Should -Be 96
        @($result.Rules | Where-Object CoverageState -EQ 'Mixed').Count | Should -Be 3
        @($result.Rules | Where-Object CoverageState -EQ 'DuplicateReference').Count | Should -Be 1
        @($result.Rules | Where-Object CoverageState -EQ 'Missing').Count | Should -Be 0
        ($result.Rules | Where-Object VulnerabilityId -EQ 'V-257939').Components.Count | Should -Be 2
        $result.RuntimeQualified | Should -BeFalse
        $result.BenchmarkSha256 | Should -Match '^[A-F0-9]{64}$'
    }

    Describe 'Get-PowerStigMachineConfigurationResourceMap' {
        It 'groups split resources under the source vulnerability without losing full native IDs' {
            $path = Join-Path $TestDrive 'split.mof'
            @(
                'instance of Registry {'
                'ResourceID = "[Registry][V-123.a][medium][Example]::[WindowsServer]Benchmark";'
                '};'
                'instance of Registry {'
                'ResourceID = "[Registry][V-123.b][medium][Example]::[WindowsServer]Benchmark";'
                '};'
                'instance of Helper {'
                'ResourceID = "[Helper]Refresh";'
                '};'
            ) | Set-Content -LiteralPath $path
            $result = Get-PowerStigMachineConfigurationResourceMap -ConfigurationMofPath $path
            $result.ResourceCount | Should -Be 3
            $result.Requirements.Count | Should -Be 1
            $result.Requirements[0].VulnerabilityId | Should -BeExactly 'V-123'
            $result.Requirements[0].ResourceIds.Count | Should -Be 2
            $result.UnmappedResourceIds | Should -Contain '[Helper]Refresh'
        }

        It 'rejects duplicate or absent resource assignments' -TestCases @(
            @{ Text = '/* no resources */' }
            @{ Text = 'ResourceID = "[Registry][V-1][medium][Example]";' + "`n" + 'ResourceID = "[Registry][V-1][medium][Example]";' }
        ) {
            param ($Text)
            $path = Join-Path $TestDrive 'invalid.mof'
            $Text | Set-Content -LiteralPath $path
            { Get-PowerStigMachineConfigurationResourceMap -ConfigurationMofPath $path } | Should -Throw
        }
    }

    It 'does not quietly compare different releases as covered' {
        $result = Get-PowerStigMachineConfigurationCoverage `
            -BenchmarkPath "$script:root\source\StigData\Archive\Linux.RHEL\U_RHEL_9_STIG_V2R8_Manual-xccdf.xml" `
            -ProcessedPath "$script:root\source\StigData\Processed\RHEL-9-2.7.xml"
        $result.SourceMatches | Should -BeFalse
        @($result.Rules | Where-Object CoverageState -NE 'SourceMismatch').Count | Should -Be 0
    }

    It 'rejects empty or non-benchmark content' {
        $path = Join-Path $TestDrive 'invalid.xml'
        '<DISASTIG />' | Set-Content -LiteralPath $path
        { Get-PowerStigMachineConfigurationCoverage -BenchmarkPath $path -ProcessedPath $path } |
            Should -Throw '*Expected an XCCDF Benchmark*'
    }

    It 'retains a source requirement absent from processed data' {
        $benchmarkPath = Join-Path $TestDrive 'benchmark.xml'
        $processedPath = Join-Path $TestDrive 'processed.xml'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Example"><version>1</version><plain-text id="release-info">Release: 2</plain-text><Group id="V-1"><Rule id="SV-1"><version>TEST-1</version><title>Example</title></Rule></Group></Benchmark>' |
            Set-Content -LiteralPath $benchmarkPath
        '<DISASTIG stigid="Example" fullversion="1.2" />' | Set-Content -LiteralPath $processedPath
        $result = Get-PowerStigMachineConfigurationCoverage -BenchmarkPath $benchmarkPath -ProcessedPath $processedPath
        $result.SourceMatches | Should -BeTrue
        $result.RequirementCount | Should -Be 1
        $result.Rules[0].CoverageState | Should -BeExactly 'Missing'
    }

    It 'rejects a benchmark with external entities' {
        $benchmarkPath = Join-Path $TestDrive 'external.xml'
        '<!DOCTYPE Benchmark [<!ENTITY example SYSTEM "file:///unreadable">]><Benchmark>&example;</Benchmark>' |
            Set-Content -LiteralPath $benchmarkPath
        {
            Get-PowerStigMachineConfigurationCoverage -BenchmarkPath $benchmarkPath `
                -ProcessedPath "$script:root\source\StigData\Processed\RHEL-9-2.8.xml"
        } | Should -Throw
    }
}
