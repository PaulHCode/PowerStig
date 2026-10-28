BeforeDiscovery {
    $script:modulePath = "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\PowerStig.MachineConfiguration\PowerStig.MachineConfiguration.psd1"
    Import-Module $script:modulePath -Force
}

Describe 'Portable audit adapters' {
    InModuleScope PowerStig.MachineConfiguration {
        It 'never infers a pass for manual or organization-specific checks' -TestCases @(
            @{ Type = 'ManualRule'; Org = 'False'; Resource = 'None'; Status = 'Manual' }
            @{ Type = 'RegistryRule'; Org = 'True'; Resource = 'Registry'; Status = 'OrganizationValueRequired' }
        ) {
            param ($Type, $Org, $Resource, $Status)
            [xml]$xml = "<DISASTIG><$Type><Rule id='V-1' dscresource='$Resource' conversionstatus='pass'><OrganizationValueRequired>$Org</OrganizationValueRequired></Rule></$Type></DISASTIG>"
            $rule = $xml.SelectSingleNode('//Rule')
            (Invoke-PowerStigProcessedCheck -Rule $rule -Family Windows).Status | Should -BeExactly $Status
        }

        It 'measures registry values and types without invoking Set' -TestCases @(
            @{ Value = 1; Kind = 'DWord'; ExpectedStatus = 'Compliant' }
            @{ Value = 0; Kind = 'DWord'; ExpectedStatus = 'NonCompliant' }
            @{ Value = 1; Kind = 'String'; ExpectedStatus = 'NonCompliant' }
        ) {
            param ($Value, $Kind, $ExpectedStatus)
            Mock Read-PowerStigRegistryValue { @{ State = 'Present'; Value = $Value; Kind = $Kind } }
            [xml]$xml = '<DISASTIG><RegistryRule><Rule id="V-1" dscresource="Registry" conversionstatus="pass"><Key>HKEY_LOCAL_MACHINE\Software\Example</Key><ValueName>Enabled</ValueName><ValueType>Dword</ValueType><ValueData>1</ValueData></Rule></RegistryRule></DISASTIG>'
            $result = Invoke-PowerStigProcessedCheck -Rule $xml.SelectSingleNode('//Rule') -Family Windows
            $result.Status | Should -BeExactly $ExpectedStatus
            $result.Observed | Should -Not -BeNullOrEmpty
        }

        It 'does not use a registry read to qualify an unadmitted resource variant' -TestCases @(
            @{ Resource = 'RegistryPolicyFile' }
            @{ Resource = 'RegistryAccessEntry' }
            @{ Resource = 'registry' }
        ) {
            param ($Resource)
            Mock Read-PowerStigRegistryValue { throw 'Unadmitted registry read.' }
            [xml]$xml = "<DISASTIG><RegistryRule><Rule id='V-1' dscresource='$Resource' conversionstatus='pass'><Key>HKEY_LOCAL_MACHINE\Software\Example</Key><ValueName>Enabled</ValueName><ValueType>Dword</ValueType><ValueData>1</ValueData></Rule></RegistryRule></DISASTIG>"
            $result = Invoke-PowerStigProcessedCheck -Rule $xml.SelectSingleNode('//Rule') -Family Windows
            $result.Status | Should -BeExactly 'Unsupported'
            $result.Adapter | Should -BeNullOrEmpty
            $result.Observed | Should -BeLike "*$Resource*"
            Should -Invoke Read-PowerStigRegistryValue -Times 0 -Exactly
        }

        It 'returns partial evidence, not effective-system compliance, for a matching Linux file line' {
            Mock Read-PowerStigTextFile { @{ State = 'Present'; Text = "setting=1`n" } }
            [xml]$xml = '<DISASTIG><nxFileLineRule><Rule id="V-1" dscresource="nxFileLine" conversionstatus="pass"><FilePath>/etc/example.conf</FilePath><ContainsLine>setting=1</ContainsLine><DoesNotContainPattern>PatternNotRequired</DoesNotContainPattern></Rule></nxFileLineRule></DISASTIG>'
            $result = Invoke-PowerStigProcessedCheck -Rule $xml.SelectSingleNode('//Rule') -Family Linux
            $result.Status | Should -BeExactly 'EvidenceOnly'
        }

        It 'makes missing Linux file evidence explicit' {
            Mock Read-PowerStigTextFile { @{ State = 'Missing'; Detail = 'Required file is missing.' } }
            [xml]$xml = '<DISASTIG><nxFileLineRule><Rule id="V-1" dscresource="nxFileLine" conversionstatus="pass"><FilePath>/etc/example.conf</FilePath><ContainsLine>setting=1</ContainsLine></Rule></nxFileLineRule></DISASTIG>'
            (Invoke-PowerStigProcessedCheck -Rule $xml.SelectSingleNode('//Rule') -Family Linux).Status | Should -BeExactly 'NonCompliant'
        }

        It 'does not guess absent processed values' {
            [xml]$xml = '<DISASTIG><nxFileLineRule><Rule id="V-1" dscresource="nxFileLine" conversionstatus="pass"><FilePath>/etc/example.conf</FilePath></Rule></nxFileLineRule></DISASTIG>'
            (Invoke-PowerStigProcessedCheck -Rule $xml.SelectSingleNode('//Rule') -Family Linux).Status | Should -BeExactly 'Unsupported'
        }
    }
}

Describe 'Fleet assessment dispatch' {
    It 'rejects a DC without trying to load a data catalog' {
        $result = Get-PowerStigBaselineAssessment -Family Windows -DataRoot "$TestDrive\absent" `
            -HostFacts @{ Family = 'Windows'; Build = '20348'; ProductType = 2; DomainRole = 5 }
        $result.Status | Should -BeExactly 'Unsupported'
        $result.Message | Should -BeLike '*Domain controllers*'
    }

    It 'rejects a wrong-family package before collecting configuration' {
        $result = Get-PowerStigBaselineAssessment -Family Windows -DataRoot "$TestDrive\absent" `
            -HostFacts @{ Family = 'Linux'; Id = 'rhel'; VersionId = '9.4' }
        $result.Status | Should -BeExactly 'Unsupported'
        $result.Message | Should -BeLike '*does not match*'
    }

    It 'does not substitute a neighboring Ubuntu release' {
        $null = New-Item -Path "$TestDrive\Data" -ItemType Directory -Force
        '{}' | Set-Content "$TestDrive\Data\catalog.json"
        $result = Get-PowerStigBaselineAssessment -Family Linux -DataRoot "$TestDrive\Data" `
            -HostFacts @{ Family = 'Linux'; Id = 'ubuntu'; VersionId = '24.04' }
        $result.Status | Should -BeExactly 'Unsupported'
        $result.Message | Should -BeLike '*no exact benchmark*'
    }
}
