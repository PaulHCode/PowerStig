BeforeAll {
    . "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\Profile.ps1"
}

Describe 'Resolve-PowerStigMachineConfigurationProfile' {
    It 'distinguishes client and server sharing build 26100' {
        $client = Resolve-PowerStigMachineConfigurationProfile -HostFacts @{
            Family = 'Windows'; Build = '26100'; ProductType = 1; DomainRole = 1
        }
        $server = Resolve-PowerStigMachineConfigurationProfile -HostFacts @{
            Family = 'Windows'; Build = '26100'; ProductType = 3; DomainRole = 3
        }
        $client.ProfileId | Should -BeExactly 'WindowsClient-11'
        $server.ProfileId | Should -BeExactly 'WindowsServer-2025-MS'
        $server.IdentityState | Should -BeExactly 'Recognized'
    }

    It 'selects the exact member-server build <Build>' -TestCases @(
        @{ Build = '14393'; Year = '2016' }
        @{ Build = '17763'; Year = '2019' }
        @{ Build = '20348'; Year = '2022' }
    ) {
        param ($Build, $Year)
        $result = Resolve-PowerStigMachineConfigurationProfile -HostFacts @{
            Family = 'Windows'; Build = $Build; ProductType = 3; DomainRole = 3
        }
        $result.ProfileId | Should -BeExactly "WindowsServer-$Year-MS"
    }

    It 'rejects a domain controller by either measured role indicator' -TestCases @(
        @{ ProductType = 2; DomainRole = 3 }
        @{ ProductType = 3; DomainRole = 4 }
        @{ ProductType = 3; DomainRole = 5 }
    ) {
        param ($ProductType, $DomainRole)
        $result = Resolve-PowerStigMachineConfigurationProfile -HostFacts @{
            Family = 'Windows'; Build = '20348'; ProductType = $ProductType; DomainRole = $DomainRole
        }
        $result.IdentityState | Should -BeExactly 'Unsupported'
        $result.Reason | Should -BeLike '*Domain controllers are excluded*'
        $result.ProfileId | Should -BeNullOrEmpty
    }

    It 'does not infer an adjacent release or a RHEL-compatible derivative' -TestCases @(
        @{ Facts = @{ Family = 'Linux'; Id = 'rocky'; VersionId = '9.4' } }
        @{ Facts = @{ Family = 'Linux'; Id = 'ubuntu'; VersionId = '26.04' } }
        @{ Facts = @{ Family = 'Windows'; Build = '99999'; ProductType = 3; DomainRole = 3 } }
    ) {
        param ($Facts)
        (Resolve-PowerStigMachineConfigurationProfile -HostFacts $Facts).IdentityState | Should -BeExactly 'Unsupported'
    }

    It 'recognizes Linux exact releases independently of content availability' -TestCases @(
        @{ Id = 'ubuntu'; Version = '18.04'; Profile = 'Ubuntu-18.04' }
        @{ Id = 'ubuntu'; Version = '22.04'; Profile = 'Ubuntu-22.04' }
        @{ Id = 'ubuntu'; Version = '24.04'; Profile = 'Ubuntu-24.04' }
        @{ Id = 'rhel'; Version = '8.10'; Profile = 'RHEL-8' }
        @{ Id = 'rhel'; Version = '9.4'; Profile = 'RHEL-9' }
        @{ Id = 'rhel'; Version = '10.2'; Profile = 'RHEL-10' }
    ) {
        param ($Id, $Version, $Profile)
        $result = Resolve-PowerStigMachineConfigurationProfile -HostFacts @{
            Family = 'Linux'; Id = $Id; VersionId = $Version
        }
        $result.ProfileId | Should -BeExactly $Profile
        $result.Reason | Should -BeLike '*separate admission gates*'
    }

    It 'rejects incomplete Windows identity instead of assuming member server' {
        {
            Resolve-PowerStigMachineConfigurationProfile -HostFacts @{ Family = 'Windows'; Build = '20348' }
        } | Should -Throw '*ProductType and DomainRole*'
    }
}
