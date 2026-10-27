BeforeAll {
    . "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\AuditInitiative.ps1"
}

Describe 'New-PowerStigAuditInitiative' {
    BeforeEach {
        $script:parameters = @{
            Name = 'PowerStigAudit'
            WindowsPolicyDefinitionId = '/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Authorization/policyDefinitions/windows'
            LinuxPolicyDefinitionId = '/providers/Microsoft.Management/managementGroups/example/providers/Microsoft.Authorization/policyDefinitions/linux'
        }
    }

    It 'creates one initiative with stable Windows and Linux reference IDs without cloud endpoints' {
        $result = New-PowerStigAuditInitiative @script:parameters
        $result.properties.policyDefinitions.Count | Should -Be 2
        $result.properties.policyDefinitions[0].policyDefinitionReferenceId | Should -BeExactly 'PowerStigWindows'
        $result.properties.policyDefinitions[1].policyDefinitionReferenceId | Should -BeExactly 'PowerStigLinux'
        $result.properties.policyDefinitions[0].policyDefinitionId | Should -BeExactly $script:parameters.WindowsPolicyDefinitionId
        ($result | ConvertTo-Json -Depth 20) | Should -Not -Match 'https://'
    }

    It 'rejects duplicate or non-custom definition IDs' -TestCases @(
        @{ Case = 'duplicate' }
        @{ Case = 'builtin' }
        @{ Case = 'resource-group' }
    ) {
        param ($Case)
        switch ($Case)
        {
            'duplicate' { $script:parameters.LinuxPolicyDefinitionId = $script:parameters.WindowsPolicyDefinitionId }
            'builtin' { $script:parameters.LinuxPolicyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/linux' }
            'resource-group' {
                $script:parameters.LinuxPolicyDefinitionId = '/subscriptions/example/resourceGroups/lab/providers/Microsoft.Authorization/policyDefinitions/linux'
            }
        }
        { New-PowerStigAuditInitiative @script:parameters } | Should -Throw
    }
}
