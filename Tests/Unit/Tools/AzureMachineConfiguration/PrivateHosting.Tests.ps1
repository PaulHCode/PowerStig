Describe 'Private-only lab artifact delivery' {
    BeforeAll {
        $infra = "$PSScriptRoot\..\..\..\..\infra"
        $hosting = Get-Content "$infra\machine-configuration-lab.json" -Raw | ConvertFrom-Json
        $publisher = Get-Content "$infra\machine-configuration-publisher.json" -Raw | ConvertFrom-Json
        $endpoint = Get-Content "$infra\machine-configuration-private-endpoint.json" -Raw | ConvertFrom-Json
        $identity = Get-Content "$infra\machine-configuration-publisher-identity.json" -Raw | ConvertFrom-Json
        $hostingResources = $hosting.resources[1].properties.template.resources
        $publisherResources = $publisher.resources[1].properties.template.resources
    }

    It 'creates the publisher identity before compute, network access or role grants' {
        $identity.resources[1].properties.template.resources.type | Should -Be @(
            'Microsoft.ManagedIdentity/userAssignedIdentities',
            'Microsoft.Authorization/locks'
        )
    }

    It 'disables the public data plane, firewall bypasses, anonymous blobs and shared keys' {
        $storage = $hostingResources | Where-Object type -eq 'Microsoft.Storage/storageAccounts'
        $storage.properties.publicNetworkAccess | Should -BeExactly 'Disabled'
        $storage.properties.networkAcls.defaultAction | Should -BeExactly 'Deny'
        $storage.properties.networkAcls.bypass | Should -BeExactly 'None'
        @($storage.properties.networkAcls.ipRules).Count | Should -Be 0
        @($storage.properties.networkAcls.virtualNetworkRules).Count | Should -Be 0
        $storage.properties.allowBlobPublicAccess | Should -BeFalse
        $storage.properties.allowSharedKeyAccess | Should -BeFalse
    }

    It 'grants the publisher identity contributor only on the package container' {
        $hosting.parameters.publisherPrincipalType.allowedValues | Should -Be @('ServicePrincipal')
        $roles = @($hostingResources | Where-Object type -eq 'Microsoft.Authorization/roleAssignments')
        $roles.Count | Should -Be 2
        foreach ($role in $roles) {
            $role.scope | Should -BeLike '*blobServices/default/containers/packages*'
        }
        $roles[0].properties.roleDefinitionId | Should -BeLike '*2a2b9908-6ea1-4ae2-8e65-a410df84e7d1*'
        $roles[1].properties.roleDefinitionId | Should -BeLike '*ba92f5b4-2d11-453d-a403-e96b0029c9fe*'
        $roles[1].properties.principalType | Should -BeExactly "[parameters('publisherPrincipalType')]"
    }

    It 'creates a passwordless publisher without a public IP or deletion-coupled disks' {
        $vm = $publisherResources | Where-Object type -eq 'Microsoft.Compute/virtualMachines'
        $vm.identity.type | Should -BeExactly 'UserAssigned'
        $vm.identity.userAssignedIdentities.PSObject.Properties.Name |
            Should -BeExactly "[parameters('publisherIdentityId')]"
        $vm.properties.osProfile.linuxConfiguration.disablePasswordAuthentication | Should -BeTrue
        $vm.properties.osProfile.PSObject.Properties.Name | Should -Not -Contain 'adminPassword'
        $vm.properties.storageProfile.osDisk.deleteOption | Should -BeExactly 'Detach'
        $vm.properties.storageProfile.imageReference.publisher | Should -BeExactly 'Debian'
        $vm.properties.storageProfile.imageReference.offer | Should -BeExactly 'debian-12'
        $vm.properties.storageProfile.imageReference.sku | Should -BeExactly '12-gen2'
        $vm.properties.networkProfile.networkInterfaces[0].properties.deleteOption | Should -BeExactly 'Detach'
        $publisherResources.type | Should -Not -Contain 'Microsoft.Network/publicIPAddresses'
        $nic = $publisherResources | Where-Object type -eq 'Microsoft.Network/networkInterfaces'
        $nic.properties.ipConfigurations[0].properties.PSObject.Properties.Name | Should -Not -Contain 'publicIPAddress'
        $publisher.parameters.imageVersion.PSObject.Properties.Name | Should -Not -Contain 'defaultValue'
        ($publisherResources | Where-Object type -eq 'Microsoft.Authorization/locks').properties.level |
            Should -BeExactly 'CanNotDelete'
        ($publisherResources | Where-Object type -eq 'Microsoft.DevTestLab/schedules').properties.taskType |
            Should -BeExactly 'ComputeVmShutdownTask'
    }

    It 'references the existing subnet and DNS zone without redeclaring shared networking or NSP allowances' {
        $endpoint.resources.type | Should -Be @(
            'Microsoft.Network/privateEndpoints',
            'Microsoft.Network/privateEndpoints/privateDnsZoneGroups'
        )
        $endpoint.resources[0].properties.subnet.id | Should -BeExactly "[parameters('subnetId')]"
        $endpoint.resources[1].properties.privateDnsZoneConfigs[0].properties.privateDnsZoneId |
            Should -BeExactly "[parameters('privateDnsZoneId')]"
        ($hostingResources.type + $publisherResources.type + $endpoint.resources.type) |
            Where-Object { $_ -like '*networkSecurityPerimeters*' -or $_ -eq 'Microsoft.Network/virtualNetworks' } |
            Should -BeNullOrEmpty
    }
}
