# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function New-PowerStigAuditInitiative
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $WindowsPolicyDefinitionId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $LinuxPolicyDefinitionId,

        [Parameter()]
        [ValidatePattern('^\d+\.\d+\.\d+$')]
        [string] $Version = '1.0.0'
    )

    $definitions = @(
        @{ Family = 'Windows'; Id = $WindowsPolicyDefinitionId }
        @{ Family = 'Linux'; Id = $LinuxPolicyDefinitionId }
    )
    $idPattern = '^/(subscriptions/[0-9a-fA-F-]{36}|providers/Microsoft.Management/managementGroups/[^/]+)/providers/Microsoft.Authorization/policyDefinitions/[^/]+$'
    foreach ($definition in $definitions)
    {
        if ($definition.Id -notmatch $idPattern)
        {
            throw "$($definition.Family)PolicyDefinitionId must be a subscription or management-group custom policy definition ARM ID."
        }
    }
    if ($WindowsPolicyDefinitionId -ieq $LinuxPolicyDefinitionId)
    {
        throw 'Windows and Linux must reference distinct OS-family Audit policy definitions.'
    }

    [ordered]@{
        name = $Name
        properties = [ordered]@{
            displayName = 'PowerSTIG - automatically selected OS baseline (Audit)'
            description = 'Audits exact guest-selected Windows member-server/client and Linux STIG profiles. Unsupported or incomplete profiles must not report compliance.'
            policyType = 'Custom'
            metadata = @{
                category = 'Guest Configuration'
                version = $Version
            }
            policyDefinitions = @(
                foreach ($definition in $definitions)
                {
                    @{
                        policyDefinitionReferenceId = "PowerStig$($definition.Family)"
                        policyDefinitionId = $definition.Id
                    }
                }
            )
        }
    }
}
