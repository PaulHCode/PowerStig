# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

. "$PSScriptRoot\Profile.ps1"

function Test-PowerStigUnsupportedLinuxWorkerReport
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary] $Report,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary] $HostFacts,

        [Parameter()]
        [datetimeoffset] $Now = [datetimeoffset]::UtcNow
    )

    $identity = Resolve-PowerStigMachineConfigurationProfile -HostFacts $HostFacts
    if ($HostFacts['Family'] -cne 'Linux' -or $identity.IdentityState -cne 'Recognized')
    {
        throw 'This contract requires a recognized Linux identity with an unbundled profile.'
    }
    if ($Report['complianceStatus'] -isnot [bool] -or $Report['complianceStatus'] -or
        @($Report['resources']).Count -ne 1)
    {
        throw 'Expected an explicitly noncompliant report with exactly one resource.'
    }
    $resource = $Report['resources'][0]
    if ($resource['complianceStatus'] -isnot [bool] -or $resource['complianceStatus'] -or
        $resource['properties']['Family'] -cne 'Linux' -or
        $resource['properties']['AssessmentJson'] -isnot [string])
    {
        throw 'Expected a noncompliant Linux resource with serialized assessment evidence.'
    }
    $assessment = ConvertFrom-Json -InputObject $resource['properties']['AssessmentJson'] -AsHashtable -Depth 40
    $message = 'OS recognized, but no exact benchmark/profile is bundled. No neighboring release is substituted.'
    if ($assessment['SchemaVersion'] -cne '1.0' -or $assessment['Status'] -cne 'Unsupported' -or
        $assessment['ProfileId'] -cne $identity.ProfileId -or $assessment['Message'] -cne $message -or
        $assessment['Rules'] -isnot [array] -or $assessment['Rules'].Count -ne 0)
    {
        throw 'Unbundled Linux profile did not return the exact unsupported explanation and empty inventory.'
    }
    foreach ($field in @('Family', 'Id', 'VersionId'))
    {
        if ($assessment['HostFacts'][$field] -cne $HostFacts[$field])
        {
            throw 'Worker identity differs from independently measured host facts.'
        }
    }
    foreach ($field in @('BenchmarkId', 'BenchmarkVersion', 'BenchmarkSha256', 'ProcessedSha256'))
    {
        if ($null -ne $assessment[$field]) { throw 'Unsupported profile must not claim benchmark provenance.' }
    }
    $timestamp = $assessment['CollectedAt']
    if ($timestamp -isnot [datetime] -or $timestamp.Kind -eq [DateTimeKind]::Unspecified -or
        ([datetimeoffset]$timestamp) -gt $Now.AddMinutes(5) -or
        ([datetimeoffset]$timestamp) -lt $Now.AddMinutes(-5))
    {
        throw 'Unsupported assessment must have a fresh, timezone-aware collection timestamp.'
    }
    foreach ($surface in @(
        @{ Items = @($resource['reasons']); Code = 'code'; Phrase = 'phrase' },
        @{ Items = @($resource['properties']['Reasons']); Code = 'Code'; Phrase = 'Phrase' }
    ))
    {
        if ($surface.Items.Count -ne 1 -or
            $surface.Items[0][$surface.Code] -cne 'PowerStigBaseline:PowerStigBaseline:Summary' -or
            $surface.Items[0][$surface.Phrase] -cne "$($identity.ProfileId): Unsupported. $message")
        {
            throw 'Both native reason surfaces must preserve the complete unsupported-profile explanation.'
        }
    }
    [pscustomobject]@{
        ProfileId = $identity.ProfileId
        WorkerComplianceStatus = $false
        UnsupportedContractValidated = $true
        NativeAzureReportAdmitted = $false
    }
}
