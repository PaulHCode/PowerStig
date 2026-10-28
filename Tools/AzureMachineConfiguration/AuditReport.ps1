# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function ConvertFrom-PowerStigMachineConfigurationReport
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary] $Report,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary] $Assignment,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string] $ExpectedPackageHash,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ExpectedConfigurationName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ExpectedConfigurationVersion,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ExpectedVmId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ExpectedAssignmentId,

        [Parameter(Mandatory = $true)]
        [psobject] $ResourceMap,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string] $ExpectedConfigurationMofHash,

        [Parameter(Mandatory = $true)]
        [psobject] $Coverage,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string] $ExpectedBenchmarkHash,

        [Parameter()]
        [ValidateRange(1, 10080)]
        [int] $MaximumAgeMinutes = 60,

        [Parameter()]
        [datetimeoffset] $Now = [datetimeoffset]::UtcNow
    )

    if (-not $Coverage.SourceMatches -or $Coverage.BenchmarkSha256 -ine $ExpectedBenchmarkHash)
    {
        throw 'Coverage must match the pinned source benchmark and processed release.'
    }
    $coverageRules = @($Coverage.Rules)
    if ($coverageRules.Count -eq 0 -or $coverageRules.Count -ne $Coverage.RequirementCount)
    {
        throw 'Coverage has an empty or inconsistent requirement inventory.'
    }
    if ($ResourceMap.ConfigurationMofSha256 -ine $ExpectedConfigurationMofHash)
    {
        throw 'Resource mapping does not match the compiled MOF from the validated package.'
    }
    $requirementMap = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($requirement in $ResourceMap.Requirements)
    {
        $id = [string]$requirement['VulnerabilityId']
        if ($id -notmatch '^V-\d+$' -or $requirementMap.ContainsKey($id))
        {
            throw "Requirements contain an invalid or duplicate vulnerability ID '$id'."
        }
        $requirementMap.Add($id, $requirement)
    }

    $configuration = $Assignment['properties']['guestConfiguration']
    $properties = $Report['properties']
    $reportConfiguration = $properties['assignment']['configuration']
    if (
        $configuration['name'] -cne $ExpectedConfigurationName -or
        $configuration['version'] -cne $ExpectedConfigurationVersion -or
        $configuration['contentHash'] -ine $ExpectedPackageHash -or
        $configuration['assignmentType'] -cne 'Audit' -or
        $reportConfiguration['name'] -cne $ExpectedConfigurationName -or
        $reportConfiguration['version'] -cne $ExpectedConfigurationVersion
    )
    {
        throw 'Assignment or report does not match the expected Audit package identity.'
    }

    $assignmentId = [string]$Assignment['id']
    $assignmentPrefix = "$($ExpectedVmId.TrimEnd('/'))/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/"
    if (
        $assignmentId -ine $ExpectedAssignmentId -or
        -not $assignmentId.StartsWith($assignmentPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        $assignmentId.Substring($assignmentPrefix.Length) -notmatch '^[^/]+$' -or
        $properties['vm']['id'] -ine $ExpectedVmId -or
        [string]::IsNullOrWhiteSpace([string]$properties['reportId']) -or
        $Report['id'] -ine "$assignmentId/reports/$($properties['reportId'])"
    )
    {
        throw 'Report does not belong to the expected VM and assignment.'
    }

    $endTime = [datetimeoffset]::MinValue
    $startTime = [datetimeoffset]::MinValue
    if (
        -not [datetimeoffset]::TryParse([string]$properties['endTime'], [ref]$endTime) -or
        -not [datetimeoffset]::TryParse([string]$properties['startTime'], [ref]$startTime) -or
        $startTime -gt $endTime -or $endTime -gt $Now
    )
    {
        throw 'Report has invalid, reversed, or future timestamps.'
    }

    $stale = ($Now - $endTime).TotalMinutes -gt $MaximumAgeMinutes
    $resources = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($resource in $properties['details']['resources'])
    {
        $resourceId = [string]$resource['resourceId']
        if ([string]::IsNullOrWhiteSpace($resourceId))
        {
            $resourceId = [string]$resource['properties']['ResourceId']
        }
        if ([string]::IsNullOrWhiteSpace($resourceId) -or $resources.ContainsKey($resourceId))
        {
            throw "Report contains an empty or duplicate DSC resource ID '$resourceId'."
        }
        $resources.Add($resourceId, $resource)
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $mapped = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $results = @(
        foreach ($coverageRule in $coverageRules)
        {
            $id = [string]$coverageRule.VulnerabilityId
            if ($id -notmatch '^V-\d+$' -or -not $seen.Add($id))
            {
                throw "Coverage contains an invalid or duplicate vulnerability ID '$id'."
            }

            if (-not $requirementMap.ContainsKey($id))
            {
                [pscustomobject]@{
                    VulnerabilityId = $id
                    Status          = $coverageRule.CoverageState
                    Reasons         = @(@{
                        Code = 'PowerStig:PowerStig:Unassessed'
                        Phrase = "No qualified resource mapping for $id; source coverage state: $($coverageRule.CoverageState)."
                    })
                    Observations    = @()
                }
                continue
            }
            $resourceIds = @($requirementMap[$id]['ResourceIds'])
            if ($resourceIds.Count -eq 0 -or @($resourceIds | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0)
            {
                throw "Requirement '$id' must explicitly list its DSC resources."
            }
            $status = 'Compliant'
            $reasons = [System.Collections.Generic.List[object]]::new()
            $observations = [System.Collections.Generic.List[object]]::new()
            foreach ($resourceId in $resourceIds)
            {
                $null = $mapped.Add($resourceId)
                if (-not $resources.ContainsKey($resourceId))
                {
                    $status = 'MissingEvidence'
                    $reasons.Add(@{ Code = 'PowerStig:PowerStig:MissingEvidence'; Phrase = "No native result for $resourceId." })
                    continue
                }
                $resource = $resources[$resourceId]
                $nativeStatus = [string]$resource['complianceStatus']
                if ($nativeStatus -cne 'Compliant' -and $status -ceq 'Compliant')
                {
                    $status = if ($nativeStatus -ceq 'NonCompliant') { 'NonCompliant' } else { 'Unknown' }
                }
                $nativeReasons = @($resource['reasons'])
                if ($nativeReasons.Count -eq 0 -or $null -eq $nativeReasons[0])
                {
                    $status = 'MissingEvidence'
                    $reasons.Add(@{ Code = 'PowerStig:PowerStig:MissingReasons'; Phrase = "Native Reasons are absent for $resourceId." })
                }
                foreach ($reason in $nativeReasons)
                {
                    if ($null -eq $reason) { continue }
                    if ([string]::IsNullOrWhiteSpace($reason['code']) -or [string]::IsNullOrWhiteSpace($reason['phrase']))
                    {
                        throw "Report contains an incomplete reason for '$resourceId'."
                    }
                    $reasons.Add(@{ Code = $reason['code']; Phrase = $reason['phrase'] })
                }
                $observations.Add(@{ ResourceId = $resourceId; Properties = $resource['properties']; NativeStatus = $nativeStatus })
            }
            if ($stale) { $status = 'Stale' }
            [pscustomobject]@{
                VulnerabilityId = $id
                Status          = $status
                Reasons         = $reasons.ToArray()
                Observations    = $observations.ToArray()
            }
        }
    )

    foreach ($id in $requirementMap.Keys)
    {
        if (-not $seen.Contains($id))
        {
            throw "Resource mapping contains a requirement outside the pinned benchmark: '$id'."
        }
    }
    $unmapped = @($resources.Keys | Where-Object { -not $mapped.Contains($_) } | Sort-Object)
    $overall = 'Indeterminate'
    if (
        -not $stale -and $unmapped.Count -eq 0 -and
        $properties['complianceStatus'] -ceq 'Compliant' -and
        $properties['details']['complianceStatus'] -ceq 'Compliant' -and
        @($results | Where-Object Status -CNE 'Compliant').Count -eq 0
    )
    {
        $overall = 'Compliant'
    }
    elseif (-not $stale -and @($results | Where-Object Status -CEQ 'NonCompliant').Count -gt 0)
    {
        $overall = 'NonCompliant'
    }
    [pscustomobject]@{
        VmId                = $ExpectedVmId
        ConfigurationName   = $ExpectedConfigurationName
        ConfigurationVersion = $ExpectedConfigurationVersion
        PackageSha256       = $ExpectedPackageHash
        ConfigurationMofSha256 = $ExpectedConfigurationMofHash
        BenchmarkSha256     = $ExpectedBenchmarkHash
        ReportId            = $properties['reportId']
        EndTime             = $endTime
        IsStale             = $stale
        NativeStatus        = $properties['complianceStatus']
        AssessmentStatus    = $overall
        UnmappedResourceIds = $unmapped
        Requirements        = $results
    }
}
