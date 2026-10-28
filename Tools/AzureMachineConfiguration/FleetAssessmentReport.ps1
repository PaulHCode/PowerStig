# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

. "$PSScriptRoot\Profile.ps1"

function ConvertFrom-PowerStigFleetAssessment
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $AssessmentJson,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $CoveragePath,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string] $ExpectedCoverageHash,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ExpectedProfileId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Windows', 'Linux')]
        [string] $ExpectedFamily,

        [Parameter()]
        [ValidateRange(1, 10080)]
        [int] $MaximumAgeMinutes = 60,

        [Parameter()]
        [datetimeoffset] $Now = [datetimeoffset]::UtcNow
    )

    if ($PSVersionTable.PSVersion.Major -lt 7)
    {
        throw 'Fleet assessment payload validation requires PowerShell 7 or later.'
    }
    if ([System.Text.Encoding]::UTF8.GetByteCount($AssessmentJson) -gt 16777216)
    {
        throw 'Fleet assessment payload exceeds the 16-MiB limit.'
    }
    $coverageFile = Get-Item -LiteralPath $CoveragePath -ErrorAction Stop
    if ($coverageFile.PSIsContainer -or $coverageFile.Length -gt 20971520)
    {
        throw 'Coverage must be a file no larger than 20 MiB.'
    }
    $coverageBytes = [System.IO.File]::ReadAllBytes($coverageFile.FullName)
    if ($coverageBytes.Length -gt 20971520) { throw 'Coverage exceeds the 20-MiB limit.' }
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try
    {
        $coverageHash = [System.BitConverter]::ToString($algorithm.ComputeHash($coverageBytes)).Replace('-', '')
    }
    finally
    {
        $algorithm.Dispose()
    }
    if ($coverageHash -ine $ExpectedCoverageHash)
    {
        throw 'Coverage does not match the hash pinned in the approved package catalog.'
    }
    $coverageText = [System.Text.UTF8Encoding]::new($false, $true).GetString($coverageBytes).TrimStart([char]0xFEFF)
    $coverage = ConvertFrom-Json -InputObject $coverageText -AsHashtable -Depth 40 -ErrorAction Stop
    $assessment = ConvertFrom-Json -InputObject $AssessmentJson -AsHashtable -Depth 40 -ErrorAction Stop
    if ($coverage -isnot [System.Collections.IDictionary] -or
        $coverage['SourceMatches'] -isnot [bool] -or -not $coverage['SourceMatches'] -or
        $coverage['Rules'] -isnot [array] -or $coverage['Rules'].Count -eq 0 -or
        $coverage['Rules'].Count -ne $coverage['RequirementCount'])
    {
        throw 'Coverage must contain a complete, source-matched requirement inventory.'
    }
    if ($assessment -isnot [System.Collections.IDictionary] -or $assessment['SchemaVersion'] -cne '1.0' -or
        $assessment['HostFacts'] -isnot [System.Collections.IDictionary] -or
        $assessment['Rules'] -isnot [array])
    {
        throw 'Expected a schema 1.0 fleet assessment object with host facts and a rule array.'
    }
    if ($assessment['Status'] -ceq 'Unsupported')
    {
        throw "Unsupported guest assessment has no admitted source inventory: $($assessment['Message'])"
    }
    $identity = Resolve-PowerStigMachineConfigurationProfile -HostFacts $assessment['HostFacts']
    if ($assessment['HostFacts']['Family'] -cne $ExpectedFamily -or
        $identity.IdentityState -cne 'Recognized' -or $identity.ProfileId -cne $ExpectedProfileId -or
        $assessment['ProfileId'] -cne $ExpectedProfileId)
    {
        throw 'Assessment profile/family does not match its reported host facts and expected profile.'
    }
    foreach ($field in @('BenchmarkId', 'BenchmarkVersion', 'BenchmarkSha256', 'ProcessedSha256'))
    {
        if ([string]::IsNullOrWhiteSpace([string]$coverage[$field]) -or
            [string]$assessment[$field] -cne [string]$coverage[$field])
        {
            throw "Assessment $field does not match the pinned source coverage."
        }
    }
    $collectedAt = [datetimeoffset]::MinValue
    $timestamp = $assessment['CollectedAt']
    $validTimestamp = $false
    if ($timestamp -is [datetime] -and $timestamp.Kind -ne [System.DateTimeKind]::Unspecified)
    {
        $collectedAt = [datetimeoffset]$timestamp
        $validTimestamp = $true
    }
    elseif ($timestamp -is [string] -and $timestamp -cmatch '^\d{4}-\d{2}-\d{2}T.+(?:Z|[+-]\d{2}:\d{2})$')
    {
        $validTimestamp = [datetimeoffset]::TryParse($timestamp, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None, [ref]$collectedAt)
    }
    if (-not $validTimestamp -or $collectedAt -gt $Now)
    {
        throw 'Assessment collection timestamp is invalid or in the future.'
    }
    $isStale = ($Now - $collectedAt).TotalMinutes -gt $MaximumAgeMinutes
    $reportedRules = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($rule in $assessment['Rules'])
    {
        if ($rule -isnot [System.Collections.IDictionary]) { throw 'Assessment contains a non-object rule.' }
        $id = [string]$rule['VulnerabilityId']
        if ($id -cnotmatch '^V-\d+$' -or $reportedRules.ContainsKey($id))
        {
            throw "Assessment contains an invalid or duplicate requirement '$id'."
        }
        $reportedRules.Add($id, $rule)
    }
    $checkCounts = [ordered]@{
        Compliant = 0; NonCompliant = 0; Manual = 0; Unsupported = 0; EvidenceOnly = 0
        OrganizationValueRequired = 0; ConversionFailed = 0; DuplicateReference = 0; Error = 0
    }
    $ruleCounts = [ordered]@{ Compliant = 0; NonCompliant = 0; Incomplete = 0; Missing = 0; Error = 0 }
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $requirements = @(
        foreach ($sourceRule in $coverage['Rules'])
        {
            if ($sourceRule -isnot [System.Collections.IDictionary] -or $sourceRule['Components'] -isnot [array])
            {
                throw 'Coverage must contain source rule objects with explicit component arrays.'
            }
            $id = [string]$sourceRule['VulnerabilityId']
            if ($id -cnotmatch '^V-\d+$' -or -not $seen.Add($id))
            {
                throw "Coverage contains an invalid or duplicate requirement '$id'."
            }
            if (-not $reportedRules.ContainsKey($id))
            {
                throw "Assessment is incomplete: no result for source requirement '$id'."
            }
            $rule = $reportedRules[$id]
            foreach ($field in @('RuleId', 'StigId', 'Title', 'Severity'))
            {
                if ([string]$rule[$field] -cne [string]$sourceRule[$field])
                {
                    throw "Assessment requirement '$id' has different source metadata: $field."
                }
            }
            if ($rule['Checks'] -isnot [array]) { throw "Requirement '$id' must contain a check array." }
            $checks = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
            foreach ($check in $rule['Checks'])
            {
                if ($check -isnot [System.Collections.IDictionary]) { throw "Requirement '$id' contains a non-object check." }
                $checkId = [string]$check['Id']
                if ([string]::IsNullOrWhiteSpace($checkId) -or $checks.ContainsKey($checkId))
                {
                    throw "Requirement '$id' contains an empty or duplicate check ID."
                }
                if ([string]$check['Status'] -cnotin @($checkCounts.Keys) -or
                    $check['Expected'] -isnot [string] -or [string]::IsNullOrWhiteSpace($check['Expected']) -or
                    $check['Observed'] -isnot [string] -or [string]::IsNullOrWhiteSpace($check['Observed']))
                {
                    throw "Check '$checkId' has an unknown status or missing expected/observed explanation."
                }
                if ($check['Status'] -ceq 'Compliant' -and
                    ($ExpectedFamily -cne 'Windows' -or $check['Adapter'] -cne 'EffectiveMachineRegistry'))
                {
                    throw "Check '$checkId' claims compliance without an admitted effective-state adapter."
                }
                $checks.Add($checkId, $check)
                $checkCounts[$check['Status']]++
            }
            $components = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($component in $sourceRule['Components'])
            {
                if ($component -isnot [System.Collections.IDictionary])
                {
                    throw "Requirement '$id' contains a non-object source component."
                }
                $componentId = [string]$component['ProcessedId']
                if ([string]::IsNullOrWhiteSpace($componentId) -or -not $components.Add($componentId) -or
                    -not $checks.ContainsKey($componentId))
                {
                    throw "Requirement '$id' is missing a source component or has an invalid component inventory."
                }
                if ($checks[$componentId]['Status'] -ceq 'Compliant' -and
                    ($component['CoverageState'] -cne 'RuntimeUnqualified' -or
                        $component['DscResource'] -cne 'Registry'))
                {
                    throw "Source component '$componentId' is not eligible for an automated compliance assertion."
                }
            }
            if ($components.Count -ne $checks.Count) { throw "Requirement '$id' contains checks outside its source components." }
            $statuses = @($rule['Checks'] | ForEach-Object { $_['Status'] })
            $state = if ($checks.Count -eq 0) { 'Missing' }
                elseif ($statuses -ccontains 'Error') { 'Error' }
                elseif ($statuses -ccontains 'NonCompliant') { 'NonCompliant' }
                elseif (@($statuses | Where-Object { $_ -cne 'Compliant' }).Count -gt 0) { 'Incomplete' }
                else { 'Compliant' }
            if ($rule['Status'] -cne $state) { throw "Requirement '$id' status contradicts its check results." }
            $ruleCounts[$state]++
            [pscustomobject]@{
                VulnerabilityId = $id
                RuleId = $sourceRule['RuleId']
                StigId = $sourceRule['StigId']
                Title = $sourceRule['Title']
                Severity = $sourceRule['Severity']
                Status = $state
                Checks = @($rule['Checks'])
            }
        }
    )
    if ($reportedRules.Count -ne $seen.Count) { throw 'Assessment contains requirements outside the pinned source inventory.' }
    $expectedStatus = if ($ruleCounts.Compliant -eq $requirements.Count) { 'Compliant' } else { 'NonCompliant' }
    if ($assessment['Status'] -cne $expectedStatus) { throw 'Assessment summary status contradicts its requirement results.' }
    $payloadStatus = if ($isStale) { 'Stale' }
        elseif ($ruleCounts.Error -gt 0) { 'Error' }
        elseif ($ruleCounts.NonCompliant -gt 0) { 'NonCompliant' }
        elseif ($ruleCounts.Incomplete -gt 0 -or $ruleCounts.Missing -gt 0) { 'Incomplete' }
        else { 'Compliant' }
    [pscustomobject]@{
        ProfileId = $ExpectedProfileId
        Family = $ExpectedFamily
        CollectedAt = $collectedAt
        IsStale = $isStale
        ReportedStatus = $assessment['Status']
        PayloadStatus = $payloadStatus
        NativeReportAdmitted = $false
        BenchmarkId = $coverage['BenchmarkId']
        BenchmarkVersion = $coverage['BenchmarkVersion']
        BenchmarkSha256 = $coverage['BenchmarkSha256']
        ProcessedSha256 = $coverage['ProcessedSha256']
        CoverageSha256 = $coverageHash
        RequirementCount = $requirements.Count
        RuleCounts = [pscustomobject]$ruleCounts
        CheckCounts = [pscustomobject]$checkCounts
        Requirements = $requirements
    }
}
