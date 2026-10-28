# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Get-PowerStigMachineConfigurationCoverage
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $BenchmarkPath,

        [Parameter(Mandatory = $true)]
        [string] $ProcessedPath
    )

    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $documents = @{}

    foreach ($inputFile in @{ Benchmark = $BenchmarkPath; Processed = $ProcessedPath }.GetEnumerator())
    {
        $file = Get-Item -LiteralPath $inputFile.Value -ErrorAction Stop
        $reader = [System.Xml.XmlReader]::Create($file.FullName, $settings)
        try
        {
            $document = [System.Xml.XmlDocument]::new()
            $document.XmlResolver = $null
            $document.Load($reader)
            $documents[$inputFile.Key] = $document
        }
        finally
        {
            $reader.Dispose()
        }
    }

    $benchmark = $documents.Benchmark.DocumentElement
    $processed = $documents.Processed.DocumentElement
    if ($benchmark.LocalName -cne 'Benchmark' -or $processed.LocalName -cne 'DISASTIG')
    {
        throw 'Expected an XCCDF Benchmark and a PowerSTIG DISASTIG document.'
    }

    $releaseNode = $benchmark.SelectSingleNode("*[local-name()='plain-text' and @id='release-info']")
    $versionNode = $benchmark.SelectSingleNode("*[local-name()='version']")
    if ($null -eq $releaseNode -or $releaseNode.InnerText -notmatch 'Release:\s*(\d+)' -or $null -eq $versionNode)
    {
        throw 'Benchmark must identify its version and release.'
    }

    $sourceVersion = "$($versionNode.InnerText).$($Matches[1])"
    $sourceId = $benchmark.GetAttribute('id')
    $sourceMatches = $sourceId -ceq $processed.GetAttribute('stigid') -and
        $sourceVersion -ceq $processed.GetAttribute('fullversion')

    $processedRules = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal
    )
    $processedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($rule in $processed.SelectNodes('*/Rule'))
    {
        $id = $rule.GetAttribute('id')
        if ($id -cnotmatch '^(V-\d+)(?:\.[a-z]+)?$' -or -not $processedIds.Add($id))
        {
            throw "Processed data contains an invalid or duplicate vulnerability ID '$id'."
        }
        $parentId = $Matches[1]
        if (-not $processedRules.ContainsKey($parentId))
        {
            $processedRules.Add($parentId, [System.Collections.Generic.List[object]]::new())
        }
        $processedRules[$parentId].Add($rule)
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $rows = @(
        foreach ($rule in $benchmark.SelectNodes(".//*[local-name()='Rule']"))
        {
            $id = $rule.ParentNode.GetAttribute('id')
            $ruleId = $rule.GetAttribute('id')
            if ($id -notmatch '^V-\d+$' -or [string]::IsNullOrWhiteSpace($ruleId) -or -not $seen.Add($id))
            {
                throw "Benchmark contains an invalid or duplicate vulnerability ID '$id'."
            }

            $state = 'Missing'
            $components = @()
            if (-not $sourceMatches)
            {
                $state = 'SourceMismatch'
            }
            elseif ($processedRules.ContainsKey($id))
            {
                $components = @(
                    foreach ($candidate in $processedRules[$id])
                    {
                        $resource = $candidate.GetAttribute('dscresource')
                        $module = $candidate.ParentNode.GetAttribute('dscresourcemodule')
                        $componentState = if ($candidate.GetAttribute('conversionstatus') -cne 'pass')
                        {
                            'ConversionFailed'
                        }
                        elseif (-not [string]::IsNullOrWhiteSpace([string]$candidate.DuplicateOf))
                        {
                            'DuplicateReference'
                        }
                        elseif ($candidate.ParentNode.LocalName -ceq 'DocumentRule' -or $resource -ceq 'None')
                        {
                            'Manual'
                        }
                        elseif ($module -ieq 'nx' -or $resource -imatch '^nx')
                        {
                            'LegacyLinux'
                        }
                        elseif ($candidate.OrganizationValueRequired -ieq 'True')
                        {
                            'OrganizationValueRequired'
                        }
                        else
                        {
                            'RuntimeUnqualified'
                        }
                        [pscustomobject]@{
                            ProcessedId = $candidate.GetAttribute('id')
                            CoverageState = $componentState
                            DscResource = $resource
                            DscModule = $module
                        }
                    }
                )
                $states = @($components.CoverageState | Sort-Object -Unique)
                $state = if ($states.Count -eq 1) { $states[0] } else { 'Mixed' }
            }

            [pscustomobject]@{
                VulnerabilityId = $id
                RuleId          = $ruleId
                StigId          = $rule.SelectSingleNode("*[local-name()='version']").InnerText
                Title           = $rule.SelectSingleNode("*[local-name()='title']").InnerText
                Severity        = $rule.GetAttribute('severity')
                CoverageState   = $state
                Components      = $components
            }

        }
    )
    if ($rows.Count -eq 0)
    {
        throw 'Benchmark contains no requirements.'
    }

    [pscustomobject]@{
        BenchmarkId          = $sourceId
        BenchmarkVersion     = $sourceVersion
        ProcessedVersion     = $processed.GetAttribute('fullversion')
        SourceMatches        = $sourceMatches
        BenchmarkSha256      = (Get-FileHash -LiteralPath $BenchmarkPath -Algorithm SHA256 -ErrorAction Stop).Hash
        ProcessedSha256      = (Get-FileHash -LiteralPath $ProcessedPath -Algorithm SHA256 -ErrorAction Stop).Hash
        RequirementCount     = $rows.Count
        RuntimeQualified     = $false
        Rules                = $rows
    }
}

function Get-PowerStigMachineConfigurationResourceMap
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $ConfigurationMofPath
    )

    $mof = Get-Content -LiteralPath $ConfigurationMofPath -Raw -ErrorAction Stop
    $resourceMatches = [regex]::Matches($mof, '(?m)^\s*ResourceID\s*=\s*"(?<id>(?:\\.|[^"\\])*)"\s*;')
    if ($resourceMatches.Count -eq 0)
    {
        throw 'Compiled MOF contains no literal ResourceID assignments.'
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $requirements = @{}
    $unmapped = [System.Collections.Generic.List[string]]::new()
    foreach ($match in $resourceMatches)
    {
        $resourceId = ('"' + $match.Groups['id'].Value + '"') | ConvertFrom-Json -ErrorAction Stop
        if (-not $seen.Add($resourceId))
        {
            throw "Compiled MOF contains duplicate ResourceID '$resourceId'."
        }
        if ($resourceId -cmatch '^\[[^\]]+\]\[(V-\d+)(?:\.[a-z]+)?\]\[')
        {
            $id = $Matches[1]
            if (-not $requirements.ContainsKey($id))
            {
                $requirements[$id] = [System.Collections.Generic.List[string]]::new()
            }
            $requirements[$id].Add($resourceId)
        }
        else
        {
            $unmapped.Add($resourceId)
        }
    }

    [pscustomobject]@{
        ConfigurationMofSha256 = (Get-FileHash -LiteralPath $ConfigurationMofPath -Algorithm SHA256 -ErrorAction Stop).Hash
        ResourceCount = $resourceMatches.Count
        UnmappedResourceIds = $unmapped.ToArray()
        Requirements = @(
            foreach ($id in ($requirements.Keys | Sort-Object))
            {
                @{ VulnerabilityId = $id; ResourceIds = $requirements[$id].ToArray() }
            }
        )
    }
}
