# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Read-PowerStigRegistryValue
{
    param ([string] $Key, [string] $ValueName)

    if ($Key -notmatch '^HKEY_LOCAL_MACHINE\\(.+)$')
    {
        return @{ State = 'Unsupported'; Value = $null; Detail = 'Only machine-wide HKLM registry values are supported; user hives are not inferred.' }
    }
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64
    )
    $subKey = $null
    try
    {
        $subKey = $baseKey.OpenSubKey($Matches[1], $false)
        if ($null -eq $subKey -or $subKey.GetValueNames() -inotcontains $ValueName)
        {
            return @{ State = 'Missing'; Value = $null; Detail = 'Registry value is absent.' }
        }
        return @{
            State = 'Present'
            Value = $subKey.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            Kind = $subKey.GetValueKind($ValueName).ToString()
        }
    }
    finally
    {
        if ($null -ne $subKey) { $subKey.Dispose() }
        $baseKey.Dispose()
    }
}

function Read-PowerStigTextFile
{
    param ([string] $Path)

    if (-not [System.IO.Path]::IsPathRooted($Path) -or $Path.Contains('*') -or $Path.Contains('?'))
    {
        return @{ State = 'Unsupported'; Detail = 'Only exact absolute file paths are supported.' }
    }
    if (-not [System.IO.File]::Exists($Path))
    {
        return @{ State = 'Missing'; Detail = 'The required file does not exist.' }
    }
    $stream = [System.IO.File]::OpenRead($Path)
    $reader = [System.IO.StreamReader]::new($stream)
    try
    {
        if ($stream.Length -gt 1048576)
        {
            throw 'The assessment file exceeds the 1-MiB read limit.'
        }
        return @{ State = 'Present'; Text = $reader.ReadToEnd().Replace("`r`n", "`n") }
    }
    finally
    {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Invoke-PowerStigProcessedCheck
{
    param
    (
        [System.Xml.XmlElement] $Rule,
        [string] $Family
    )

    $id = $Rule.GetAttribute('id')
    $result = [ordered]@{
        Id = $id
        Status = 'Unsupported'
        Expected = 'A compatible read-only adapter for this processed check.'
        Observed = "No admitted adapter for $($Rule.ParentNode.LocalName)/$($Rule.GetAttribute('dscresource'))."
        Adapter = $null
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$Rule.DuplicateOf))
    {
        $result.Status = 'DuplicateReference'
        $result.Observed = "Source identifies duplicate of $($Rule.DuplicateOf); no independent pass is inferred."
    }
    elseif ($Rule.ParentNode.LocalName -in @('ManualRule', 'DocumentRule') -or $Rule.GetAttribute('dscresource') -ceq 'None')
    {
        $result.Status = 'Manual'
        $result.Expected = 'Reviewed manual evidence for the source requirement.'
        $result.Observed = 'No automated host assessment is claimed.'
    }
    elseif ($Rule.GetAttribute('conversionstatus') -cne 'pass')
    {
        $result.Status = 'ConversionFailed'
    }
    elseif ([string]$Rule.OrganizationValueRequired -ieq 'True')
    {
        $result.Status = 'OrganizationValueRequired'
        $result.Expected = 'Explicitly approved organization-specific values.'
        $result.Observed = 'No organization value is substituted from an example/default.'
    }
    elseif ($Family -ceq 'Windows' -and $Rule.ParentNode.LocalName -ceq 'RegistryRule')
    {
        $result.Adapter = 'EffectiveMachineRegistry'
        $result.Expected = "$($Rule.Key)\$($Rule.ValueName) [$($Rule.ValueType)] = $($Rule.ValueData)"
        $actual = Read-PowerStigRegistryValue -Key ([string]$Rule.Key) -ValueName ([string]$Rule.ValueName)
        if ($actual.State -ceq 'Unsupported')
        {
            $result.Observed = $actual.Detail
        }
        elseif ([string]$Rule.ValueData -ceq 'ShouldBeAbsent' -or [string]$Rule.Ensure -ceq 'Absent')
        {
            $result.Status = if ($actual.State -ceq 'Missing') { 'Compliant' } else { 'NonCompliant' }
            $result.Observed = if ($actual.State -ceq 'Missing') { 'Absent' } else { 'Present' }
        }
        elseif ($actual.State -ceq 'Missing')
        {
            $result.Status = 'NonCompliant'
            $result.Observed = $actual.Detail
        }
        elseif ([string]$Rule.ValueType -in @('Dword', 'Qword'))
        {
            $expected = [long]0
            if (-not [long]::TryParse([string]$Rule.ValueData, [ref]$expected))
            {
                throw "Processed numeric registry value is not a literal integer for $id."
            }
            $kindMatches = $actual.Kind -ieq [string]$Rule.ValueType
            $result.Status = if ($kindMatches -and [long]$actual.Value -eq $expected) { 'Compliant' } else { 'NonCompliant' }
            $result.Observed = "$($actual.Value) [$($actual.Kind)]"
        }
        elseif ([string]$Rule.ValueType -in @('String', 'ExpandString', 'MultiString'))
        {
            $expectedValues = @(([string]$Rule.ValueData).Split([string[]]@('{;}'), [System.StringSplitOptions]::None))
            $observedValues = @($actual.Value)
            $expectedJson = ConvertTo-Json -InputObject $expectedValues -Compress
            $observedJson = ConvertTo-Json -InputObject $observedValues -Compress
            $result.Status = if ($actual.Kind -ieq [string]$Rule.ValueType -and $expectedJson -ceq $observedJson) {
                'Compliant'
            } else { 'NonCompliant' }
            $result.Observed = "$observedJson [$($actual.Kind)]"
        }
    }
    elseif ($Family -ceq 'Linux' -and $Rule.ParentNode.LocalName -ceq 'nxFileLineRule')
    {
        $result.Adapter = 'ProcessedFileLineEvidence'
        $result.Expected = "File $($Rule.FilePath) contains the pinned processed line and no prohibited pattern."
        $contains = [string]$Rule.ContainsLine
        if ([string]::IsNullOrEmpty($contains))
        {
            $result.Observed = 'Processed ContainsLine is absent; no line requirement is guessed.'
            return [pscustomobject]$result
        }
        $actual = Read-PowerStigTextFile -Path ([string]$Rule.FilePath)
        if ($actual.State -ceq 'Missing')
        {
            $result.Status = 'NonCompliant'
            $result.Observed = $actual.Detail
        }
        elseif ($actual.State -ceq 'Unsupported')
        {
            $result.Observed = $actual.Detail
        }
        else
        {
            $linePresent = $actual.Text.Contains($contains.Replace("`r`n", "`n"))
            $prohibited = $false
            $pattern = [string]$Rule.DoesNotContainPattern
            if (-not [string]::IsNullOrEmpty($pattern) -and $pattern -cne 'PatternNotRequired')
            {
                $prohibited = [regex]::IsMatch($actual.Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline,
                    [timespan]::FromMilliseconds(250))
            }
            # Static line evidence is not proof of effective daemon/kernel configuration.
            $result.Status = if ($linePresent -and -not $prohibited) { 'EvidenceOnly' } else { 'NonCompliant' }
            $result.Observed = "Pinned text present=$linePresent; prohibited pattern present=$prohibited; effective configuration not assessed."
        }
    }
    return [pscustomobject]$result
}

function Get-PowerStigBaselineAssessment
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Windows', 'Linux')]
        [string] $Family,

        [Parameter()]
        [string] $DataRoot = (Join-Path $PSScriptRoot 'Data'),

        [Parameter()]
        [System.Collections.IDictionary] $HostFacts
    )

    if ($PSVersionTable.PSVersion.Major -lt 7)
    {
        throw 'Assessment execution requires PowerShell 7 or later.'
    }
    if ($null -eq $HostFacts) { $HostFacts = Get-PowerStigMachineConfigurationHost }
    $identity = Resolve-PowerStigMachineConfigurationProfile -HostFacts $HostFacts
    $assessment = [ordered]@{
        SchemaVersion = '1.0'
        CollectedAt = [datetimeoffset]::UtcNow.ToString('o')
        ProfileId = $identity.ProfileId
        HostFacts = $HostFacts
        Status = 'Unsupported'
        Message = $identity.Reason
        BenchmarkId = $null
        BenchmarkVersion = $null
        BenchmarkSha256 = $null
        ProcessedSha256 = $null
        Rules = @()
    }
    if ($HostFacts['Family'] -cne $Family)
    {
        $assessment.Message = 'Policy package family does not match the measured guest family.'
        return [pscustomobject]$assessment
    }
    if ($identity.IdentityState -cne 'Recognized') { return [pscustomobject]$assessment }
    $catalog = Get-Content -LiteralPath (Join-Path $DataRoot 'catalog.json') -Raw -ErrorAction Stop |
        ConvertFrom-Json -AsHashtable -ErrorAction Stop
    if (-not $catalog.ContainsKey($identity.ProfileId))
    {
        $assessment.Message = 'OS recognized, but no exact benchmark/profile is bundled. No neighboring release is substituted.'
        return [pscustomobject]$assessment
    }
    $profile = $catalog[$identity.ProfileId]
    $processedPath = Join-Path $DataRoot $profile.ProcessedFile
    $coveragePath = Join-Path $DataRoot $profile.CoverageFile
    foreach ($pin in @(
        @{ Path = $processedPath; Hash = $profile.ProcessedSha256 }
        @{ Path = $coveragePath; Hash = $profile.CoverageSha256 }
    ))
    {
        if ((Get-FileHash -LiteralPath $pin.Path -Algorithm SHA256 -ErrorAction Stop).Hash -ine $pin.Hash)
        {
            throw "Bundled profile integrity check failed for '$($identity.ProfileId)'."
        }
    }
    $coverage = Get-Content -LiteralPath $coveragePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $xmlSettings = [System.Xml.XmlReaderSettings]::new()
    $xmlSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $xmlSettings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create($processedPath, $xmlSettings)
    $document = [System.Xml.XmlDocument]::new()
    try { $document.Load($reader) } finally { $reader.Dispose() }
    $processed = @{}
    foreach ($rule in $document.DocumentElement.SelectNodes('*/Rule'))
    {
        $processed[$rule.GetAttribute('id')] = $rule
    }
    $assessment.BenchmarkId = $coverage.BenchmarkId
    $assessment.BenchmarkVersion = $coverage.BenchmarkVersion
    $assessment.BenchmarkSha256 = $coverage.BenchmarkSha256
    $assessment.ProcessedSha256 = $profile.ProcessedSha256
    $started = [System.Diagnostics.Stopwatch]::StartNew()
    $assessment.Rules = @(
        foreach ($sourceRule in $coverage.Rules)
        {
            $checks = @(
                foreach ($component in $sourceRule.Components)
                {
                    if ($started.Elapsed.TotalSeconds -gt 120)
                    {
                        [pscustomobject]@{ Id = $component.ProcessedId; Status = 'Error'; Expected = 'Completed collection'; Observed = 'Assessment time budget exhausted.'; Adapter = $null }
                        continue
                    }
                    try
                    {
                        Invoke-PowerStigProcessedCheck -Rule $processed[$component.ProcessedId] -Family $Family
                    }
                    catch
                    {
                        [pscustomobject]@{
                            Id = $component.ProcessedId; Status = 'Error'; Expected = 'Successful read-only collection'
                            Observed = $_.Exception.Message; Adapter = $null
                        }
                    }
                }
            )
            $state = if ($checks.Count -eq 0) { 'Missing' }
                elseif (@($checks | Where-Object Status -CEQ 'Error').Count -gt 0) { 'Error' }
                elseif (@($checks | Where-Object Status -CEQ 'NonCompliant').Count -gt 0) { 'NonCompliant' }
                elseif (@($checks | Where-Object Status -CNE 'Compliant').Count -gt 0) { 'Incomplete' }
                else { 'Compliant' }
            [pscustomobject]@{
                VulnerabilityId = $sourceRule.VulnerabilityId
                RuleId = $sourceRule.RuleId
                StigId = $sourceRule.StigId
                Title = $sourceRule.Title
                Severity = $sourceRule.Severity
                Status = $state
                Checks = $checks
            }
        }
    )
    $assessment.Status = if ($assessment.Rules.Count -eq 0) { 'Error' }
        elseif (@($assessment.Rules | Where-Object Status -CNE 'Compliant').Count -eq 0) { 'Compliant' }
        else { 'NonCompliant' }
    $assessment.Message = "Pinned historical benchmark $($assessment.BenchmarkVersion). Manual, unsupported, partial and organization-dependent checks remain explicit; not a current-release qualification."
    return [pscustomobject]$assessment
}
