# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true)]
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows')
{
    throw 'Worker execution is restricted to an ephemeral GitHub-hosted Windows runner.'
}
if (Test-Path -LiteralPath $OutputPath) { throw 'Use a fresh worker output directory.' }
. "$PSScriptRoot\AuditPackage.ps1"
. "$PSScriptRoot\Profile.ps1"
. "$PSScriptRoot\WorkerReportShape.ps1"
. "$PSScriptRoot\FleetAssessmentReport.ps1"
$stage = 'Build'
try
{
    $null = & "$PSScriptRoot\Build-FleetPackage.ps1" -Family Windows -OutputPath $OutputPath
    $package = Test-PowerStigAuditPackage -PackagePath "$OutputPath\PowerStigFleetWindows.zip" -ExpectedVersion '0.2.0'
    $module = @(Get-Module GuestConfiguration | Where-Object Version -EQ ([version]'4.10.0'))
    if ($module.Count -ne 1) { throw 'Expected one pinned GuestConfiguration 4.10.0 module.' }
    $command = $module[0].ExportedCommands['Get-GuestConfigurationPackageComplianceStatus']
    if ($command -isnot [System.Management.Automation.CommandInfo]) { throw 'Pinned worker-test command is unavailable.' }
    $facts = Get-PowerStigMachineConfigurationHost
    $identity = Resolve-PowerStigMachineConfigurationProfile -HostFacts $facts
    $catalogPath = "$OutputPath\modules\PowerStig.MachineConfiguration\0.2.0\Data\catalog.json"
    $catalog = Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json -AsHashtable
    if ($identity.IdentityState -cne 'Recognized' -or -not $catalog.ContainsKey($identity.ProfileId))
    {
        throw 'The hosted runner does not have an admitted bundled Windows profile.'
    }
    $coveragePath = Join-Path (Split-Path $catalogPath) $catalog[$identity.ProfileId].CoverageFile
    if ((Get-FileHash -LiteralPath $coveragePath).Hash -cne $catalog[$identity.ProfileId].CoverageSha256)
    {
        throw 'Hosted coverage integrity mismatch.'
    }
    $coverage = Get-Content -LiteralPath $coveragePath -Raw | ConvertFrom-Json -AsHashtable
    $stage = 'Worker'
    $report = & $command -Path $package.PackagePath -ErrorAction Stop
    $reportJson = $report | ConvertTo-Json -Depth 40
    $rawPath = Join-Path $OutputPath 'worker-report.private.json'
    [IO.File]::WriteAllText($rawPath, $reportJson)
    $reportObject = ConvertFrom-Json -InputObject $reportJson -AsHashtable -Depth 40 -ErrorAction Stop
    $shape = Get-PowerStigWorkerReportShape -Report $reportObject
    $stage = 'ReportContract'
    $expectedCodes = @('PowerStigBaseline:PowerStigBaseline:Summary') + @(
        $coverage.Rules | ForEach-Object { "PowerStigBaseline:PowerStigBaseline:$($_.VulnerabilityId.Replace('-', ''))" }
    )
    $missing = @($expectedCodes | Where-Object { $_ -cnotin $shape.PowerStigReasonCodes })
    $unexpected = @($shape.PowerStigReasonCodes | Where-Object { $_ -cnotin $expectedCodes })
    $summary = [ordered]@{
        EvidenceKind = 'EphemeralWindowsWorkerNotAzurePolicyAdmission'
        PackageSha256 = $package.PackageSha256
        ProfileId = $identity.ProfileId
        RequirementCount = $coverage.RequirementCount
        WorkerComplianceStatus = $(if ($reportObject['complianceStatus'] -is [bool]) { $reportObject['complianceStatus'] } else { $null })
        ReasonCount = $shape.PowerStigReasonCodes.Count
        MissingReasonCount = $missing.Count
        UnexpectedReasonCount = $unexpected.Count
        NativeReportSha256 = (Get-FileHash -LiteralPath $rawPath).Hash
        Shape = $shape
        PayloadValidated = $false
        NativeReasonPhrasesValidated = $false
        NativeAzureReportAdmitted = $false
    }
    $summary | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath "$OutputPath\worker-summary.json" -Encoding utf8
    if ($reportObject['complianceStatus'] -isnot [bool] -or $reportObject['complianceStatus'] -or
        @($reportObject['resources']).Count -ne 1 -or $missing.Count -or $unexpected.Count)
    {
        throw 'Worker output did not preserve the expected incomplete baseline and complete source Reasons. Inspect the scalar-redacted shape artifact.'
    }
    $stage = 'PayloadContract'
    $resource = $reportObject['resources'][0]
    if ($resource['complianceStatus'] -isnot [bool] -or $resource['complianceStatus'] -or
        $resource['properties']['AssessmentJson'] -isnot [string])
    {
        throw 'Expected a noncompliant resource with the complete serialized assessment.'
    }
    $payload = ConvertFrom-PowerStigFleetAssessment -AssessmentJson $resource['properties']['AssessmentJson'] `
        -CoveragePath $coveragePath -ExpectedCoverageHash $catalog[$identity.ProfileId].CoverageSha256 `
        -ExpectedProfileId $identity.ProfileId -ExpectedFamily Windows
    if ($payload.IsStale -or $payload.RuleCounts.Error -gt 0)
    {
        throw 'The worker assessment is stale or contains collector errors.'
    }
    $assessment = ConvertFrom-Json -InputObject $resource['properties']['AssessmentJson'] -AsHashtable -Depth 40
    $expectedPhrases = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
    $expectedPhrases.Add('PowerStigBaseline:PowerStigBaseline:Summary',
        "$($assessment.ProfileId): $($assessment.Status). $($assessment.Message)")
    foreach ($rule in $payload.Requirements)
    {
        $phrase = "$($rule.VulnerabilityId): $($rule.Status). $($rule.Title)"
        foreach ($check in $rule.Checks)
        {
            $phrase += " [$($check.Id): $($check.Status); expected=$($check.Expected); observed=$($check.Observed)]"
        }
        $expectedPhrases.Add("PowerStigBaseline:PowerStigBaseline:$($rule.VulnerabilityId.Replace('-', ''))", $phrase)
    }
    foreach ($reasons in @(
        @{ Items = @($resource['reasons']); Code = 'code'; Phrase = 'phrase' },
        @{ Items = @($resource['properties']['Reasons']); Code = 'Code'; Phrase = 'Phrase' }
    ))
    {
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        if ($reasons.Items.Count -ne $expectedPhrases.Count) { throw 'Native reason inventory is incomplete.' }
        foreach ($reason in $reasons.Items)
        {
            $code = $reason[$reasons.Code]
            if ($code -isnot [string] -or -not $expectedPhrases.ContainsKey($code) -or -not $seen.Add($code) -or
                $reason[$reasons.Phrase] -cne $expectedPhrases[$code])
            {
                throw 'Native reason explanation differs from the validated requirement/check evidence.'
            }
        }
    }
    $summary.PayloadValidated = $true
    $summary.NativeReasonPhrasesValidated = $true
    $summary.PayloadStatus = $payload.PayloadStatus
    $summary.RuleCounts = $payload.RuleCounts
    $summary.CheckCounts = $payload.CheckCounts
    $summary | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath "$OutputPath\worker-summary.json" -Encoding utf8
}
catch
{
    if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -Path $OutputPath -ItemType Directory }
    $failure = [ordered]@{
        Stage = $stage
        ExceptionType = $_.Exception.GetType().FullName
        Category = $_.CategoryInfo.Category.ToString()
        SourceFile = [IO.Path]::GetFileName($_.InvocationInfo.ScriptName)
        SourceLine = $_.InvocationInfo.ScriptLineNumber
    }
    $compileLog = "$OutputPath\PowerStigFleetWindows.compile.log"
    if ($stage -ceq 'Build' -and (Test-Path -LiteralPath $compileLog))
    {
        # Compilation precedes collection; this diagnostic contains authoring output only.
        $compileText = Get-Content -LiteralPath $compileLog -Raw
        $failure.CompileDiagnostics = $compileText.Substring(0, [Math]::Min(16384, $compileText.Length))
    }
    $failure | ConvertTo-Json | Set-Content -LiteralPath "$OutputPath\worker-failure.json" -Encoding utf8
    throw
}
