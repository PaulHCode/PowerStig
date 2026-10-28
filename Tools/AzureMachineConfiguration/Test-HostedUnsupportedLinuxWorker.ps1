# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true)]
    [string] $PackagePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string] $ExpectedPackageSha256,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
if (-not $IsLinux -or $env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Linux')
{
    throw 'Worker execution is restricted to an ephemeral GitHub-hosted Linux runner.'
}
if (Test-Path -LiteralPath $OutputPath) { throw 'Use a fresh worker output directory.' }
. "$PSScriptRoot\AuditPackage.ps1"
. "$PSScriptRoot\WorkerReportShape.ps1"
. "$PSScriptRoot\UnsupportedWorkerReport.ps1"
$null = New-Item -Path $OutputPath -ItemType Directory
$stage = 'Package'
try
{
    $package = Test-PowerStigAuditPackage -PackagePath $PackagePath -ExpectedVersion '0.2.0'
    if ($package.PackageName -cne 'PowerStigFleetLinux' -or
        $package.PackageSha256 -ine $ExpectedPackageSha256)
    {
        throw 'Expected the exact Linux Audit package from the dependent Windows authoring job.'
    }
    $facts = Get-PowerStigMachineConfigurationHost
    $identity = Resolve-PowerStigMachineConfigurationProfile -HostFacts $facts
    if ($identity.IdentityState -cne 'Recognized')
    {
        throw 'The negative test requires a recognized but unbundled Linux release.'
    }
    $archive = [IO.Compression.ZipFile]::OpenRead($package.PackagePath)
    try
    {
        $entry = $archive.GetEntry('Modules/PowerStig.MachineConfiguration/Data/catalog.json')
        if ($null -eq $entry -or $entry.Length -gt 1048576) { throw 'Missing or oversized package catalog.' }
        $reader = [IO.StreamReader]::new($entry.Open())
        try { $catalog = $reader.ReadToEnd() | ConvertFrom-Json -AsHashtable }
        finally { $reader.Dispose() }
    }
    finally { $archive.Dispose() }
    if ($catalog.ContainsKey($identity.ProfileId))
    {
        throw 'The measured profile is bundled; use the supported-profile contract instead.'
    }
    Import-PowerStigGuestConfiguration -Version '4.10.0'
    $modules = @(Get-Module GuestConfiguration | Where-Object Version -EQ ([version]'4.10.0'))
    if ($modules.Count -ne 1) { throw 'Expected one pinned GuestConfiguration 4.10.0 module.' }
    $command = $modules[0].ExportedCommands['Get-GuestConfigurationPackageComplianceStatus']
    if ($command -isnot [Management.Automation.CommandInfo]) { throw 'Pinned worker command is unavailable.' }
    $stage = 'Worker'
    $report = & $command -Path $package.PackagePath -ErrorAction Stop
    $reportJson = $report | ConvertTo-Json -Depth 40
    $rawPath = Join-Path $OutputPath 'worker-report.private.json'
    [IO.File]::WriteAllText($rawPath, $reportJson)
    $reportObject = ConvertFrom-Json -InputObject $reportJson -AsHashtable -Depth 40
    $summary = [ordered]@{
        EvidenceKind = 'EphemeralLinuxUnsupportedWorkerNotAzurePolicyAdmission'
        PackageSha256 = $package.PackageSha256
        ProfileId = $identity.ProfileId
        Shape = Get-PowerStigWorkerReportShape -Report $reportObject
        NativeReportSha256 = (Get-FileHash -LiteralPath $rawPath).Hash
        UnsupportedContractValidated = $false
        NativeAzureReportAdmitted = $false
    }
    $summary | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath (Join-Path $OutputPath 'worker-summary.json') -Encoding utf8
    $stage = 'UnsupportedContract'
    $contract = Test-PowerStigUnsupportedLinuxWorkerReport -Report $reportObject -HostFacts $facts
    $summary.UnsupportedContractValidated = $contract.UnsupportedContractValidated
    $summary.WorkerComplianceStatus = $contract.WorkerComplianceStatus
    $summary | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath (Join-Path $OutputPath 'worker-summary.json') -Encoding utf8
}
catch
{
    [ordered]@{
        Stage = $stage
        ExceptionType = $_.Exception.GetType().FullName
        Category = $_.CategoryInfo.Category.ToString()
        SourceFile = [IO.Path]::GetFileName($_.InvocationInfo.ScriptName)
        SourceLine = $_.InvocationInfo.ScriptLineNumber
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputPath 'worker-failure.json') -Encoding utf8
    throw
}
