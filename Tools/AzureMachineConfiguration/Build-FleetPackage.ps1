# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [Parameter()]
    [ValidateSet('Windows', 'Linux', 'Both')]
    [string] $Family = 'Both'
)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows)
{
    throw 'This build uses Windows PowerShell to compile the cross-platform class-resource MOF. Run on a Windows authoring host.'
}
. "$PSScriptRoot\Coverage.ps1"
. "$PSScriptRoot\AuditPackage.ps1"

$output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$null = New-Item -Path $output -ItemType Directory -Force
$moduleParent = Join-Path $output 'modules'
$modulePath = Join-Path (Join-Path $moduleParent 'PowerStig.MachineConfiguration') '0.2.0'
if (Test-Path -LiteralPath $modulePath)
{
    throw 'Use a fresh build output directory; existing module staging is never overwritten.'
}
$null = New-Item -Path $modulePath -ItemType Directory -Force
Copy-Item -Path "$PSScriptRoot\PowerStig.MachineConfiguration\*" -Destination $modulePath -Recurse
$dataPath = Join-Path $modulePath 'Data'
$null = New-Item -Path $dataPath -ItemType Directory
$sourceRoot = (Resolve-Path "$PSScriptRoot\..\..\source\StigData").Path
$profiles = [ordered]@{
    'WindowsClient-11' = 'WindowsClient-11-2.7.xml'
    'WindowsServer-2016-MS' = 'WindowsServer-2016-MS-2.10.xml'
    'WindowsServer-2019-MS' = 'WindowsServer-2019-MS-3.8.xml'
    'WindowsServer-2022-MS' = 'WindowsServer-2022-MS-2.8.xml'
    'WindowsServer-2025-MS' = 'WindowsServer-2025-MS-1.1.xml'
    'RHEL-9' = 'RHEL-9-2.8.xml'
    'Ubuntu-18.04' = 'Ubuntu-18.04-2.15.xml'
}
$catalog = [ordered]@{}
foreach ($profileId in $profiles.Keys)
{
    $processedPath = Join-Path (Join-Path $sourceRoot 'Processed') $profiles[$profileId]
    [xml]$processed = Get-Content -LiteralPath $processedPath -Raw
    $sources = @(Get-ChildItem -LiteralPath (Join-Path $sourceRoot 'Archive') -Filter $processed.DISASTIG.filename -File -Recurse)
    if ($sources.Count -ne 1)
    {
        throw "Expected one exact source benchmark for '$profileId'; found $($sources.Count)."
    }
    $coverage = Get-PowerStigMachineConfigurationCoverage -BenchmarkPath $sources[0].FullName -ProcessedPath $processedPath
    if (-not $coverage.SourceMatches) { throw "Source mismatch for '$profileId'." }
    $coverageFile = "$profileId.coverage.json"
    $coverage | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $dataPath $coverageFile) -Encoding utf8
    Copy-Item -LiteralPath $processedPath -Destination $dataPath
    $catalog[$profileId] = @{
        ProcessedFile = $profiles[$profileId]
        ProcessedSha256 = $coverage.ProcessedSha256
        CoverageFile = $coverageFile
        CoverageSha256 = (Get-FileHash -LiteralPath (Join-Path $dataPath $coverageFile) -Algorithm SHA256).Hash
        BenchmarkId = $coverage.BenchmarkId
        BenchmarkVersion = $coverage.BenchmarkVersion
        BenchmarkSha256 = $coverage.BenchmarkSha256
    }
}
$catalog | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $dataPath 'catalog.json') -Encoding utf8

$initialModulePath = $env:PSModulePath
try
{
    $env:PSModulePath = "$moduleParent$([System.IO.Path]::PathSeparator)$initialModulePath"
    $families = if ($Family -ceq 'Both') { @('Windows', 'Linux') } else { @($Family) }
    foreach ($targetFamily in $families)
    {
        $name = "PowerStigFleet$targetFamily"
        $compileScript = Join-Path $output "$name.compile.ps1"
        $mofDirectory = Join-Path $output $name
        $escapedMofDirectory = $mofDirectory.Replace("'", "''")
        $compile = @(
            '$ErrorActionPreference = ''Stop'''
            "configuration $name"
            '{'
            '    Import-DscResource -ModuleName PowerStig.MachineConfiguration -ModuleVersion 0.2.0'
            '    Node localhost'
            '    {'
            '        PowerStigBaseline Baseline'
            '        {'
            "            Name = 'Audit'"
            "            Family = '$targetFamily'"
            '        }'
            '    }'
            '}'
            "$name -OutputPath '$escapedMofDirectory'"
        )
        $compile | Set-Content -LiteralPath $compileScript -Encoding utf8
        & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -File $compileScript
        if ($LASTEXITCODE -ne 0) { throw "MOF compilation failed for $targetFamily." }
        $package = New-PowerStigAuditPackage -Name $name `
            -ConfigurationMofPath (Join-Path $mofDirectory 'localhost.mof') `
            -OutputPath $output -PackageVersion '0.2.0'
        $package | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $output "$name.manifest.json") -Encoding utf8
        $package
    }
}
finally
{
    $env:PSModulePath = $initialModulePath
}
