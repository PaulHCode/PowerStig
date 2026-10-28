# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Test-PowerStigAuditPackage
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PackagePath,

        [Parameter()]
        [ValidatePattern('^\d+\.\d+\.\d+$')]
        [string]
        $ExpectedVersion,

        [Parameter()]
        [ValidateRange(1, [long]::MaxValue)]
        [long]
        $MaximumExpandedBytes = 104857600
    )

    $packageFile = Get-Item -LiteralPath $PackagePath -ErrorAction Stop

    if ($packageFile.PSIsContainer -or $packageFile.Extension -cne '.zip')
    {
        throw "PackagePath must refer to a ZIP file: $PackagePath"
    }

    $packageName = [System.IO.Path]::GetFileNameWithoutExtension($packageFile.Name)
    $metadataName = "$packageName.metaconfig.json"
    $configurationName = "$packageName.mof"
    $archive = [System.IO.Compression.ZipFile]::OpenRead($packageFile.FullName)

    try
    {
        $metadataEntry = $archive.GetEntry($metadataName)

        if ($null -eq $metadataEntry)
        {
            throw "Audit package is missing its metadata entry '$metadataName'."
        }

        $configurationEntry = $archive.GetEntry($configurationName)

        if ($null -eq $configurationEntry)
        {
            throw "Audit package is missing its compiled configuration '$configurationName'."
        }

        if ($configurationEntry.Length -eq 0)
        {
            throw "Audit package contains an empty compiled configuration '$configurationName'."
        }

        $expandedBytes = [long]0
        $buffer = [byte[]]::new(65536)

        foreach ($entry in $archive.Entries)
        {
            $entryBytes = [long]0
            $entryStream = $entry.Open()

            try
            {
                while (($bytesRead = $entryStream.Read($buffer, 0, $buffer.Length)) -gt 0)
                {
                    if ($bytesRead -gt ($MaximumExpandedBytes - $expandedBytes))
                    {
                        throw "Expanded package size exceeds the $MaximumExpandedBytes-byte limit."
                    }

                    $entryBytes += $bytesRead
                    $expandedBytes += $bytesRead
                }
            }
            finally
            {
                $entryStream.Dispose()
            }

            if ($entryBytes -ne $entry.Length)
            {
                throw "ZIP entry '$($entry.FullName)' expanded to $entryBytes bytes; expected $($entry.Length)."
            }
        }

        $metadataStream = $metadataEntry.Open()
        $reader = [System.IO.StreamReader]::new($metadataStream)

        try
        {
            $metadata = $reader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop
        }
        finally
        {
            $reader.Dispose()
            $metadataStream.Dispose()
        }

        if ($metadata.Type -cne 'Audit')
        {
            throw "Package type must be Audit; found '$($metadata.Type)'."
        }

        if ($metadata.Version -notmatch '^\d+\.\d+\.\d+$')
        {
            throw "Package metadata contains an invalid semantic version '$($metadata.Version)'."
        }

        if ($PSBoundParameters.ContainsKey('ExpectedVersion') -and $metadata.Version -cne $ExpectedVersion)
        {
            throw "Package version '$($metadata.Version)' does not match expected version '$ExpectedVersion'."
        }

        $configurationStream = $configurationEntry.Open()
        $hashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
        try
        {
            $configurationHash = [System.BitConverter]::ToString(
                $hashAlgorithm.ComputeHash($configurationStream)
            ).Replace('-', '')
        }
        finally
        {
            $hashAlgorithm.Dispose()
            $configurationStream.Dispose()
        }

        [pscustomobject]@{
            PackagePath          = $packageFile.FullName
            PackageName          = $packageName
            Type                 = $metadata.Type
            Version              = $metadata.Version
            PackageSha256        = (Get-FileHash -LiteralPath $packageFile.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            CompressedSizeBytes  = $packageFile.Length
            ExpandedSizeBytes    = $expandedBytes
            EntryCount           = $archive.Entries.Count
            ConfigurationMofName = $configurationName
            ConfigurationMofSha256 = $configurationHash
        }
    }
    finally
    {
        $archive.Dispose()
    }
}

function New-PowerStigAuditPackage
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$')]
        [string]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ConfigurationMofPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutputPath,

        [Parameter()]
        [ValidatePattern('^\d+\.\d+\.\d+$')]
        [string]
        $PackageVersion = '1.0.0',

        [Parameter()]
        [ValidatePattern('^\d+\.\d+\.\d+$')]
        [string]
        $GuestConfigurationVersion = '4.10.0',

        [Parameter()]
        [switch]
        $Force
    )

    if ($PSVersionTable.PSVersion.Major -lt 7)
    {
        throw 'PowerStig Azure Machine Configuration package creation requires PowerShell 7 or later.'
    }

    $configurationFile = Get-Item -LiteralPath $ConfigurationMofPath -ErrorAction Stop

    if ($configurationFile.PSIsContainer -or $configurationFile.Extension -cne '.mof')
    {
        throw 'ConfigurationMofPath must refer to a compiled .mof file.'
    }

    $outputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

    if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container))
    {
        $null = New-Item -Path $outputDirectory -ItemType Directory -Force -ErrorAction Stop
    }

    $packagePath = Join-Path -Path $outputDirectory -ChildPath "$Name.zip"

    if ((Test-Path -LiteralPath $packagePath) -and -not $Force)
    {
        throw "Package already exists at '$packagePath'. Use -Force to replace it."
    }

    Import-PowerStigGuestConfiguration -Version $GuestConfigurationVersion

    $packageParameters = @{
        Name          = $Name
        Configuration = $configurationFile.FullName
        Version       = $PackageVersion
        Type          = 'Audit'
        Path          = $outputDirectory
        ErrorAction   = 'Stop'
    }

    if ($Force)
    {
        $packageParameters.Force = $true
    }

    Invoke-PowerStigGuestConfigurationPackage -PackageParameters $packageParameters -Version $GuestConfigurationVersion

    if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf))
    {
        throw "GuestConfiguration completed without creating the expected package '$packagePath'."
    }

    Test-PowerStigAuditPackage -PackagePath $packagePath -ExpectedVersion $PackageVersion
}

function Import-PowerStigGuestConfiguration
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^\d+\.\d+\.\d+$')]
        [string]
        $Version
    )

    $loadedModule = Get-Module -Name GuestConfiguration |
        Where-Object -FilterScript { $PSItem.Version -eq [version] $Version } |
        Select-Object -First 1

    if ($null -eq $loadedModule)
    {
        Import-Module -Name GuestConfiguration -RequiredVersion $Version -ErrorAction Stop
    }
}

function Invoke-PowerStigGuestConfigurationPackage
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [hashtable]
        $PackageParameters,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^\d+\.\d+\.\d+$')]
        [string]
        $Version
    )

    $modules = @(Get-Module -Name GuestConfiguration |
        Where-Object { $_.Version -eq [version]$Version })
    if ($modules.Count -ne 1)
    {
        throw "Expected exactly one loaded GuestConfiguration $Version module."
    }
    $command = $modules[0].ExportedCommands['New-GuestConfigurationPackage']
    if ($command -isnot [System.Management.Automation.CommandInfo])
    {
        throw "GuestConfiguration $Version does not export New-GuestConfigurationPackage."
    }
    $null = & $command @PackageParameters
}
