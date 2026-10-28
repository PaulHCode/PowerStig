# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Test-PowerStigAuditPolicyDefinition
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PolicyPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PackagePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ContentUri,

        [Parameter(Mandatory = $true)]
        [guid]
        $ExpectedPolicyId
    )

    $policyFile = Get-Item -LiteralPath $PolicyPath -ErrorAction Stop

    if ($policyFile.PSIsContainer -or $policyFile.Extension -cne '.json')
    {
        throw "PolicyPath must refer to a JSON file: $PolicyPath"
    }

    if ($ExpectedPolicyId -eq [guid]::Empty)
    {
        throw 'ExpectedPolicyId cannot be an empty GUID.'
    }

    $package = Test-PowerStigAuditPackage -PackagePath $PackagePath
    $packageUri = ConvertTo-PowerStigAuditContentUri -ContentUri $ContentUri
    $policy = Get-Content -LiteralPath $policyFile.FullName -Raw -ErrorAction Stop |
        ConvertFrom-Json -AsHashtable -Depth 100 -ErrorAction Stop

    $policyId = [guid]::Empty
    if (-not [guid]::TryParse([string]$policy['name'], [ref]$policyId))
    {
        throw 'Policy definition contains a missing or invalid name GUID.'
    }

    if ($policyId -ne $ExpectedPolicyId)
    {
        throw "Policy definition ID '$policyId' does not match expected ID '$ExpectedPolicyId'."
    }

    $properties = $policy['properties']
    $guestConfiguration = $properties['metadata']['guestConfiguration']
    $policyRule = $properties['policyRule']
    $then = $policyRule['then']
    $details = $then['details']

    if ($null -eq $guestConfiguration -or $null -eq $details)
    {
        throw 'Policy definition is missing Guest Configuration metadata or an audit condition.'
    }

    if ($then['effect'] -cne 'auditIfNotExists')
    {
        throw "Policy effect must be auditIfNotExists; found '$($then['effect'])'."
    }

    if ($details['type'] -cne 'Microsoft.GuestConfiguration/guestConfigurationAssignments')
    {
        throw "Policy must audit Guest Configuration assignments; found '$($details['type'])'."
    }

    $expectedAssignmentName = "[concat('$($package.PackageName)`$pid', uniqueString(policy().assignmentId, policy().definitionReferenceId))]"
    if ($details['name'] -isnot [string] -or $details['name'] -cne $expectedAssignmentName)
    {
        throw 'Policy must target the exact Policy-derived Guest Configuration assignment name for this package.'
    }

    if (
        $guestConfiguration['contentType'] -cne 'Custom' -or
        $guestConfiguration['name'] -cne $package.PackageName -or
        $guestConfiguration['version'] -cne $package.Version
    )
    {
        throw 'Policy Guest Configuration identity does not match the validated Audit package.'
    }

    if ($guestConfiguration['contentUri'] -cne $packageUri.AbsoluteUri)
    {
        throw 'Policy package content URI does not match the requested URI.'
    }

    if ($guestConfiguration['contentHash'] -ine $package.PackageSha256)
    {
        throw 'Policy package content hash does not match the validated Audit package.'
    }

    if ($guestConfiguration['contentManagedIdentity'] -cne 'system')
    {
        throw 'Policy must use the system-assigned identity for package content.'
    }

    $existenceCondition = $details['existenceCondition']
    $conditions = @($existenceCondition['allOf'])
    $requiredConditions = Get-PowerStigAuditExistenceCondition -Package $package
    if ($existenceCondition.Keys.Count -ne 1 -or $conditions.Count -ne $requiredConditions.allOf.Count)
    {
        throw 'Policy must require compliance and the exact configuration name, version and content hash in allOf.'
    }

    foreach ($requiredCondition in $requiredConditions.allOf)
    {
        $matchingConditions = @($conditions | Where-Object {
            $_['field'] -is [string] -and $_['field'] -ceq $requiredCondition.field
        })
        if (
            $matchingConditions.Count -ne 1 -or $matchingConditions[0].Keys.Count -ne 2 -or
            $matchingConditions[0]['equals'] -isnot [string] -or
            $matchingConditions[0]['equals'] -ine $requiredCondition.equals
        )
        {
            throw "Policy must bind assignment field '$($requiredCondition.field)' to the validated Audit package."
        }
    }

    [pscustomobject]@{
        PolicyPath      = $policyFile.FullName
        PolicyId        = $policyId
        PackageName     = $package.PackageName
        PackageVersion  = $package.Version
        PackageSha256   = $package.PackageSha256
        ContentUri      = $packageUri.AbsoluteUri
        Effect          = $then['effect']
        AssignmentType  = 'Audit'
        ContentIdentity = $guestConfiguration['contentManagedIdentity']
    }
}

function New-PowerStigAuditPolicyDefinition
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PackagePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ContentUri,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DisplayName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Description,

        [Parameter(Mandatory = $true)]
        [guid]
        $PolicyId,

        [Parameter()]
        [ValidatePattern('^\d+\.\d+\.\d+$')]
        [string]
        $PolicyVersion = '1.0.0',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutputPath,

        [Parameter()]
        [ValidateSet('Windows', 'Linux')]
        [string]
        $Platform = 'Windows',

        [Parameter()]
        [bool]
        $IncludeVMSS = $true,

        [Parameter()]
        [ValidatePattern('^\d+\.\d+\.\d+$')]
        [string]
        $GuestConfigurationVersion = '4.10.0',

        [Parameter()]
        [switch]
        $Force
    )

    if ($PolicyId -eq [guid]::Empty)
    {
        throw 'PolicyId cannot be an empty GUID.'
    }

    if ($DisplayName.Length -gt 128)
    {
        throw 'DisplayName cannot exceed 128 characters.'
    }

    if ($Description.Length -gt 512)
    {
        throw 'Description cannot exceed 512 characters.'
    }

    $package = Test-PowerStigAuditPackage -PackagePath $PackagePath
    $packageUri = ConvertTo-PowerStigAuditContentUri -ContentUri $ContentUri
    $outputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

    if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container))
    {
        $null = New-Item -Path $outputDirectory -ItemType Directory -Force -ErrorAction Stop
    }

    $policyName = "$($package.PackageName)_AuditIfNotExists.json"
    $policyPath = Join-Path -Path $outputDirectory -ChildPath $policyName

    if ((Test-Path -LiteralPath $policyPath) -and -not $Force)
    {
        throw "Policy definition already exists at '$policyPath'. Use -Force to replace it."
    }

    $installedModule = Get-Module -ListAvailable -Name GuestConfiguration |
        Where-Object -FilterScript { $PSItem.Version -eq [version]$GuestConfigurationVersion } |
        Select-Object -First 1

    if ($null -eq $installedModule)
    {
        throw "GuestConfiguration $GuestConfigurationVersion is not installed. Install the pinned module before generating the policy."
    }

    $sourceModuleRoot = Split-Path -Path $installedModule.Path -Parent
    $sourceModuleScript = Join-Path -Path $sourceModuleRoot -ChildPath 'GuestConfiguration.psm1'
    $sourceTemplates = Join-Path -Path $sourceModuleRoot -ChildPath 'templates'

    if (-not (Test-Path -LiteralPath $sourceModuleScript -PathType Leaf))
    {
        throw "GuestConfiguration module script was not found at '$sourceModuleScript'."
    }

    if (-not (Test-Path -LiteralPath $sourceTemplates -PathType Container))
    {
        throw "GuestConfiguration templates were not found at '$sourceTemplates'."
    }

    $workRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "PowerStigGuestConfiguration_$([guid]::NewGuid().ToString('N'))"
    $stagingDirectory = Join-Path -Path $outputDirectory -ChildPath ".$($package.PackageName)_policy_$([guid]::NewGuid().ToString('N'))"
    $isolatedModule = $null

    if ((Test-Path -LiteralPath $workRoot) -or (Test-Path -LiteralPath $stagingDirectory))
    {
        throw 'A generated temporary path already exists; refusing to reuse or remove it.'
    }

    $null = New-Item -Path $workRoot -ItemType Directory -ErrorAction Stop
    $null = New-Item -Path $stagingDirectory -ItemType Directory -ErrorAction Stop

    try
    {
        $isolatedModuleScript = Join-Path -Path $workRoot -ChildPath 'GuestConfiguration.psm1'
        $isolatedTemplates = Join-Path -Path $workRoot -ChildPath 'templates'

        Copy-Item -LiteralPath $sourceModuleScript -Destination $isolatedModuleScript -ErrorAction Stop
        Copy-Item -LiteralPath $sourceTemplates -Destination $workRoot -Recurse -ErrorAction Stop

        $sourceModuleHash = (Get-FileHash -LiteralPath $sourceModuleScript -Algorithm SHA256 -ErrorAction Stop).Hash
        $isolatedModuleHash = (Get-FileHash -LiteralPath $isolatedModuleScript -Algorithm SHA256 -ErrorAction Stop).Hash

        if ($sourceModuleHash -cne $isolatedModuleHash)
        {
            throw 'Isolated GuestConfiguration module script does not match the installed pinned module.'
        }

        $templateFiles = @(Get-ChildItem -LiteralPath $sourceTemplates -File -Recurse -ErrorAction Stop)

        if ($templateFiles.Count -eq 0)
        {
            throw 'The installed GuestConfiguration module has no policy templates.'
        }

        foreach ($templateFile in $templateFiles)
        {
            $relativePath = [System.IO.Path]::GetRelativePath($sourceTemplates, $templateFile.FullName)
            $isolatedTemplatePath = Join-Path -Path $isolatedTemplates -ChildPath $relativePath

            if (-not (Test-Path -LiteralPath $isolatedTemplatePath -PathType Leaf))
            {
                throw "Isolated GuestConfiguration template is missing '$relativePath'."
            }

            $sourceTemplateHash = (Get-FileHash -LiteralPath $templateFile.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            $isolatedTemplateHash = (Get-FileHash -LiteralPath $isolatedTemplatePath -Algorithm SHA256 -ErrorAction Stop).Hash

            if ($sourceTemplateHash -cne $isolatedTemplateHash)
            {
                throw "Isolated GuestConfiguration template '$relativePath' does not match the installed pinned module."
            }
        }

        $guestConfigurationParameters = @{
            ContentUri                = $packageUri
            DisplayName               = $DisplayName
            Description               = $Description
            PolicyId                  = $PolicyId
            PolicyVersion             = [version]$PolicyVersion
            Path                      = $stagingDirectory
            Platform                  = $Platform
            Mode                      = 'Audit'
            ContentVersion            = [version]$package.Version
            LocalContentPath          = $package.PackagePath
            UseSystemAssignedIdentity = $true
            IncludeVMSS               = $IncludeVMSS
            ErrorAction               = 'Stop'
        }

        $isolatedModule = Import-Module -Name $isolatedModuleScript -Force -PassThru -ErrorAction Stop
        $generatedPolicy = Invoke-PowerStigGuestConfigurationPolicy `
            -Module $isolatedModule `
            -PolicyParameters $guestConfigurationParameters

        if ($null -eq $generatedPolicy -or -not (Test-Path -LiteralPath $generatedPolicy.Path -PathType Leaf))
        {
            throw 'GuestConfiguration completed without creating the expected policy definition.'
        }

        # The pinned template checks status alone; also bind the evaluated assignment's package.
        $generatedDefinition = Get-Content -LiteralPath $generatedPolicy.Path -Raw -ErrorAction Stop |
            ConvertFrom-Json -AsHashtable -Depth 100 -ErrorAction Stop
        $generatedDefinition['properties']['policyRule']['then']['details']['existenceCondition'] =
            Get-PowerStigAuditExistenceCondition -Package $package
        $generatedDefinition | ConvertTo-Json -Depth 100 |
            Set-Content -LiteralPath $generatedPolicy.Path -Encoding utf8 -ErrorAction Stop

        $null = Test-PowerStigAuditPolicyDefinition `
            -PolicyPath $generatedPolicy.Path `
            -PackagePath $package.PackagePath `
            -ContentUri $packageUri.AbsoluteUri `
            -ExpectedPolicyId $PolicyId

        [System.IO.File]::Move($generatedPolicy.Path, $policyPath, [bool]$Force)

        Test-PowerStigAuditPolicyDefinition `
            -PolicyPath $policyPath `
            -PackagePath $package.PackagePath `
            -ContentUri $packageUri.AbsoluteUri `
            -ExpectedPolicyId $PolicyId
    }
    finally
    {
        if ($null -ne $isolatedModule)
        {
            Remove-Module -ModuleInfo $isolatedModule -ErrorAction Stop
        }

        if (Test-Path -LiteralPath $workRoot)
        {
            Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction Stop
        }

        if (Test-Path -LiteralPath $stagingDirectory)
        {
            Remove-Item -LiteralPath $stagingDirectory -Recurse -Force -ErrorAction Stop
        }
    }
}

function Get-PowerStigAuditExistenceCondition
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $Package
    )

    $aliasPrefix = 'Microsoft.GuestConfiguration/guestConfigurationAssignments'
    @{
        allOf = @(
            @{ field = "$aliasPrefix/complianceStatus"; equals = 'Compliant' }
            @{ field = "$aliasPrefix/guestConfiguration.name"; equals = $Package.PackageName }
            @{ field = "$aliasPrefix/guestConfiguration.version"; equals = $Package.Version }
            @{ field = "$aliasPrefix/guestConfiguration.contentHash"; equals = $Package.PackageSha256 }
        )
    }
}

function Invoke-PowerStigGuestConfigurationPolicy
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSModuleInfo]
        $Module,

        [Parameter(Mandatory = $true)]
        [hashtable]
        $PolicyParameters
    )

    & $Module {
        param
        (
            [Parameter(Mandatory = $true)]
            [hashtable]
            $Parameters
        )

        New-GuestConfigurationPolicy @Parameters
    } $PolicyParameters
}

function ConvertTo-PowerStigAuditContentUri
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ContentUri
    )

    $packageUri = $null

    if (-not [System.Uri]::TryCreate($ContentUri, [System.UriKind]::Absolute, [ref]$packageUri))
    {
        throw 'ContentUri must be an absolute HTTPS URI.'
    }

    if (
        $packageUri.Scheme -cne 'https' -or
        [string]::IsNullOrWhiteSpace($packageUri.Host) -or
        -not [string]::IsNullOrEmpty($packageUri.UserInfo) -or
        -not [string]::IsNullOrEmpty($packageUri.Query) -or
        -not [string]::IsNullOrEmpty($packageUri.Fragment)
    )
    {
        throw 'ContentUri must be an HTTPS URI without embedded credentials, query tokens, or fragments.'
    }

    return $packageUri
}
