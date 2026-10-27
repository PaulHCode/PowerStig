# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Get-PowerStigMachineConfigurationHost
{
    [CmdletBinding()]
    param ()

    if ($IsWindows)
    {
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        return @{
            Family      = 'Windows'
            Build       = [string]$operatingSystem.BuildNumber
            ProductType = [int]$operatingSystem.ProductType
            DomainRole  = [int]$computerSystem.DomainRole
        }
    }

    if (-not $IsLinux)
    {
        throw 'Machine Configuration host discovery supports only Windows and Linux.'
    }

    $values = @{}
    foreach ($line in [System.IO.File]::ReadAllLines('/etc/os-release'))
    {
        if ($line -match '^(ID|VERSION_ID)=(.*)$')
        {
            $key = $Matches[1]
            $value = $Matches[2]
            if ($values.ContainsKey($key))
            {
                throw "os-release contains duplicate '$key' values."
            }
            if ($value -match '^"([^"\\]*)"$' -or $value -match "^'([^']*)'$")
            {
                $value = $Matches[1]
            }
            if ($value -notmatch '^[A-Za-z0-9._-]+$')
            {
                throw "os-release contains an invalid '$key' value."
            }
            $values[$key] = $value
        }
    }
    return @{ Family = 'Linux'; Id = $values.ID; VersionId = $values.VERSION_ID }
}

function Resolve-PowerStigMachineConfigurationProfile
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary] $HostFacts
    )

    $profileId = $null
    $reason = 'The measured operating system has no exact supported profile identity.'
    if ($HostFacts['Family'] -ceq 'Windows')
    {
        if (
            -not $HostFacts.Contains('ProductType') -or -not $HostFacts.Contains('DomainRole') -or
            [string]$HostFacts['ProductType'] -notmatch '^[123]$' -or
            [string]$HostFacts['DomainRole'] -notmatch '^[0-5]$'
        )
        {
            throw 'Windows host facts must contain valid ProductType and DomainRole values.'
        }
        if ($HostFacts['ProductType'] -eq 2 -or $HostFacts['DomainRole'] -in @(4, 5))
        {
            $reason = 'Domain controllers are excluded; only Windows Server member-server STIGs are in scope.'
        }
        elseif ($HostFacts['ProductType'] -eq 1)
        {
            if ([string]$HostFacts['Build'] -cin @('22000', '22621', '22631', '26100', '26200'))
            {
                $profileId = 'WindowsClient-11'
            }
        }
        elseif ($HostFacts['ProductType'] -eq 3)
        {
            $serverBuilds = @{ '14393' = '2016'; '17763' = '2019'; '20348' = '2022'; '26100' = '2025' }
            $build = [string]$HostFacts['Build']
            if ($serverBuilds.ContainsKey($build))
            {
                $profileId = "WindowsServer-$($serverBuilds[$build])-MS"
            }
        }
    }
    elseif ($HostFacts['Family'] -ceq 'Linux')
    {
        if ($HostFacts['Id'] -ceq 'ubuntu' -and $HostFacts['VersionId'] -cin @('18.04', '20.04', '22.04', '24.04'))
        {
            $profileId = "Ubuntu-$($HostFacts['VersionId'])"
        }
        elseif ($HostFacts['Id'] -ceq 'rhel' -and [string]$HostFacts['VersionId'] -cmatch '^(8|9|10)(\.\d+)?$')
        {
            $profileId = "RHEL-$($Matches[1])"
        }
    }
    else
    {
        throw 'Host facts must identify the Windows or Linux family.'
    }

    [pscustomobject]@{
        ProfileId     = $profileId
        IdentityState = if ($null -eq $profileId) { 'Unsupported' } else { 'Recognized' }
        Reason        = if ($null -eq $profileId) { $reason } else {
            'Exact OS identity recognized. Benchmark coverage and runtime qualification are separate admission gates.'
        }
        HostFacts     = $HostFacts
    }
}
