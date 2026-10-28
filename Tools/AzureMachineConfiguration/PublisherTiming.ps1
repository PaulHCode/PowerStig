# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Get-PowerStigPublisherTimingBudget
{
    [CmdletBinding()]
    param ()

    $collection = 18 * 60
    $cli = 60
    $polling = 5 * 60
    $pollOvershoot = 10 + $cli
    # VM read, deallocate and deployment read sit outside the cleanup poll.
    $cleanup = $polling + (3 * $cli) + $pollOvershoot
    $inFlight = 10 + $cli
    $margin = 40
    [pscustomobject]@{
        CollectionLimitSeconds = $collection
        CleanupPollingSeconds = $polling
        CleanupReserveSeconds = $cleanup
        InFlightReserveSeconds = $inFlight
        TransitionMarginSeconds = $margin
        MinimumAdmissionSeconds = $collection + $cleanup + $inFlight + $margin
        MaximumWindowSeconds = 30 * 60
    }
}

function Assert-PowerStigPublisherAdmission
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [datetimeoffset] $DeadlineUtc,

        [Parameter()]
        [datetimeoffset] $Now = [datetimeoffset]::UtcNow
    )

    $budget = Get-PowerStigPublisherTimingBudget
    $remaining = ($DeadlineUtc - $Now).TotalSeconds
    if ($remaining -lt $budget.MinimumAdmissionSeconds -or $remaining -gt $budget.MaximumWindowSeconds)
    {
        throw 'Publisher admission requires 29-30 minutes to the fixed deadline, including collection, bounded cleanup calls and transition reserves. A deadline is not execution authorization.'
    }
}

function Assert-PowerStigPublisherCollectionBudget
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [datetimeoffset] $DeadlineUtc,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [double]::IsNaN($_) -and -not [double]::IsInfinity($_) -and $_ -ge 0 })]
        [double] $ElapsedSeconds,

        [Parameter()]
        [datetimeoffset] $Now = [datetimeoffset]::UtcNow
    )

    $budget = Get-PowerStigPublisherTimingBudget
    $reserve = $budget.CleanupReserveSeconds + $budget.InFlightReserveSeconds + $budget.TransitionMarginSeconds
    if ($ElapsedSeconds -ge $budget.CollectionLimitSeconds -or ($DeadlineUtc - $Now).TotalSeconds -lt $reserve)
    {
        throw 'Publisher collection stopped to reserve time for terminal deallocation, bounded calls and transitions.'
    }
}
