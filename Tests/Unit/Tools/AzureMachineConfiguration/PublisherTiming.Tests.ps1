# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

BeforeAll {
    . "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\PublisherTiming.ps1"
}

Describe 'Private publisher timing admission (no Azure operations)' {
    BeforeEach {
        $now = [datetimeoffset]'2026-10-28T13:00:00Z'
    }

    It 'accounts for cleanup polling, three outer CLI calls and the final poll overshoot' {
        $budget = Get-PowerStigPublisherTimingBudget
        $budget.CleanupReserveSeconds | Should -Be (300 + 3 * 60 + 10 + 60)
        $budget.MinimumAdmissionSeconds | Should -Be 1740
        $budget.MaximumWindowSeconds | Should -Be 1800
        ($budget.CollectionLimitSeconds + $budget.CleanupReserveSeconds +
            $budget.InFlightReserveSeconds + $budget.TransitionMarginSeconds) |
            Should -Be $budget.MinimumAdmissionSeconds
    }

    It 'admits exact full-window boundaries' -TestCases @(@{ Seconds = 1740 }, @{ Seconds = 1800 }) {
        param ($Seconds)
        { Assert-PowerStigPublisherAdmission -DeadlineUtc $now.AddSeconds($Seconds) -Now $now } | Should -Not -Throw
    }

    It 'rejects expired, insufficient or oversized windows' -TestCases @(
        @{ Seconds = -1 }
        @{ Seconds = 0 }
        @{ Seconds = 1276 }
        @{ Seconds = 1380 }
        @{ Seconds = 1739.999 }
        @{ Seconds = 1800.001 }
    ) {
        param ($Seconds)
        { Assert-PowerStigPublisherAdmission -DeadlineUtc $now.AddSeconds($Seconds) -Now $now } |
            Should -Throw '*29-30 minutes*'
    }

    It 'rejects a window aged by read-only preflight without renewing its deadline' {
        $deadline = $now.AddMinutes(30)
        { Assert-PowerStigPublisherAdmission -DeadlineUtc $deadline -Now $now } | Should -Not -Throw
        { Assert-PowerStigPublisherAdmission -DeadlineUtc $deadline -Now $now.AddSeconds(61) } |
            Should -Throw '*29-30 minutes*'
    }

    It 'cuts collection off at exactly eighteen minutes, including provisioning time' {
        $deadline = $now.AddMinutes(29)
        { Assert-PowerStigPublisherCollectionBudget -DeadlineUtc $deadline -ElapsedSeconds 1079.999 -Now $now } |
            Should -Not -Throw
        { Assert-PowerStigPublisherCollectionBudget -DeadlineUtc $deadline -ElapsedSeconds 1080 -Now $now } |
            Should -Throw '*reserve time for terminal deallocation*'
    }

    It 'preserves cleanup, a full in-flight call and transitions at the exact absolute boundary' {
        { Assert-PowerStigPublisherCollectionBudget -DeadlineUtc $now.AddSeconds(660) -ElapsedSeconds 1 -Now $now } |
            Should -Not -Throw
        { Assert-PowerStigPublisherCollectionBudget -DeadlineUtc $now.AddSeconds(659.999) -ElapsedSeconds 1 -Now $now } |
            Should -Throw '*reserve time for terminal deallocation*'
    }

    It 'rejects invalid elapsed clocks' -TestCases @(
        @{ Elapsed = -1 }
        @{ Elapsed = [double]::NaN }
        @{ Elapsed = [double]::PositiveInfinity }
    ) {
        param ($Elapsed)
        { Assert-PowerStigPublisherCollectionBudget -DeadlineUtc $now.AddMinutes(29) -ElapsedSeconds $Elapsed -Now $now } |
            Should -Throw
    }
}
