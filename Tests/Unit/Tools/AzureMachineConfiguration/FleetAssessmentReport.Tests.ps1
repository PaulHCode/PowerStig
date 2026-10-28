# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

BeforeAll {
    . "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\FleetAssessmentReport.ps1"
    . "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\PowerStig.MachineConfiguration\Assessment.ps1"

    function Save-FleetCoverageFixture
    {
        $script:coverage | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $script:parameters.CoveragePath -Encoding utf8
        $script:parameters.ExpectedCoverageHash = (Get-FileHash -LiteralPath $script:parameters.CoveragePath).Hash
    }

    function Invoke-FleetReportFixture
    {
        $script:parameters.AssessmentJson = $script:assessment | ConvertTo-Json -Depth 20
        ConvertFrom-PowerStigFleetAssessment @script:parameters
    }
}

Describe 'Fleet assessment payload admission (not native VM report admission)' {
    BeforeEach {
        $script:coverage = @{
            SourceMatches = $true; RequirementCount = 2
            BenchmarkId = 'example-benchmark'; BenchmarkVersion = '2.7'
            BenchmarkSha256 = 'b' * 64; ProcessedSha256 = 'c' * 64
            Rules = @(
                @{
                    VulnerabilityId = 'V-1'; RuleId = 'SV-1'; StigId = 'WN-1'; Title = 'Registry setting'; Severity = 'medium'
                    Components = @(@{ ProcessedId = 'V-1'; CoverageState = 'RuntimeUnqualified'; DscResource = 'Registry' })
                },
                @{
                    VulnerabilityId = 'V-2'; RuleId = 'SV-2'; StigId = 'WN-2'; Title = 'Manual review'; Severity = 'low'
                    Components = @(@{ ProcessedId = 'V-2'; CoverageState = 'Manual'; DscResource = 'None' })
                }
            )
        }
        $script:assessment = @{
            SchemaVersion = '1.0'; ProfileId = 'WindowsClient-11'; Status = 'NonCompliant'
            HostFacts = @{ Family = 'Windows'; Build = '22631'; ProductType = 1; DomainRole = 1 }
            CollectedAt = '2026-10-28T12:30:00Z'
            BenchmarkId = 'example-benchmark'; BenchmarkVersion = '2.7'
            BenchmarkSha256 = 'b' * 64; ProcessedSha256 = 'c' * 64
            Rules = @(
                @{
                    VulnerabilityId = 'V-1'; RuleId = 'SV-1'; StigId = 'WN-1'; Title = 'Registry setting'
                    Severity = 'medium'; Status = 'Compliant'
                    Checks = @(@{ Id = 'V-1'; Status = 'Compliant'; Expected = 'Enabled = 1'; Observed = '1 [DWord]'; Adapter = 'EffectiveMachineRegistry' })
                },
                @{
                    VulnerabilityId = 'V-2'; RuleId = 'SV-2'; StigId = 'WN-2'; Title = 'Manual review'
                    Severity = 'low'; Status = 'Incomplete'
                    Checks = @(@{ Id = 'V-2'; Status = 'Manual'; Expected = 'Reviewed manual evidence'; Observed = 'No automated assessment'; Adapter = $null })
                }
            )
        }
        $script:parameters = @{
            CoveragePath = "$TestDrive\coverage.json"; ExpectedCoverageHash = 'a' * 64
            ExpectedProfileId = 'WindowsClient-11'; ExpectedFamily = 'Windows'
            Now = [datetimeoffset]'2026-10-28T13:00:00Z'
            AssessmentJson = '{}'
        }
        Save-FleetCoverageFixture
    }

    It 'preserves explanations and the complete denominator without claiming native admission' {
        $result = Invoke-FleetReportFixture
        $result.PayloadStatus | Should -BeExactly 'Incomplete'
        $result.ReportedStatus | Should -BeExactly 'NonCompliant'
        $result.NativeReportAdmitted | Should -BeFalse
        $result.RequirementCount | Should -Be 2
        $result.RuleCounts.Compliant | Should -Be 1
        $result.RuleCounts.Incomplete | Should -Be 1
        $result.CheckCounts.Manual | Should -Be 1
        $result.Requirements[0].Checks[0].Expected | Should -BeExactly 'Enabled = 1'
        $result.Requirements[0].Checks[0].Observed | Should -BeExactly '1 [DWord]'
        $result.CoverageSha256 | Should -BeExactly $script:parameters.ExpectedCoverageHash
    }

    It 'separates measured noncompliance from incomplete manual checks' {
        $script:assessment.Rules[0].Checks[0].Status = 'NonCompliant'
        $script:assessment.Rules[0].Checks[0].Observed = '0 [DWord]'
        $script:assessment.Rules[0].Status = 'NonCompliant'
        $result = Invoke-FleetReportFixture
        $result.PayloadStatus | Should -BeExactly 'NonCompliant'
        $result.RuleCounts.NonCompliant | Should -Be 1
        $result.RuleCounts.Incomplete | Should -Be 1
    }

    It 'allows a fully explained payload pass but never treats it as native VM compliance' {
        $script:coverage.Rules = @($script:coverage.Rules[0])
        $script:coverage.RequirementCount = 1
        Save-FleetCoverageFixture
        $script:assessment.Rules = @($script:assessment.Rules[0])
        $script:assessment.Status = 'Compliant'
        $result = Invoke-FleetReportFixture
        $result.PayloadStatus | Should -BeExactly 'Compliant'
        $result.NativeReportAdmitted | Should -BeFalse
    }

    It 'accepts the actual collector serialization with mocked registry reads' {
        @'
<PowerStig>
  <RegistryRule>
    <Rule id="V-1" conversionstatus="pass" dscresource="Registry">
      <Key>HKEY_LOCAL_MACHINE\SOFTWARE\Example</Key><ValueName>Enabled</ValueName>
      <ValueType>Dword</ValueType><ValueData>1</ValueData>
    </Rule>
  </RegistryRule>
  <DocumentRule><Rule id="V-2" conversionstatus="pass" dscresource="None" /></DocumentRule>
</PowerStig>
'@ | Set-Content -LiteralPath "$TestDrive\processed.xml" -Encoding utf8
        $script:coverage.ProcessedSha256 = (Get-FileHash -LiteralPath "$TestDrive\processed.xml").Hash
        Save-FleetCoverageFixture
        @{
            'WindowsClient-11' = @{
                ProcessedFile = 'processed.xml'; CoverageFile = 'coverage.json'
                ProcessedSha256 = $script:coverage.ProcessedSha256
                CoverageSha256 = $script:parameters.ExpectedCoverageHash
            }
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$TestDrive\catalog.json" -Encoding utf8
        Mock Read-PowerStigRegistryValue { @{ State = 'Present'; Value = 1; Kind = 'DWord' } }
        $collected = Get-PowerStigBaselineAssessment -Family Windows -DataRoot $TestDrive -HostFacts $script:assessment.HostFacts
        $script:assessment = $collected
        $script:parameters.Now = [datetimeoffset]::UtcNow
        $result = Invoke-FleetReportFixture
        $result.PayloadStatus | Should -BeExactly 'Incomplete'
        $result.RuleCounts.Compliant | Should -Be 1
        $result.CheckCounts.Manual | Should -Be 1
        $result.NativeReportAdmitted | Should -BeFalse
        Should -Invoke Read-PowerStigRegistryValue -Times 1 -Exactly
    }

    It 'accounts for source requirements without any processed component' {
        $script:coverage.Rules[1].Components = @()
        Save-FleetCoverageFixture
        $script:assessment.Rules[1].Checks = @()
        $script:assessment.Rules[1].Status = 'Missing'
        $result = Invoke-FleetReportFixture
        $result.PayloadStatus | Should -BeExactly 'Incomplete'
        $result.RuleCounts.Missing | Should -Be 1
        $result.RequirementCount | Should -Be 2
    }

    It 'counts nonpassing check states explicitly' -TestCases @(
        @{ Status = 'Manual'; Outcome = 'Incomplete' }
        @{ Status = 'Unsupported'; Outcome = 'Incomplete' }
        @{ Status = 'EvidenceOnly'; Outcome = 'Incomplete' }
        @{ Status = 'OrganizationValueRequired'; Outcome = 'Incomplete' }
        @{ Status = 'ConversionFailed'; Outcome = 'Incomplete' }
        @{ Status = 'DuplicateReference'; Outcome = 'Incomplete' }
        @{ Status = 'Error'; Outcome = 'Error' }
    ) {
        param ($Status, $Outcome)
        $script:assessment.Rules[0].Checks[0].Status = $Status
        $script:assessment.Rules[0].Status = if ($Status -ceq 'Error') { 'Error' } else { 'Incomplete' }
        $result = Invoke-FleetReportFixture
        $result.PayloadStatus | Should -BeExactly $Outcome
        $result.CheckCounts.$Status | Should -Be $(if ($Status -ceq 'Manual') { 2 } else { 1 })
    }

    It 'accepts RHEL static evidence as incomplete, not effective-state compliance' {
        $script:parameters.ExpectedProfileId = 'RHEL-9'
        $script:parameters.ExpectedFamily = 'Linux'
        $script:assessment.ProfileId = 'RHEL-9'
        $script:assessment.HostFacts = @{ Family = 'Linux'; Id = 'rhel'; VersionId = '9.4' }
        $script:assessment.Rules[0].Status = 'Incomplete'
        $script:assessment.Rules[0].Checks[0].Status = 'EvidenceOnly'
        $script:assessment.Rules[0].Checks[0].Adapter = 'ProcessedFileLineEvidence'
        $script:coverage.Rules[0].Components[0].CoverageState = 'LegacyLinux'
        $script:coverage.Rules[0].Components[0].DscResource = 'nxFileLine'
        Save-FleetCoverageFixture
        (Invoke-FleetReportFixture).PayloadStatus | Should -BeExactly 'Incomplete'
    }

    It 'rejects a static Linux pass even when the summary claims compliance' {
        $script:parameters.ExpectedProfileId = 'RHEL-9'
        $script:parameters.ExpectedFamily = 'Linux'
        $script:assessment.ProfileId = 'RHEL-9'
        $script:assessment.HostFacts = @{ Family = 'Linux'; Id = 'rhel'; VersionId = '9.4' }
        $script:assessment.Rules[0].Checks[0].Adapter = 'ProcessedFileLineEvidence'
        { Invoke-FleetReportFixture } | Should -Throw '*effective-state adapter*'
    }

    It 'rejects a fabricated pass for an ineligible source component' -TestCases @(
        @{ State = 'Manual' }
        @{ State = 'OrganizationValueRequired' }
        @{ State = 'ConversionFailed' }
        @{ State = 'DuplicateReference' }
        @{ State = 'LegacyLinux' }
        @{ State = 'Unknown' }
    ) {
        param ($State)
        $script:coverage.Rules[1].Components[0].CoverageState = $State
        $script:coverage.Rules[1].Components[0].DscResource = 'Registry'
        Save-FleetCoverageFixture
        $script:assessment.Rules[1].Checks[0].Status = 'Compliant'
        $script:assessment.Rules[1].Checks[0].Adapter = 'EffectiveMachineRegistry'
        $script:assessment.Rules[1].Status = 'Compliant'
        $script:assessment.Status = 'Compliant'
        { Invoke-FleetReportFixture } | Should -Throw '*not eligible*'
    }

    It 'rejects missing, duplicate, or unrelated requirements' -TestCases @(
        @{ Case = 'missing' }
        @{ Case = 'duplicate' }
        @{ Case = 'extra' }
    ) {
        param ($Case)
        switch ($Case)
        {
            'missing' { $script:assessment.Rules = @($script:assessment.Rules[0]) }
            'duplicate' { $script:assessment.Rules += $script:assessment.Rules[0] }
            'extra' {
                $extra = $script:assessment.Rules[0] | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
                $extra.VulnerabilityId = 'V-3'
                $script:assessment.Rules += $extra
            }
        }
        { Invoke-FleetReportFixture } | Should -Throw
    }

    It 'requires all and only the pinned processed components' -TestCases @(
        @{ Case = 'missing' }
        @{ Case = 'duplicate' }
        @{ Case = 'extra' }
    ) {
        param ($Case)
        switch ($Case)
        {
            'missing' { $script:assessment.Rules[0].Checks = @() }
            'duplicate' { $script:assessment.Rules[0].Checks += $script:assessment.Rules[0].Checks[0] }
            'extra' {
                $extra = $script:assessment.Rules[0].Checks[0].Clone()
                $extra.Id = 'V-1.b'
                $script:assessment.Rules[0].Checks += $extra
            }
        }
        { Invoke-FleetReportFixture } | Should -Throw
    }

    It 'rejects missing explanations' -TestCases @(@{ Field = 'Expected' }, @{ Field = 'Observed' }) {
        param ($Field)
        $script:assessment.Rules[0].Checks[0][$Field] = ''
        { Invoke-FleetReportFixture } | Should -Throw '*explanation*'
    }

    It 'rejects inconsistent statuses, identities, metadata, or source hashes' -TestCases @(
        @{ Case = 'coverage-hash' }
        @{ Case = 'benchmark-hash' }
        @{ Case = 'profile' }
        @{ Case = 'dc' }
        @{ Case = 'title' }
        @{ Case = 'summary' }
        @{ Case = 'rule-state' }
        @{ Case = 'unknown-state' }
    ) {
        param ($Case)
        switch ($Case)
        {
            'coverage-hash' { $script:parameters.ExpectedCoverageHash = 'd' * 64 }
            'benchmark-hash' { $script:assessment.BenchmarkSha256 = 'd' * 64 }
            'profile' { $script:parameters.ExpectedProfileId = 'WindowsServer-2022-MS' }
            'dc' { $script:assessment.HostFacts.ProductType = 2; $script:assessment.HostFacts.DomainRole = 5 }
            'title' { $script:assessment.Rules[0].Title = 'Different source' }
            'summary' { $script:assessment.Status = 'Compliant' }
            'rule-state' { $script:assessment.Rules[0].Status = 'Incomplete' }
            'unknown-state' { $script:assessment.Rules[0].Checks[0].Status = 'Pending' }
        }
        { Invoke-FleetReportFixture } | Should -Throw
    }

    It 'enforces the exact report-age threshold' {
        $script:parameters.Now = [datetimeoffset]'2026-10-28T13:30:00Z'
        (Invoke-FleetReportFixture).IsStale | Should -BeFalse
        $script:parameters.Now = $script:parameters.Now.AddSeconds(1)
        $result = Invoke-FleetReportFixture
        $result.IsStale | Should -BeTrue
        $result.PayloadStatus | Should -BeExactly 'Stale'
    }

    It 'rejects malformed or future collection timestamps' -TestCases @(
        @{ Timestamp = 'not-a-timestamp' }
        @{ Timestamp = '2026-10-28T13:00:01Z' }
        @{ Timestamp = '2026-10-28T12:30:00' }
    ) {
        param ($Timestamp)
        $script:assessment.CollectedAt = $Timestamp
        { Invoke-FleetReportFixture } | Should -Throw '*timestamp*'
    }

    It 'preserves absolute time across JSON timestamp conversion and local culture' {
        $script:assessment.CollectedAt = '2026-10-28T14:30:00+02:00'
        $priorCulture = [cultureinfo]::CurrentCulture
        try
        {
            [cultureinfo]::CurrentCulture = [cultureinfo]'fr-FR'
            (Invoke-FleetReportFixture).CollectedAt.UtcDateTime |
                Should -Be ([datetime]'2026-10-28T12:30:00Z').ToUniversalTime()
        }
        finally
        {
            [cultureinfo]::CurrentCulture = $priorCulture
        }
    }

    It 'does not treat an unsupported empty payload as a zero-rule pass' {
        $script:assessment.Status = 'Unsupported'
        $script:assessment.Message = 'No bundled profile.'
        $script:assessment.Rules = @()
        { Invoke-FleetReportFixture } | Should -Throw '*Unsupported guest assessment*'
    }

    It 'rejects source coverage that does not match or has an inconsistent denominator' -TestCases @(
        @{ Case = 'mismatch' }
        @{ Case = 'count' }
    ) {
        param ($Case)
        if ($Case -ceq 'mismatch') { $script:coverage.SourceMatches = $false } else { $script:coverage.RequirementCount = 3 }
        Save-FleetCoverageFixture
        { Invoke-FleetReportFixture } | Should -Throw '*complete, source-matched*'
    }

    It 'rejects an absent component array instead of accepting it as zero checks' {
        $script:coverage.Rules[1].Remove('Components')
        Save-FleetCoverageFixture
        $script:assessment.Rules[1].Checks = @()
        $script:assessment.Rules[1].Status = 'Missing'
        { Invoke-FleetReportFixture } | Should -Throw '*explicit component arrays*'
    }
}
