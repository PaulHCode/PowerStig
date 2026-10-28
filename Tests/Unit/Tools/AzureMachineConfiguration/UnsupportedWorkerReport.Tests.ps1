# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

BeforeAll {
    . "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\UnsupportedWorkerReport.ps1"
}

Describe 'Unbundled Linux native worker contract' {
    BeforeEach {
        $facts = @{ Family = 'Linux'; Id = 'ubuntu'; VersionId = '24.04' }
        $now = [datetimeoffset]::UtcNow
        $message = 'OS recognized, but no exact benchmark/profile is bundled. No neighboring release is substituted.'
        $assessment = @{
            SchemaVersion = '1.0'; Status = 'Unsupported'; ProfileId = 'Ubuntu-24.04'
            HostFacts = $facts.Clone(); CollectedAt = $now.ToString('o'); Message = $message
            Rules = @(); BenchmarkId = $null; BenchmarkVersion = $null
            BenchmarkSha256 = $null; ProcessedSha256 = $null
        }
        $reason = @{ code = 'PowerStigBaseline:PowerStigBaseline:Summary'; phrase = "Ubuntu-24.04: Unsupported. $message" }
        $resource = @{
            complianceStatus = $false
            reasons = @($reason.Clone())
            properties = @{ Family = 'Linux'; Reasons = @($reason.Clone()) }
        }
        $report = @{ complianceStatus = $false; resources = @($resource) }
    }

    It 'accepts only explicit unsupported evidence, never native Azure admission' {
        $resource.properties.AssessmentJson = $assessment | ConvertTo-Json -Depth 10
        $result = Test-PowerStigUnsupportedLinuxWorkerReport -Report $report -HostFacts $facts -Now $now
        $result.UnsupportedContractValidated | Should -BeTrue
        $result.WorkerComplianceStatus | Should -BeFalse
        $result.NativeAzureReportAdmitted | Should -BeFalse
    }

    It 'rejects malformed or contradictory unsupported evidence: <Case>' -TestCases @(
        @{ Case = 'summary-pass' }, @{ Case = 'resource-pass' }, @{ Case = 'missing-summary-status' }
        @{ Case = 'neighbor-profile' }, @{ Case = 'wrong-host' }, @{ Case = 'invented-rules' }
        @{ Case = 'source-provenance' }, @{ Case = 'stale' }, @{ Case = 'missing-native-reason' }
        @{ Case = 'truncated-property-reason' }
    ) {
        param ($Case)
        switch ($Case) {
            'summary-pass' { $report.complianceStatus = $true }
            'resource-pass' { $resource.complianceStatus = $true }
            'missing-summary-status' { $report.Remove('complianceStatus') }
            'neighbor-profile' { $assessment.ProfileId = 'Ubuntu-18.04' }
            'wrong-host' { $assessment.HostFacts.VersionId = '22.04' }
            'invented-rules' { $assessment.Rules = @(@{ Status = 'Compliant' }) }
            'source-provenance' { $assessment.BenchmarkId = 'unearned' }
            'stale' { $assessment.CollectedAt = $now.AddMinutes(-10).ToString('o') }
            'missing-native-reason' { $resource.reasons = @() }
            'truncated-property-reason' { $resource.properties.Reasons[0].phrase = 'Unsupported' }
        }
        $resource.properties.AssessmentJson = $assessment | ConvertTo-Json -Depth 10
        { Test-PowerStigUnsupportedLinuxWorkerReport -Report $report -HostFacts $facts -Now $now } | Should -Throw
    }
}
