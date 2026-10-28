BeforeAll {
    . "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\AuditReport.ps1"
}

Describe 'ConvertFrom-PowerStigMachineConfigurationReport' {
    BeforeEach {
        $vmId = '/subscriptions/example/resourceGroups/lab/providers/Microsoft.Compute/virtualMachines/example'
        $assignmentId = "$vmId/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/Sample"
        $script:parameters = @{
            ExpectedVmId = $vmId
            ExpectedAssignmentId = $assignmentId
            ExpectedConfigurationName = 'Sample'
            ExpectedConfigurationVersion = '1.0.0'
            ExpectedPackageHash = 'a' * 64
            ExpectedBenchmarkHash = 'b' * 64
            Now = [datetimeoffset]'2026-10-27T23:00:00Z'
            ExpectedConfigurationMofHash = 'd' * 64
            ResourceMap = [pscustomobject]@{
                ConfigurationMofSha256 = 'd' * 64
                Requirements = @(@{ VulnerabilityId = 'V-1'; ResourceIds = @('[Registry]V-1') })
            }
            Coverage = [pscustomobject]@{
                SourceMatches = $true; BenchmarkSha256 = 'b' * 64; RequirementCount = 1
                Rules = @([pscustomobject]@{ VulnerabilityId = 'V-1'; CoverageState = 'RuntimeUnqualified' })
            }
            Assignment = @{
                id = $assignmentId
                properties = @{
                    guestConfiguration = @{
                        name = 'Sample'; version = '1.0.0'; contentHash = 'a' * 64; assignmentType = 'Audit'
                    }
                }
            }
            Report = @{
                id = "$assignmentId/reports/report1"
                properties = @{
                    reportId = 'report1'; vm = @{ id = $vmId }
                    assignment = @{ configuration = @{ name = 'Sample'; version = '1.0.0' } }
                    startTime = '2026-10-27T22:29:00Z'; endTime = '2026-10-27T22:30:00Z'
                    complianceStatus = 'Compliant'
                    details = @{
                        complianceStatus = 'Compliant'
                        resources = @(@{
                            resourceId = '[Registry]V-1'; complianceStatus = 'Compliant'
                            properties = @{ ValueData = '1' }
                            reasons = @(@{ code = 'Registry:Registry:ValueMatch'; phrase = 'Expected 1; observed 1.' })
                        })
                    }
                }
            }
        }
    }

    It 'preserves native reasons and observed properties, with package and source provenance' {
        $result = ConvertFrom-PowerStigMachineConfigurationReport @script:parameters
        $result.AssessmentStatus | Should -BeExactly 'Compliant'
        $result.Requirements[0].Reasons[0].Phrase | Should -BeExactly 'Expected 1; observed 1.'
        $result.Requirements[0].Observations[0].Properties.ValueData | Should -BeExactly '1'
        $result.BenchmarkSha256 | Should -BeExactly ('b' * 64)
    }

    It 'keeps unimplemented source rules in the denominator' {
        $script:parameters.Coverage.Rules += [pscustomobject]@{ VulnerabilityId = 'V-2'; CoverageState = 'Manual' }
        $script:parameters.Coverage.RequirementCount = 2
        $result = ConvertFrom-PowerStigMachineConfigurationReport @script:parameters
        $result.AssessmentStatus | Should -BeExactly 'Indeterminate'
        $result.Requirements.Count | Should -Be 2
        $result.Requirements[1].Status | Should -BeExactly 'Manual'
    }

    It 'requires all compiled components of a split vulnerability' {
        $script:parameters.ResourceMap.Requirements[0].ResourceIds += '[Registry]V-1.b'
        $result = ConvertFrom-PowerStigMachineConfigurationReport @script:parameters
        $result.AssessmentStatus | Should -BeExactly 'Indeterminate'
        $result.Requirements[0].Status | Should -BeExactly 'MissingEvidence'
        $result.Requirements[0].Reasons.Phrase | Should -Contain 'No native result for [Registry]V-1.b.'
    }

    It 'does not promote missing, stale, pending, or unexplained results to passing' -TestCases @(
        @{ Case = 'missing'; Status = 'MissingEvidence' }
        @{ Case = 'stale'; Status = 'Stale' }
        @{ Case = 'pending'; Status = 'Unknown' }
        @{ Case = 'no-reasons'; Status = 'MissingEvidence' }
    ) {
        param ($Case, $Status)
        switch ($Case)
        {
            'missing' { $script:parameters.Report.properties.details.resources = @() }
            'stale' { $script:parameters.Now = [datetimeoffset]'2026-10-28T23:00:00Z' }
            'pending' { $script:parameters.Report.properties.details.resources[0].complianceStatus = 'Pending' }
            'no-reasons' { $script:parameters.Report.properties.details.resources[0].reasons = @() }
        }
        $result = ConvertFrom-PowerStigMachineConfigurationReport @script:parameters
        $result.AssessmentStatus | Should -BeExactly 'Indeterminate'
        $result.Requirements[0].Status | Should -BeExactly $Status
    }

    It 'preserves a measured noncompliant result' {
        $script:parameters.Report.properties.details.resources[0].complianceStatus = 'NonCompliant'
        $result = ConvertFrom-PowerStigMachineConfigurationReport @script:parameters
        $result.AssessmentStatus | Should -BeExactly 'NonCompliant'
    }

    It 'accepts a Policy-created assignment name distinct from the configuration name' {
        $id = $script:parameters.ExpectedAssignmentId + '$pidgeneratedsuffix'
        $script:parameters.ExpectedAssignmentId = $id
        $script:parameters.Assignment.id = $id
        $script:parameters.Report.id = "$id/reports/report1"
        (ConvertFrom-PowerStigMachineConfigurationReport @script:parameters).AssessmentStatus |
            Should -BeExactly 'Compliant'
    }

    It 'rejects mismatched package, VM, source, or future data' -TestCases @(
        @{ Case = 'hash' }
        @{ Case = 'vm' }
        @{ Case = 'source' }
        @{ Case = 'future' }
        @{ Case = 'apply' }
        @{ Case = 'mof' }
    ) {
        param ($Case)
        switch ($Case)
        {
            'hash' { $script:parameters.ExpectedPackageHash = 'c' * 64 }
            'vm' { $script:parameters.Report.properties.vm.id = '/different/vm' }
            'source' { $script:parameters.ExpectedBenchmarkHash = 'c' * 64 }
            'future' { $script:parameters.Report.properties.endTime = '2026-10-28T00:00:00Z' }
            'apply' { $script:parameters.Assignment.properties.guestConfiguration.assignmentType = 'ApplyAndAutoCorrect' }
            'mof' { $script:parameters.ExpectedConfigurationMofHash = 'c' * 64 }
        }
        { ConvertFrom-PowerStigMachineConfigurationReport @script:parameters } | Should -Throw
    }

    It 'rejects duplicate native resource results' {
        $script:parameters.Report.properties.details.resources += $script:parameters.Report.properties.details.resources[0]
        { ConvertFrom-PowerStigMachineConfigurationReport @script:parameters } | Should -Throw '*duplicate DSC resource*'
    }

    It 'does not silently discard unexpected native resources' {
        $script:parameters.Report.properties.details.resources += @{
            resourceId = '[Registry]Unexpected'; complianceStatus = 'Compliant'
        }
        $result = ConvertFrom-PowerStigMachineConfigurationReport @script:parameters
        $result.AssessmentStatus | Should -BeExactly 'Indeterminate'
        $result.UnmappedResourceIds | Should -Contain '[Registry]Unexpected'
    }
}
