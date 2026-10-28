# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

BeforeAll {
    . "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\WorkerReportShape.ps1"
}

Describe 'Worker report shape inspection, not native admission' {
    It 'retains field shapes and public reason codes without scalar observations' {
        $report = @{
            complianceStatus = $false
            resources = @(
                @{ Reasons = @(@{ Code = 'PowerStigBaseline:PowerStigBaseline:Summary'; Phrase = 'CI_SECRET_SENTINEL' }) },
                @{ Reasons = @(@{ Code = 'PowerStigBaseline:PowerStigBaseline:V123'; Phrase = 'OTHER_SECRET' }) }
            )
        }
        $result = Get-PowerStigWorkerReportShape -Report $report
        $result.PowerStigReasonCodes.Count | Should -Be 2
        $result.Shape.Properties.resources.Count | Should -Be 2
        $json = $result | ConvertTo-Json -Depth 40
        $json | Should -Not -Match 'CI_SECRET_SENTINEL|OTHER_SECRET'
    }

    It 'inspects JSON-encoded properties without emitting their observed values' {
        $report = @{ Properties = '{"Reasons":[{"Code":"PowerStigBaseline:PowerStigBaseline:V456","Phrase":"PRIVATE_VALUE"}]}' }
        $result = Get-PowerStigWorkerReportShape -Report $report
        $result.PowerStigReasonCodes | Should -Contain 'PowerStigBaseline:PowerStigBaseline:V456'
        $result.Shape.Properties.Properties.Type | Should -BeExactly 'JsonString'
        ($result | ConvertTo-Json -Depth 40) | Should -Not -Match 'PRIVATE_VALUE'
    }

    It 'records a JSON-looking ordinary string that is not parseable' {
        $result = Get-PowerStigWorkerReportShape -Report @{ Phrase = '[ordinary non-JSON text]' }
        $result.JsonLikeStringsNotParsed | Should -Be 1
        $result.Shape.Properties.Phrase.Type | Should -BeExactly 'String'
    }

    It 'rejects excessive nesting' {
        $report = @{ Last = $null }
        1..25 | ForEach-Object { $report = @{ Child = $report } }
        { Get-PowerStigWorkerReportShape -Report $report } | Should -Throw '*inspection bound*'
    }
}
