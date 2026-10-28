# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

. "$PSScriptRoot\Profile.ps1"
. "$PSScriptRoot\Assessment.ps1"

class PowerStigReason
{
    [DscProperty()]
    [string] $Code

    [DscProperty()]
    [string] $Phrase
}

[DscResource()]
class PowerStigBaseline
{
    [DscProperty(Key)]
    [string] $Name

    [DscProperty(Mandatory)]
    [ValidateSet('Windows', 'Linux')]
    [string] $Family

    [DscProperty(NotConfigurable)]
    [string] $AssessmentJson

    [DscProperty(NotConfigurable)]
    [PowerStigReason[]] $Reasons

    [PowerStigBaseline] Get()
    {
        $assessment = Get-PowerStigBaselineAssessment -Family $this.Family
        $result = [PowerStigBaseline]::new()
        $result.Name = $this.Name
        $result.Family = $this.Family
        $result.AssessmentJson = $assessment | ConvertTo-Json -Depth 20 -Compress
        $nativeReasons = [System.Collections.Generic.List[PowerStigReason]]::new()
        $summary = [PowerStigReason]::new()
        $summary.Code = 'PowerStigBaseline:PowerStigBaseline:Summary'
        $summary.Phrase = "$($assessment.ProfileId): $($assessment.Status). $($assessment.Message)"
        $nativeReasons.Add($summary)
        foreach ($rule in $assessment.Rules)
        {
            $reason = [PowerStigReason]::new()
            $reason.Code = "PowerStigBaseline:PowerStigBaseline:$($rule.VulnerabilityId.Replace('-', ''))"
            $reason.Phrase = "$($rule.VulnerabilityId): $($rule.Status). $($rule.Title)"
            foreach ($check in $rule.Checks)
            {
                $reason.Phrase += " [$($check.Id): $($check.Status); expected=$($check.Expected); observed=$($check.Observed)]"
            }
            $nativeReasons.Add($reason)
        }
        $result.Reasons = $nativeReasons.ToArray()
        return $result
    }

    [bool] Test()
    {
        $assessment = Get-PowerStigBaselineAssessment -Family $this.Family
        return $assessment.Status -ceq 'Compliant'
    }

    [void] Set()
    {
        throw 'PowerStigBaseline is audit-only. Set/remediation is prohibited.'
    }
}
