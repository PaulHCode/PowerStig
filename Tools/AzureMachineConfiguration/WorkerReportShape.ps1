# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Get-PowerStigWorkerReportShape
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary] $Report
    )

    $context = @{
        Nodes = 0
        JsonLikeStringsNotParsed = 0
        Codes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    }
    function Read-WorkerShape
    {
        param ([AllowNull()] $Value, [int] $Depth)
        $context.Nodes++
        if ($context.Nodes -gt 50000 -or $Depth -gt 24) { throw 'Worker report exceeds the shape-inspection bound.' }
        if ($null -eq $Value) { return @{ Type = 'Null' } }
        if ($Value -is [string])
        {
            if ($Value -cmatch '^PowerStigBaseline:PowerStigBaseline:(Summary|V\d+)$')
            {
                $null = $context.Codes.Add($Value)
            }
            if ($Value.TrimStart().StartsWith('{') -or $Value.TrimStart().StartsWith('['))
            {
                $parsed = $null
                try { $parsed = ConvertFrom-Json -InputObject $Value -AsHashtable -Depth 40 -NoEnumerate -ErrorAction Stop }
                catch [System.ArgumentException] { $context.JsonLikeStringsNotParsed++ }
                if ($parsed -is [System.Collections.IDictionary] -or $parsed -is [array])
                {
                    return @{ Type = 'JsonString'; Content = Read-WorkerShape -Value $parsed -Depth ($Depth + 1) }
                }
            }
            return @{ Type = 'String' }
        }
        if ($Value -is [System.Collections.IDictionary])
        {
            $properties = [ordered]@{}
            foreach ($key in $Value.Keys)
            {
                $properties[$key] = Read-WorkerShape -Value $Value[$key] -Depth ($Depth + 1)
            }
            return @{ Type = 'Object'; Properties = $properties }
        }
        if ($Value -is [array])
        {
            $first = $null
            for ($index = 0; $index -lt $Value.Count; $index++)
            {
                $itemShape = Read-WorkerShape -Value $Value[$index] -Depth ($Depth + 1)
                if ($index -eq 0) { $first = $itemShape }
            }
            return @{ Type = 'Array'; Count = $Value.Count; FirstItem = $first }
        }
        if ($Value -is [bool]) { return @{ Type = 'Boolean' } }
        if ($Value -is [ValueType]) { return @{ Type = 'Scalar' } }
        throw 'Expected a JSON-deserialized worker report.'
    }
    $shape = Read-WorkerShape -Value $Report -Depth 0
    [pscustomobject]@{
        Shape = $shape
        PowerStigReasonCodes = @($context.Codes | Sort-Object)
        NodeCount = $context.Nodes
        JsonLikeStringsNotParsed = $context.JsonLikeStringsNotParsed
    }
}
