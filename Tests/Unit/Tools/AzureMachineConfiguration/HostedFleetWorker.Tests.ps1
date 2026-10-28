# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

BeforeAll {
    $workerScript = "$PSScriptRoot\..\..\..\..\Tools\AzureMachineConfiguration\Test-HostedFleetWorker.ps1"
}

Describe 'Hosted worker safety boundary' {
    BeforeEach {
        $priorActions = $env:GITHUB_ACTIONS
        $priorEnvironment = $env:RUNNER_ENVIRONMENT
    }

    AfterEach {
        $env:GITHUB_ACTIONS = $priorActions
        $env:RUNNER_ENVIRONMENT = $priorEnvironment
    }

    It 'refuses a workstation before building or collecting anything' {
        $env:GITHUB_ACTIONS = 'false'
        $output = Join-Path $TestDrive 'workstation'
        { & $workerScript -OutputPath $output } | Should -Throw '*ephemeral GitHub-hosted Windows runner*'
        Test-Path -LiteralPath $output | Should -BeFalse
    }

    It 'refuses a self-hosted GitHub runner' {
        $env:GITHUB_ACTIONS = 'true'
        $env:RUNNER_ENVIRONMENT = 'self-hosted'
        $output = Join-Path $TestDrive 'self-hosted'
        { & $workerScript -OutputPath $output } | Should -Throw '*ephemeral GitHub-hosted Windows runner*'
        Test-Path -LiteralPath $output | Should -BeFalse
    }
}
