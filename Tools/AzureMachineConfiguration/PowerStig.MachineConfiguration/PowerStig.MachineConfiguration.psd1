@{
    RootModule = 'PowerStig.MachineConfiguration.psm1'
    ModuleVersion = '0.2.0'
    GUID = 'f97c96e6-f491-4d38-acb6-6bd5d3b20cda'
    Author = 'PowerSTIG contributors'
    Description = 'Audit-only portable PowerSTIG assessment adapters for Azure Machine Configuration.'
    PowerShellVersion = '5.1'
    DscResourcesToExport = @('PowerStigBaseline')
    FunctionsToExport = @('Get-PowerStigBaselineAssessment', 'Get-PowerStigMachineConfigurationHost', 'Resolve-PowerStigMachineConfigurationProfile')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            LicenseUri = 'https://github.com/PaulHCode/PowerStig/blob/main/LICENSE'
            ProjectUri = 'https://github.com/PaulHCode/PowerStig'
        }
    }
}
