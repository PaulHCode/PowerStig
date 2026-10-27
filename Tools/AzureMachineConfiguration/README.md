# PowerSTIG and Azure Machine Configuration

This folder contains a Windows-first helper for packaging a compiled PowerSTIG
configuration as an **Audit-only** Azure Machine Configuration package. It
doesn't publish the package, create Azure Policy definitions or assignments, or
run a configuration against a machine.

## Build an Audit package

Compile the selected Windows PowerSTIG configuration with the pinned PowerSTIG
and resource-module versions in a controlled Windows PowerShell 5.1 build
environment. For example, the independently tested baseline is Windows Server
2022 Member Server, PowerSTIG 4.30.0, STIG V2R8. The benchmark is older than
the current V2R11 target and must not be represented as current coverage.

Then use PowerShell 7 and the pinned GuestConfiguration module to package the
compiled MOF:

```powershell
. .\Tools\AzureMachineConfiguration\AuditPackage.ps1

$result = New-PowerStigAuditPackage `
    -Name 'PowerStig_WindowsServer2022_MS_V2R8' `
    -ConfigurationMofPath '.\artifacts\PowerStig_WindowsServer2022_MS_V2R8.mof' `
    -OutputPath '.\output\machine-configuration' `
    -PackageVersion '1.0.0' `
    -GuestConfigurationVersion '4.10.0'

$result
```

The helper always passes `-Type Audit`; it rejects missing compiled MOFs,
prevents accidental replacement unless `-Force` is supplied, and validates
the resulting ZIP's metadata, embedded MOF, semantic version, SHA-256, and
expanded size against Azure Machine Configuration's 100-MB package limit.
The helper requires GuestConfiguration to be available locally; it does not
install dependencies or perform network access on its own.

## Limits of this helper

Successful package creation and structural validation are not proof that the
Machine Configuration worker executes every PowerSTIG resource correctly,
that `Get` produces useful native `Reasons`, that the profile matches the
current DISA release, or that Azure Policy delivers a fresh report. Those are
separate gates. The package must not be published or assigned until those
checks are completed for the exact OS, role, benchmark, dependency set, and
Azure environment.

The legacy Linux `nx` resources are not covered by this Windows helper. Azure
Machine Configuration doesn't use the older DSC-for-Linux `nx*` providers;
similarly named resources in Azure's `nxtools` module are separate
implementations and require their own compatibility and behavior validation.

References:

- [Machine Configuration DSC behavior and Audit mode](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/whats-new/psdsc-in-machine-configuration)
- [Develop a custom Machine Configuration package](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/develop-custom-package/overview)
- [PowerSTIG Windows Server configuration](https://github.com/microsoft/PowerStig/tree/4.30.0-PSGallery/source/DSCResources/WindowsServer)
- [Azure `nxtools` project](https://github.com/Azure/nxtools)
