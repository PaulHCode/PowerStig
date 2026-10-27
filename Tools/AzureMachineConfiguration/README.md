# PowerSTIG and Azure Machine Configuration

This folder contains a Windows-first helper for packaging a compiled PowerSTIG
configuration as an **Audit-only** Azure Machine Configuration package. It
also contains an offline generator and validator for a matching
`auditIfNotExists` Azure Policy definition. These helpers don't publish
packages or policy definitions, create policy assignments, or run a
configuration against a machine.

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

## Generate a local Audit policy definition

After building and validating the package, generate a policy definition that
checks the exact package identity, content URI, and hash:

```powershell
. .\Tools\AzureMachineConfiguration\AuditPackage.ps1
. .\Tools\AzureMachineConfiguration\AuditPolicy.ps1

$definition = New-PowerStigAuditPolicyDefinition `
    -PackagePath '.\output\machine-configuration\PowerStig_WindowsServer2022_MS_V2R8.zip' `
    -ContentUri 'https://<storage-account>.blob.core.windows.net/<private-container>/PowerStig_WindowsServer2022_MS_V2R8.zip' `
    -DisplayName 'PowerSTIG Windows Server 2022 MS V2R8 audit' `
    -Description 'Checks the status of the matching PowerSTIG Guest Configuration assignment.' `
    -PolicyId '2b94bf59-65d4-44bb-8b15-7ccf499b1d58' `
    -PolicyVersion '1.0.0' `
    -OutputPath '.\output\policy-definitions'

$definition
```

`ContentUri` must be an HTTPS URL without embedded credentials, SAS/query
tokens, or fragments. Use a version-specific, immutable package path and ensure
the identity used by the eventual Guest Configuration assignment can read the
hosted package. The generator hashes the local ZIP; it does not contact the
URL or test its reachability or permissions.

The generated definition uses `auditIfNotExists` to require a compliant
`Microsoft.GuestConfiguration/guestConfigurationAssignments` resource.
When the policy definition is published and assigned, Azure Machine
Configuration uses the policy metadata to automatically create the guest
assignment and deliver the package for evaluation. This helper only generates
and validates local JSON; it does not publish the package or definition,
create a policy assignment, or run the guest evaluation. Do not replace that
normal service flow with a manually fabricated guest assignment for
qualification. Azure deletes a guest assignment created by Policy when its
parent Policy assignment is deleted, so preserve the assignment and definition
after a test unless their deletion is explicitly approved.

`New-PowerStigAuditPolicyDefinition` refuses to replace an existing JSON file
unless `-Force` is specified; the separate validator rechecks the effect,
assignment condition, package version, URI, and exact SHA-256 before
returning.

The helper runs the pinned GuestConfiguration policy generator from a
temporary, byte-verified copy of its module script and templates. This
isolation is intentional: GuestConfiguration 4.10.0's generator resets its
own `gcworker\temp` directory, so invoking it directly could remove unrelated
files from the installed module's worker workspace. The isolated copy and
staging files are removed after generation; the installed module and its
worker state are not modified.

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
- [Machine Configuration assignment resources and Policy delivery](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/concepts/assignments)
- [Develop a custom Machine Configuration package](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/develop-custom-package/overview)
- [PowerSTIG Windows Server configuration](https://github.com/microsoft/PowerStig/tree/4.30.0-PSGallery/source/DSCResources/WindowsServer)
- [Azure `nxtools` project](https://github.com/Azure/nxtools)
