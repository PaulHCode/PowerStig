# PowerSTIG and Azure Machine Configuration

This folder contains a Windows-first helper for packaging a compiled PowerSTIG
configuration as an **Audit-only** Azure Machine Configuration package. It
also contains an offline generator and validator for a matching
`auditIfNotExists` Azure Policy definition. These helpers don't publish
packages or policy definitions, create policy assignments, or run a
configuration against a machine.

## One assignment, measured OS selection

The delivery design is **one initiative**, containing a Windows Audit policy and
a Linux Audit policy. Each family package must measure its guest OS and select
an exact, pinned profile. Azure Policy image fields only route the family; they
cannot establish the running release or the Windows server role. This also
supports custom images without requiring an administrator-maintained OS tag.

Windows Server uses **MS profiles only**. Guest detection explicitly rejects
domain controllers, including a mismatch between OS ProductType and computer
DomainRole. Windows 11 is distinguished from Server 2025 even though they can
share a kernel build. Ubuntu releases are exact matches; RHEL minor versions
map to their major-release benchmark. Derivatives such as Rocky Linux do not
silently inherit a RHEL profile.

**Implementation status:** the identity, coverage, resource-map, report and
initiative helpers below are available for offline development. They are not yet
wired into distributable guest dispatcher packages. No OS/cloud combination is
production-qualified by these helpers. In particular, do not assign an existing
Server 2022 composite package to every Windows VM: the generic policy generator
targets an OS family, not that package's exact release. A fleet assignment needs
the guest dispatcher and profile-admission gates first.

```powershell
. .\Tools\AzureMachineConfiguration\Profile.ps1
$identity = Resolve-PowerStigMachineConfigurationProfile `
    -HostFacts (Get-PowerStigMachineConfigurationHost)
$identity
```

`Recognized` is an identity result, not a promise that content or a qualified
runtime exists. Unknown releases and DCs return `Unsupported` with a reason.
Discovery reads CIM or `/etc/os-release`; it does not execute content from
`os-release`, infer a release from image names, or change guest settings.

## Coverage before compliance

Use the official XCCDF as the denominator, not only processed rules. Pin and
review the intended benchmark before building. An archived benchmark documents
that historical release, not today's latest DISA requirements.

```powershell
. .\Tools\AzureMachineConfiguration\Coverage.ps1
$coverage = Get-PowerStigMachineConfigurationCoverage `
    -BenchmarkPath '.\source\StigData\Archive\Linux.RHEL\U_RHEL_9_STIG_V2R8_Manual-xccdf.xml' `
    -ProcessedPath '.\source\StigData\Processed\RHEL-9-2.8.xml'
$coverage.Rules | Group-Object CoverageState | Select-Object Name, Count

$mapping = Get-PowerStigMachineConfigurationResourceMap `
    -ConfigurationMofPath '<approved compiled configuration>.mof'
```

Coverage includes benchmark/processed SHA-256, exact version/identity comparison,
every source vulnerability, and all processed split-rule components. Manual,
legacy Linux, organization-value, duplicate-reference, conversion-failure,
missing and mixed states remain visible. A processed `pass` is never a host
pass. The MOF mapper preserves complete DSC resource IDs and groups `.a`/`.b`
components under their source vulnerability. Unmapped helper resources remain
visible and require explicit review.

## Native reports with explanations

`ConvertFrom-PowerStigMachineConfigurationReport` accepts the **full native
assignment report** and the corresponding assignment, loaded as hashtables.
Supply expected VM/assignment IDs, package name/version/hash, pinned benchmark
hash, coverage and resource mapping:

```powershell
. .\Tools\AzureMachineConfiguration\AuditReport.ps1
$parameters = @{
    Report                       = Get-Content '<private report>.json' -Raw | ConvertFrom-Json -AsHashtable
    Assignment                   = Get-Content '<private assignment>.json' -Raw | ConvertFrom-Json -AsHashtable
    ExpectedVmId                 = '<exact VM ARM ID>'
    ExpectedAssignmentId         = '<exact Policy-created guest assignment ARM ID>'
    ExpectedConfigurationName    = '<package configuration name>'
    ExpectedConfigurationVersion = '1.0.0'
    ExpectedPackageHash          = '<approved ZIP SHA-256>'
    ExpectedBenchmarkHash        = $coverage.BenchmarkSha256
    Coverage                     = $coverage
    ResourceMap                  = $mapping
    ExpectedConfigurationMofHash = $package.ConfigurationMofSha256
    MaximumAgeMinutes            = 60
}
$assessment = ConvertFrom-PowerStigMachineConfigurationReport @parameters
$assessment.Requirements | Select-Object VulnerabilityId, Status, Reasons
```

Here `$package` is the result of `Test-PowerStigAuditPackage` on the approved
ZIP. The mapper's MOF hash must match the embedded MOF hash from that package,
not an unrelated compile output.

Reports are the `2024-04-05` Guest Configuration report REST shape, not just
Policy compliance summaries or `latestAssignmentReport` summaries. Use the
assignment's report link/ID to read its full `reports/<reportId>` resource.
Policy-created assignment names can differ from configuration names.

The reader preserves native `Code`/`Phrase` reasons and observed properties.
It does not invent an expected value when the resource did not report it.
Wrong VM/package/source identities, duplicate IDs and invalid timestamps fail
explicitly. Missing resources/reasons, pending/unknown states, stale results,
unmapped resources and unassessed source requirements cannot become a whole
benchmark pass. `AssessmentStatus` describes the admitted report, not release
or cloud production qualification. Keep raw guest reports private: they may
contain sensitive machine configuration.

## Compose the administrator entry point

After both family policies and their packages pass admission, publish their
custom definitions and compose an initiative using the actual definition IDs:

```powershell
. .\Tools\AzureMachineConfiguration\AuditInitiative.ps1
$initiative = New-PowerStigAuditInitiative `
    -Name 'PowerStigAudit' `
    -WindowsPolicyDefinitionId '<published Windows custom policy ARM ID>' `
    -LinuxPolicyDefinitionId '<published Linux custom policy ARM ID>'
$initiative | ConvertTo-Json -Depth 30 | Set-Content '.\PowerStigAudit.json'
```

The composer produces local JSON only. It accepts subscription or management
group custom-definition IDs, with stable `PowerStigWindows`/`PowerStigLinux`
references. It does not publish definitions, provision prerequisites, grant
roles, or attest to the referenced policies' safety. Both references must point
to reviewed **Audit-only family dispatchers**, not arbitrary per-profile MOFs.
Assign the resulting initiative once at the intended management group,
subscription or resource-group scope. Use separate prerequisite onboarding for
VM identity, the Machine Configuration extension and package read access.

## Cloud and operational qualification

| Environment | Required evidence | Current qualification |
| --- | --- | --- |
| Azure commercial | Exact guest worker, native Reasons, normal Policy delivery, targeting and freshness | Not qualified |
| Azure Government | Same gates in the target government cloud, approved local hosting/identity/network | Not qualified |
| USSEC | Environment-owner-confirmed service/API availability, approved endpoints and local artifacts; all gates in that environment | Not qualified |
| USNAT | Environment-owner-confirmed service/API availability, approved endpoints and local artifacts; all gates in that environment | Not qualified |

No sovereign endpoint is inferred or hard-coded. An initiative's ARM IDs are
cloud-neutral, but service availability, extension images, resource-provider
registration, policy aliases, storage access and API versions are not thereby
qualified. Disconnected environments need approved mirrored dependencies and
artifact promotion without public Gallery/GitHub access at evaluation time.
If Machine Configuration is unavailable in a target environment, a custom
Policy definition cannot make that service available.

Before a lab run, record the exact artifact hashes, target, action, output
location, timeout and powered-on budget. Coordinate exclusive guest access on
shared VMs. Keep new supporting resources in one dedicated resource group;
Policy definitions are subscription/management-group resources, not RG-contained
resources, while their test assignment may target the shared VM RG. Do not
change existing TLS assignments or use their evidence as STIG qualification.
Preserve before/after ARM state, full native results and errors privately.
Restore/deallocate only the exact VMs started for the agreed test; do not delete
shared lab resources as cleanup.

Release gates remain: current source coverage and tailoring review; pinned
offline dependencies; Audit-only artifact inspection; guest runtime execution;
per-rule native explanations; Policy delivery and OS/DC targeting; freshness;
and separate cloud qualification. Roll back by reassigning an approved prior
immutable release, with approval for any assignment deletion. Do not overwrite
old package blobs. Manual controls/exceptions remain visible in reporting.

## Focused validation

```powershell
Import-Module Pester -RequiredVersion 5.3.1
Invoke-Pester -Path .\Tests\Unit\Tools\AzureMachineConfiguration -Output Detailed
```

These are offline behavior tests. They do not execute a configuration against
the workstation or establish guest-worker, Azure Policy or sovereign acceptance.
The [implementation journal](../../AZURE-MACHINE-CONFIGURATION-PLAN.md#journal)
tracks decisions, corrections, completed increments and remaining gates.

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
Its `details.name` must match the pinned generator's exact expression:
`[concat('<package-name>$pid', uniqueString(policy().assignmentId, policy().definitionReferenceId))]`.
The `$pid` portion is literal, not the authoring process ID. This is the
Policy-created assignment name, not a bare package name or a wildcard.
The helper strengthens GuestConfiguration 4.10.0's status-only template with
an `allOf` that requires `Compliant` **and** the assignment's
`guestConfiguration.name`, `guestConfiguration.version`, and
`guestConfiguration.contentHash` to match the validated ZIP. Metadata is
validated separately; metadata alone does not constrain the related-resource
lookup. Missing/broad/unrelated names, status-only conditions and missing,
duplicate, disjunctive or mismatched package conditions fail validation.
These Policy aliases were confirmed against commercial Azure provider
metadata; their availability still requires validation in each sovereign cloud.

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
- [Azure Policy auditIfNotExists related-resource lookup semantics](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-audit-if-not-exists)
- [Develop a custom Machine Configuration package](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/develop-custom-package/overview)
- [PowerSTIG Windows Server configuration](https://github.com/microsoft/PowerStig/tree/4.30.0-PSGallery/source/DSCResources/WindowsServer)
- [Azure `nxtools` project](https://github.com/Azure/nxtools)
