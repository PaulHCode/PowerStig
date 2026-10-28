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

**Implementation status:** `Build-FleetPackage.ps1` builds candidate Windows and
Linux Audit 0.2.0 dispatchers using the included class resource. The adapters
measure a limited subset of checks; manual, unsupported, organization-specific,
conversion-failed and partial evidence remain explicit. Native worker execution,
normal Policy delivery and OS/cloud qualification remain release gates.
In particular, do not assign an existing
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

The fleet candidates return one `PowerStigBaseline` DSC resource with structured
`AssessmentJson` and per-requirement native Reasons. The existing report reader
below maps **per-control DSC instances**; it is not a fleet-dispatcher parser.
Do not treat its resource-map output as admission of the single-resource fleet
report. Retain the full native report and verify its embedded assessment against
the exact source inventory before making a fleet coverage/compliance claim.

### Fleet assessment payloads (offline validation only)

`ConvertFrom-PowerStigFleetAssessment` validates an extracted `AssessmentJson`
payload against the exact hash-pinned coverage inventory. It checks the
consistency of reported host facts/profile, source metadata, every requirement
and split component, explanations, timestamps and status reductions. It keeps
manual/unsupported/partial checks separate from reported failing checks.
Static Linux evidence and ineligible source components cannot become passes.

Use PowerShell 7 or later. Obtain the catalog and coverage from an independently
hash-verified approved package; do not generate the expected coverage hash from
the same untrusted file being admitted.

```powershell
. .\Tools\AzureMachineConfiguration\FleetAssessmentReport.ps1
$catalog = Get-Content '<approved extracted catalog>.json' -Raw | ConvertFrom-Json -AsHashtable
$parameters = @{
    AssessmentJson       = Get-Content '<extracted AssessmentJson payload>.json' -Raw
    CoveragePath         = '<approved extracted WindowsClient-11.coverage.json>'
    ExpectedCoverageHash = $catalog['WindowsClient-11'].CoverageSha256
    ExpectedProfileId    = 'WindowsClient-11'
    ExpectedFamily       = 'Windows'
    MaximumAgeMinutes    = 60
}
$payload = ConvertFrom-PowerStigFleetAssessment @parameters
$payload.RuleCounts
$payload.CheckCounts
$payload.Requirements.Checks | Select-Object Id, Status, Expected, Observed
```

`PayloadStatus` is `Compliant`, `NonCompliant`, `Incomplete`, `Error` or `Stale`,
with stale results taking precedence. A result exactly at the age limit is
fresh. Invalid/future timestamps, inventory/hash/profile mismatches and
contradictory statuses throw rather than returning a success-shaped fallback.
Payloads are limited to 16 MiB and coverage files to 20 MiB.

**This is not native report admission.** `NativeReportAdmitted` is always
`false`, even for a fully compliant payload. Reported host facts are not
independently attested by this function. It neither extracts a payload from an
unqualified native report shape nor verifies the VM, assignment, package or
native Reasons envelope. Those fleet acceptance gates remain open. No payload
status alone establishes Azure Policy compliance or release/cloud qualification.

### Per-control native reports

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

### Private-only artifact delivery

Use the ordinary HTTPS blob endpoint returned by ARM, with private DNS resolving
it to the approved blob private endpoint. Both the publishing host and assessed
VM need private routing and DNS; a private container alone is not network
isolation, and a private endpoint alone does not give a workstation a route.

The lab templates under `infra` separate identity, hosting, the blob private
endpoint and an isolated utility publisher. Storage explicitly disables public
network access, shared-key authorization and anonymous blobs; its firewall
defaults to Deny with no bypass, IP rules or service-endpoint allowances. No NSP
public publishing exception is part of this design. Grant assessed VM identities
only Storage Blob Data Reader on the packages container. Give a separate
publisher-only managed identity Storage Blob Data Contributor on that container,
not the storage account/subscription and not the assessed guest.

For production, publish from an approved private-connected build agent. The lab
utility uses a pinned Debian image, no public IP/password, an identity-first
deployment and explicit power/shutdown guards. Validate the actual new identity
and exact role scope before provisioning compute. Managed Run Command staging
is a **management-plane** transport, not a storage private endpoint; never copy
operator credentials to the guest. Stage artifacts in bounded, hash-checked
chunks rather than embedding large ZIPs in one inline script. Preserve part
receipts, final package hash, private DNS/TLS evidence and terminal power state.

Use version/hash-addressed blob names, create-only publication and authenticated
download/re-hash before assigning Policy. Reject a public DNS result or a
different TLS peer rather than falling back to a public allowance. Preserve
resources/evidence; a lab CanNotDelete lock is supplementary protection, not
permission to remove resources later. Refresh absolute shutdown deadlines
immediately before a bounded run: a stale daily `HHmm` value can otherwise
schedule shutdown on the following day.

For Azure VMs, Machine Configuration documents a separate service-side private
path: set the VM tag `EnablePrivateNetworkGC` to `TRUE`. Its host connection uses
Azure's platform virtual IP `168.63.129.16`; the package URL must still resolve
and route to the storage private endpoint. See the [Machine Configuration
network requirements](https://learn.microsoft.com/azure/governance/machine-configuration/overview/03-network-requirements#communicate-over-private-link-in-azure).
An initiative does not set that tag or establish either route. Treat identity,
extension, private service-path enablement and package connectivity as explicit
onboarding prerequisites; do not broaden network access automatically.

Private package delivery does not establish that ARM, Entra, extension delivery
or a utility publisher's Managed Run Command uses Private Link. Managed Run
Command requires Linux Guest Agent 2.4.0.2 or newer and uses the VM-agent channel;
its live execution and return path must be demonstrated on the exact image and
network, not inferred from Machine Configuration's private-path support. The
Action Run Command API's 262,144-character script limit is not evidence of a
Managed Run Command input limit. Keep independent per-script, serialized-body,
aggregate-byte, call-count and deadline bounds. Review each service's supported
network requirements in the target cloud. An Azure Storage service endpoint
is not a private endpoint, and an NSG allow rule does not provide an outbound
route. If every control-plane connection must also be private, that remains an
additional qualification gate, not a promise made by these storage templates.

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

`PublisherTiming.ps1` provides offline admission/collection assertions for the
bounded lab publisher controller. A five-minute **polling loop** is not a
five-minute end-to-end cleanup allowance: the initial VM read, deallocate
request and final deployment read each have a 60-second CLI timeout, and the
last poll can overrun by its ten-second sleep plus a 60-second read.

The timing model reserves 18 minutes for collection **including provisioning**,
9m10s for that complete cleanup path, 1m10s for an in-flight call/sleep and
40 seconds for transitions: a minimum 29-minute admission window, within the
existing 30-minute utility-VM ceiling. Check admission at startup and again
immediately before creation after read-only preflight. Collection must stop at
18 minutes or earlier to preserve cleanup/in-flight/transition reserves.
Recheck after blocking reads before submitting subsequent work. If timeouts or
polling behavior change, update the model and its regression cases together.

These are conservative local admission checks, not a guarantee of Azure
backend completion or permission to create/start a VM. Terminal ARM power and
deployment evidence is still required; reconciliation failures must remain
explicit and withhold readiness. A future reservation must be independently
authorized. The held publisher proposal cannot be renewed by passing this
helper, and no new deadline/slot is created by the offline tests.

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

The workflow also tests the real Windows worker on an ephemeral GitHub-hosted
runner. `Test-HostedFleetWorker.ps1` refuses normal workstation/self-hosted
execution, builds a fresh Audit-only surrogate package and invokes the
GuestConfiguration 4.10.0 export
`Get-GuestConfigurationPackageComplianceStatus`, never remediation/Apply.
The child process is limited to eight minutes and the job to fifteen minutes.
No Azure credentials, lab VMs, package publication or Policy assignments are
used by this check.

The worker check expects the measured runner profile's complete source Reasons
and a noncompliant result while manual/unsupported checks remain. It validates
the worker's serialized assessment against hash-pinned source coverage, rejects
stale/error results, and compares both native reason surfaces with every complete
requirement/check explanation. Its public
artifact contains only field structure, public PowerSTIG reason codes, counts,
hashes and safe failure metadata. Raw observations/logs stay in the ephemeral
runner and are not uploaded. `NativeAzureReportAdmitted` remains false: a local
worker result is not the Azure assignment report envelope or cloud acceptance.
The worker package is a fresh CI build, not a replacement for an approved
immutable release. See Microsoft's
[package-testing guidance](https://learn.microsoft.com/azure/governance/machine-configuration/how-to/develop-custom-package/3-test-package).

Package creation dispatches through the exact loaded module version's command
export. Merely importing the pinned module is insufficient when another module
version or global command shadows it. Missing/ambiguous pinned modules and
missing exports fail explicitly; no older-tool fallback is used.

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
