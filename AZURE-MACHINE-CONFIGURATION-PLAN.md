# PowerSTIG fork: Azure Machine Configuration audit plan

**Status:** Implementation has started with a local-only Windows Audit-package
builder/validator and an offline `auditIfNotExists` policy-definition
generator/validator. Package publication, policy assignment, guest execution,
and profile qualification remain separate, uncompleted gates.

## Goal

Use the PowerSTIG fork as the upstream-aligned source for DISA STIG data and
Windows DSC checks, and determine whether it can support audit-only Azure
Machine Configuration at scale. Reuse existing PowerSTIG capability wherever
the exact rule, release, OS role, and runtime are suitable. Add or port only
demonstrated gaps. Keep TLS compliance distinct from broad STIG compliance:
the existing TLS work measures application-specific TLS configuration and
should not be replaced by a general OS baseline.

The resulting assessment must preserve separate claims for official
requirements, implemented checks, host evidence, administrator tailoring, and
Azure Policy delivery. Missing evidence, unsupported content, collection
errors, manual procedures, and stale reports must never be shown as passing.

## Evidence already available

- The fork is based on `microsoft/PowerStig`; version 4.30.0 is pinned at
  commit `8c1425e9ab21a2b8aab54783e2945f16c3bb4811`.
- A static, source-bound comparison exists in the prior AzureTLSCompliance
  workspace. It is not a runtime assessment. For Server 2022 MS it found 197
  DSC candidate IDs among 277 current V2R11 requirements; PowerSTIG contains
  V2R8. For Windows 11, it found 216 among 257 V2R11 requirements; PowerSTIG
  contains V2R7. Role-separated Windows Server rules require MS/DC-aware
  accounting.
- The same comparison found 100 DSC candidate IDs and 343 manual/document IDs
  among 445 RHEL 9 V2R10 requirements, while PowerSTIG contains RHEL 9 V2R8.
  The upstream RHEL and Ubuntu composites import `nx` 1.0; Azure Machine
  Configuration does not use the legacy `nx*` Linux DSC providers. The pinned
  PowerSTIG release has Ubuntu 18.04 data, but no Ubuntu 20.04, 22.04, or
  24.04 data, and no RHEL 8 or 10 data.
- An isolated PowerShell 5.1 compile for Windows Server 2022 MS V2R8 succeeded.
  A GuestConfiguration 4.10.0 Audit package was built without upstream
  modifications. Its 800 ZIP members, hashes, Audit metadata, embedded MOF,
  and 8,130,042-byte uncompressed size were independently verified.
- The successful package proves compile and package-format compatibility only.
  It does **not** prove Guest Configuration worker execution, correct
  compliance Reasons, current V2R11 coverage, host assessment, Azure Policy
  delivery, or fleet qualification.

## Principles and constraints

1. **Audit only.** No DSC `Set`/remediation path in the assessment package.
   Review the generated MOF, package metadata, and resource implementations
   before accepting an artifact as audit-only.
2. **Upstream first.** Do not create a parallel full STIG engine. Keep a clean,
   reviewable fork and prefer upstream data, resources, and maintenance. Keep
   local changes narrow, versioned, tested, and documented for upstream
   contribution where appropriate.
3. **Exact release and role.** Pin the official benchmark artifact, release,
   role, source URL, and hashes. Do not silently substitute an older upstream
   STIG release for a newer official benchmark.
4. **No conversion optimism.** A processed/conversion `pass` marker is not a
   passing host assessment. Preserve manual/document requirements as manual
   evidence; do not make a whole-profile pass claim from a subset.
5. **Machine Configuration compatibility is a separate gate.** Legacy DSC
   resource presence does not establish PowerShell 7 or Linux runtime support.
   Linux `nx*` resources cannot be assumed to run under Machine Configuration.
6. **Meaningful reporting.** Verify native per-rule observed/expected output,
   including Machine Configuration `Reasons` (`Code` and `Phrase`) where
   applicable. Errors and unknown applicability remain explicit.
7. **Tailoring is transparent.** Distinguish official values, organization
   settings, exceptions, and skipped rules. Any excluded control remains
   visible and cannot become an unqualified compliance assertion.
8. **Separate environment qualification.** Commercial Azure results do not
   qualify Azure Government, USSEC, or USNAT. Use only confirmed endpoints,
   service availability, identities, network paths, and approved package
   hosting for each environment.
9. **Preserve evidence and resources.** Keep prior packages, historical
   acceptance, failures, and lab resources intact. Any future guest test needs
   explicit scope, bounded execution, raw evidence, and verified deallocation.
10. **Protect tenant information.** Do not copy Azure tenant identifiers,
    screenshots, raw guest evidence, credentials, or internal lab artifacts
    into this public-source fork.

## Proposed phases and decision gates

### Phase 1 — Establish the fork baseline and contribution model

- Confirm the fork default branch, upstream remote, license, contributor
  instructions, pull-request template, and current upstream release.
- Record a reproducible upstream synchronization procedure. Never merge
  unrelated AzureTLSCompliance lab files or evidence into the fork.
- Decide whether an additional `upstream` remote is needed and document safe
  synchronization without changing user Git configuration.

**Exit:** clean branch history, known upstream baseline, and an agreed
contribution/update strategy.

### Phase 2 — Build a complete versioned coverage matrix

- For each target OS and role, compare the pinned DISA benchmark to the exact
  PowerSTIG release data and resources by stable vulnerability and STIG IDs.
- Start with Windows Server 2022 MS, because the isolated V2R8 Audit package
  already compiles; explicitly reconcile it to the current V2R11 benchmark.
- Include Windows Server 2016, 2019, and 2025, Windows 11, RHEL 8/9/10, and
  Ubuntu 18.04/20.04/22.04/24.04 only where those releases remain in scope.
- Separate automated-resource candidates, manual/document controls, absent
  rules, role/applicability differences, duplicate/split rules, and version
  changes. Retain the source text and hashes for every comparison.
- Determine whether newer exact benchmark imports can be made through the
  repository's supported conversion process or need a narrowly scoped upstream
  contribution.

**Exit:** reviewed per-profile inventory with every official rule represented
and no version/role mismatches hidden as coverage.

### Phase 3 — Validate the Windows Audit runtime and reporting

- Reproduce the pinned Windows Server 2022 MS V2R8 compilation and package
  from a clean, documented build environment.
- Verify that the package dependencies are complete, version-pinned, and
  isolated; verify the Audit mode in the exact package consumed by the worker.
- Inspect DSC resource `Get`, `Test`, and `Set` behavior. Prove the assigned
  Audit artifact cannot remediate. Review whether Get returns useful,
  rule-specific observed/expected information and valid native Reasons.
- Test safe fixtures and errors without running against a workstation or
  changing a production/lab guest. Keep package-format evidence distinct from
  worker and service evidence.
- Reconcile the upstream V2R8 content against the intended current release;
  document any controls that cannot be claimed current.

**Gate:** do not call the Windows profile Azure-qualified until the actual
Machine Configuration worker executes the artifact in an explicitly approved
test environment and returns independently verified native evidence.

### Phase 4 — Choose a supported Linux reuse/port strategy

- Do not package the existing `nx*` composites for Machine Configuration as if
  they were compatible.
- For RHEL 9 and Ubuntu 18.04, evaluate reusable rule data and check semantics
  separately from the legacy DSC resources.
- Compare the cost and maintenance risk of porting suitable checks to
  PowerShell 7-compatible DSC v3 resources versus retaining an explicit,
  supported alternative assessment engine for Linux.
- For RHEL 8/10 and Ubuntu 20.04/22.04/24.04, first establish whether the
  required PowerSTIG benchmark data can be imported and maintained. Do not
  infer coverage from a neighboring OS release.
- Include per-rule positive, negative, missing-evidence, unsupported, and
  collection-error cases; no remediating implementation.

**Decision gate:** select a Linux architecture only after exact release data,
runtime support, reporting, and maintenance ownership are demonstrated.
If Machine Configuration cannot support the chosen resource model, record
that limitation instead of claiming a cross-platform drop-in solution.

### Phase 5 — Define assessment contracts, parameters, and tailoring

- Specify profile identity, source/version pins, OS/role dispatch, stale-data
  handling, error/unknown states, and per-rule output.
- Decide how parameters are passed through Azure assignments, respecting
  Machine Configuration's string-only configuration parameter limitation.
- Define how organizational values, exceptions, skipped rules, and manual
  evidence appear in reports without converting exclusions to passes.
- Keep `NotApplicable` tied to measured, source-supported applicability—not an
  inferred image name, VM name, or missing field.

**Exit:** schema and acceptance tests reject missing IDs, duplicate/truncated
results, mismatched source hashes, unknown status, and unsupported targeting.

### Phase 6 — Build and release pipeline

- Create deterministic, offline-capable package builds from pinned sources and
  dependencies. Record tool versions, module versions, input hashes, MOF
  identity, package contents, audit mode, and output hashes.
- Produce immutable versioned artifacts and a Software Bill of Materials or
  equivalent dependency inventory.
- Separate source validation, package-format validation, worker/runtime
  validation, native report validation, and Azure Policy assignment validation.
- Keep artifacts and any storage permissions least-privilege. Do not put
  internal tenant evidence or credentials in the public fork.

**Exit:** repeat builds are explainable and produce verified, immutable
artifacts with no implicit dependency downloads.

### Phase 7 — Azure Policy and environment deployment design

- Define separate, explicit policy definitions/assignments for each qualified
  OS release/role; group them with an initiative only after targeting is
  proven. Unsupported machines must not be silently selected.
- The current local generator creates an `auditIfNotExists` definition that
  checks the compliance state of a Guest Configuration assignment. When the
  definition is published and assigned, Machine Configuration uses its
  metadata to create the guest assignment. The local generator does not publish
  or assign the policy. Keep the normal Policy delivery path; do not fabricate
  guest assignments for qualification. Deleting a Policy assignment also
  deletes its Policy-created guest assignment, so retain both after tests.
- Validate normal Machine Configuration delivery, assignment identity,
  assignment content hash, freshness, per-rule Reasons, and post-scan state.
- Document commercial Azure first. Treat Azure Government, USSEC, and USNAT
  as separate availability/network/identity qualification exercises; do not
  guess endpoints or reuse commercial-cloud success as proof.
- Keep audit assignment and any remediation/redeploy process out of scope until
  separately authorized.

**Exit:** test evidence proves exact targeting and normal delivery with no
scope/cloud auto-switch and no silent fallback.

### Phase 8 — Controlled acceptance and operator documentation

- Obtain approval before any VM starts, guest invocation, cloud publication,
  role assignment, or Policy assignment.
- Test one explicitly approved machine per supported OS/release/role, preserving
  raw inputs, complete outputs, invocation receipts, source/package pins,
  errors, and final power-state evidence.
- Compare service-level status to native per-rule observations; CLI success
  alone is not assessment success.
- Document package admission, tailoring approvals, assignment, monitoring,
  failure triage, update, rollback, and environment-specific prerequisites.
- Retain the already completed TLS and Windows Server 2022 legacy acceptance as
  separate historical scopes; do not silently broaden their claims.

**Final acceptance:** only name the OS/release/role/environment combinations
that passed every source, runtime, reporting, delivery, targeting, and
operations gate. Keep all other combinations explicitly unqualified.

## Explicitly out of scope for this planning branch

- Implementing or changing DSC resources, rule data, collectors, packages, or
  Policy definitions.
- Running a guest assessment, `Get`/`Test`/`Set`, remediation, or any Azure
  mutation.
- Claiming current Windows V2R11 or Linux Machine Configuration compatibility
  from the V2R8 package-format trial.
- Uploading internal AzureTLSCompliance evidence or tenant data to this fork.
- Deleting or rewriting historical lab resources, artifacts, acceptance, or
  failures.

**Current implementation increment:** `Tools\AzureMachineConfiguration\`
contains a Windows-first helper that always requests `Type Audit` and validates
the generated package metadata, embedded MOF, version, SHA-256, and expanded
size. It also generates a local `auditIfNotExists` policy definition bound to
that package's exact hash and HTTPS content URI, then validates the definition.
The pinned GuestConfiguration 4.10.0 generator runs from a temporary
byte-verified copy so its `gcworker\temp` reset cannot remove files from the
installed module. Focused Pester tests cover package/policy validation,
overwrite guards, unsafe URI rejection, and offline generation. No package or
policy has been published, no policy assignment or guest assignment has been
created, no guest has been invoked, and the worker's per-rule Reasons behavior
is not qualified.

## Journal

### 2026-10-27 - Cross-platform implementation authorization and dispatch decision

- The user authorized implementing this plan, GitHub iterations, documentation,
  and lab policy testing. Earlier "plan only" restrictions describe the original
  planning request, not the current implementation authorization.
- The administrator entry point will be one initiative, with separate Windows
  and Linux Audit packages. Policy routes by OS family; measured guest identity
  selects an exact versioned profile. Marketplace image labels are not evidence
  of the running OS. Unknown/custom-image releases must remain explicit.
- Windows Server scope is member-server profiles only, per the user's follow-up.
  Domain controllers must be rejected by guest detection, not assumed absent.
  Standalone servers may use the MS role only where the benchmark permits it.
- Lab Policy may target the existing shared lab VM resource group. New supporting
  resources belong in one separate PowerSTIG lab resource group. Coordinate guest
  access and power operations with the existing lab owner; preserve TLS artifacts.
  Tenant IDs, private evidence, and cloud credentials stay outside this repository.
- Reused the existing package and policy commits through `e5d6e68e`, rather than
  rewriting the prior integration. The 14 inherited tests passed on PowerShell 7
  with Pester 5.3.1 and GuestConfiguration 4.10.0.
- A source-bound inventory of the archived RHEL 9 V2R8 benchmark contains 446
  requirements. An initial exact-ID lookup appeared to show 18 missing rules;
  inspecting compiled resource names exposed PowerSTIG's `.a`/`.b` split IDs.
  Corrected parent/component accounting yields 346 manual, 96 legacy Linux,
  three mixed-component requirements, and one duplicate reference. No source
  requirements are absent in this exact archived comparison. None of these
  static states establishes host compliance or current-release coverage.
- Added exact measured-identity resolution, source-bound coverage accounting,
  compiled resource-to-vulnerability mapping, native report interpretation, and
  an offline two-family initiative composer. These are foundation helpers, not
  packaged guest dispatchers. The existing per-profile package must not be
  assigned fleet-wide: its generated policy targets the whole OS family.
- Native report admission must use the actual Policy-created assignment ID,
  not assume assignment name equals package name. GuestConfiguration 4.10.0
  generates an assignment name with a Policy-derived suffix. The report reader
  separately checks assignment ID, VM ID, configuration identity and content hash.
- Reproduced the frozen Server 2022 MS package/MOF hash match offline. Its 207
  DSC instances map to 198 source vulnerability IDs, with one explicitly
  unmapped registry-refresh helper. Added split-component and missing-evidence
  report tests. Package validation now exposes the embedded MOF SHA-256 so the
  resource map cannot silently use an unrelated compile output.
- Confirmed archived matching source inventories for Windows 11 V2R7 (262),
  Server 2022 MS V2R8 (238) and Ubuntu 18.04 V2R15 (176). These denominators
  differ from later benchmark releases; do not merge their coverage claims.
- Lab inspection was management-plane read-only. The proposed Windows 11 test
  guest was deallocated and had no extensions. The shared lab coordinator
  reserved a future conditional exclusive slot; no VM was started, extension
  installed, policy assigned, package uploaded or resource created in this
  increment. End-to-end dispatcher and cloud acceptance remain outstanding.
- Local validation: `Import-Module Pester -RequiredVersion 5.3.1;
  Invoke-Pester -Path .\Tests\Unit\Tools\AzureMachineConfiguration -Output Normal
  -PassThru` passed all 63 tests with zero skipped tests; `git diff --check`
  passed. The new GitHub workflow repeats the offline suite on Windows and
  Ubuntu and fails for discovery/container failures as well as failed tests.
  These checks do not qualify native guest execution.
- First GitHub iteration: Ubuntu CI passed. Windows failed before tests because
  the runner's installed Pester 5.9.0 uses a different signing-certificate chain
  than pinned Pester 5.3.1. Changed restoration to `Save-Module` in a job-local
  module directory, avoiding publisher-check bypasses and changes to installed
  runner modules. This is toolchain isolation, not a guest compliance failure.

### 2026-10-27 — Offline Audit policy-definition generation

- Added `New-PowerStigAuditPolicyDefinition` and
  `Test-PowerStigAuditPolicyDefinition`. The generated definition is
  `auditIfNotExists` and must match the validated Audit ZIP's name, version,
  SHA-256, HTTPS content URI, system-assigned content identity, and
  `complianceStatus=Compliant` condition.
- GuestConfiguration 4.10.0's `New-GuestConfigurationPolicy` resets
  `<PSScriptRoot>\gcworker\temp`. To avoid touching the installed module's
  worker state, the helper copies only its policy script and complete templates
  directory to a unique temporary root and verifies their SHA-256 hashes
  before invoking the generator. It stages and validates JSON before moving it
  into the requested output directory, and preserves existing output unless
  `-Force` is provided.
- A local generator integration test used a fixture package and
  `https://example.invalid/` URI with `LocalContentPath`; no network call or
  Azure operation was made. All seven focused policy tests passed with Pester
  5.3.1. The frozen Server 2022 MS V2R8 package was separately revalidated:
  Audit 1.0.0, 800 ZIP entries, 8,130,042 expanded bytes, SHA-256
  `af3213d5b4416f4bd63eedce6559b09e8fec5152da2b1b13eeb2f5ec39f8f05d`.
- This policy effect only checks for an existing compliant Guest Configuration
  assignment at the policy-rule level; Microsoft documents that the Machine
  Configuration service uses the policy metadata to create the guest
  assignment after policy assignment. No package/policy publication,
  assignment, identity change, VM start, or guest execution has occurred.

### 2026-10-27 - Exact-assignment policy review correction

- Confirmed the review finding: the validator previously admitted a missing
  related-resource name. GuestConfiguration 4.10.0's audit template does set
  `details.name`, but its existence condition checks only compliance status.
- Verified the pinned generator's
  `New-GuestConfigurationPolicyGuestAssignmentNameReference` expression:
  `[concat('<package-name>$pid', uniqueString(policy().assignmentId, policy().definitionReferenceId))]`.
  Admission now requires that exact package-bound expression; `$pid` is
  literal and the suffix differentiates policy assignments/initiative references.
- Read-only commercial provider metadata confirms Policy aliases for
  `guestConfiguration.name`, `.version`, and `.contentHash`. The helper now
  strengthens the generated existence condition to require all three plus
  `complianceStatus=Compliant` in `allOf`. It independently revalidates package
  metadata, URI, identity and ZIP SHA-256. Sovereign alias availability and
  live Policy evaluation are not established by this check.
- Added negative cases for missing, wildcard and unrelated assignment names,
  including another package's Policy-derived name; status-only conditions;
  mismatched status/name/version/hash; removed or duplicated predicates; and
  `anyOf`. The actual pinned offline generator test checks the final name,
  four-condition conjunction and ZIP hash.
- Focused validation with Pester 5.3.1:
  `Invoke-Pester -Path .\Tests\Unit\Tools\AzureMachineConfiguration\AuditPolicy.Tests.ps1 -Output Normal -PassThru`
  passed all 21 tests with zero skipped; `git diff --check` passed.
- This correction is scoped to the existing PR. No merge, approval, VM
  operation, assignment change, hosting deployment or cleanup was performed.
- Follow-up clarification: the stock pinned generator already supplies the
  correct suffixed name; the established gap is validator admission of an
  omitted/altered name, not a missing name in the stock generated output.
  Microsoft's [auditIfNotExists semantics](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-audit-if-not-exists)
  specify that `name` fetches one specific related resource instead of all
  resources of that type, and that any matching resource satisfying
  `existenceCondition` suppresses the audit. Thus a name-less, status-only
  variant can be satisfied by an unrelated compliant assignment in the
  applicable lookup scope. This is documented semantic validation, not a
  claim of a live exploit or service-level test.
- Commit `ebb8de02` passed both Windows and Ubuntu jobs in the PR and push
  workflows. `gh pr checks 1 --repo PaulHCode/PowerStig --watch --interval 10`
  completed successfully; PR run `40600341154` reports success for the exact
  commit. No merge or approval was performed.

### 2026-10-28 - Candidate dispatchers and private-only deployment iteration

- Built candidate Windows/Linux Audit 0.2.0 packages with a shared measured-OS
  dispatcher and read-only adapters. Windows reads effective registry values;
  Linux static file matches remain partial evidence, not effective-system
  compliance. Every archived source requirement remains in the denominator.
  Unsupported releases/DCs fail closed. These historical profiles are not
  current-benchmark or cross-cloud qualification.
- The new class resource returns structured assessment data and per-requirement
  Reasons. The original multi-instance report reader must not be used blindly
  for the single-resource fleet report. Native report admission is outstanding.
- Live preflight found the previous supporting deployment absent following a
  coordinator-reported retention incident. Historical package/network receipts
  were not reused as current readiness. Recreated the dedicated support group
  with a publisher-only managed identity and CanNotDelete evidence-retention
  lock; no deletes or cleanup were performed.
- Deployed and ARM-verified private-only storage, a dedicated approved blob
  private endpoint and its DNS zone group. Existing subnet/zone/link are
  references, not redeclared resources. The assessed VM receives container-only
  Reader; the separate publisher identity receives container-only Contributor.
  PNA Disabled, firewall Deny/bypass None, no IP/VNet allowances, no keys/public
  blobs and no NSP publishing exception are explicit and were read back.
- The workstation has no proven private publishing route. Prepared an isolated
  no-PIP Debian utility publisher rather than using existing TLS/Ubuntu guests.
  Its production analogue is an approved private-connected build agent.
  ARM/Entra/agent management traffic is not thereby proved to use Private Link.
- Rejected oversized one-shot Run Command staging before execution. Prepared
  exactly eight hash-checked 128-KiB binary chunks and one final publication
  command, each below conservative source/request limits. Offline reconstruction
  matched both ZIP hashes. The controller checks immutable requests, an absolute
  shutdown deadline, bounded call count/bytes/time and final deallocation.
  A stale daily shutdown time is rejected rather than rolling into the next day.
- The full focused Pester suite passes 93 tests with zero failed/skipped.
  Private publisher DNS/hash rejection and create-only publication behavior
  were also checked offline. ARM validation and What-If passed each deployed
  phase, with no Modify/Delete. Raw tenant evidence and parameters remain private.
- Guest starts, utility publishing, native full reports and normal Policy
  delivery remain separate bounded acceptance gates. Reconcile current guest
  reservations and cumulative power before any start; no overall status alone
  qualifies this candidate for fleet or sovereign-cloud use.
- Reconciled the original validation authorization as a per-VM ceiling, not
  an aggregate cohort allowance. An expired exclusive slot is still expired;
  remaining cumulative time does not authorize an immediate start.
- Documented the Azure VM `EnablePrivateNetworkGC=TRUE` host-channel path
  separately from private package storage and the publisher's Run Command.
  No VM tags or shared network settings were changed to obtain this evidence.
  Managed Run Command input limits are not inferred from the Action API.
- Hardened the unexecuted publisher controller against the ARM instance-view
  shape, creation/extension races, existing NIC/schedule conflicts and loss
  of the original error during terminal-state reconciliation. Readiness is
  written only after verified publication and terminal deallocation. Offline
  fault injection covers these paths; it is not live network/agent acceptance.

### 2026-10-28 - Publisher hold and source-inventory payload validation

- Publisher proposal 004 is NO-GO. Its absolute deadline did not leave the full
  collection/deallocation reservation plus admission/provisioning latency.
  Successful validation/What-If did not authorize execution. No publisher
  create/start or Managed Run Command was performed; retained evidence is not
  overwritten. A future attempt needs fresh deadline-bound artifacts, review
  and exclusive admission. Remaining per-VM budget does not renew a slot.
- Added a host-side fleet `AssessmentJson` validator, separate from the existing
  per-control native report reader. It checks hash-pinned coverage, reported
  identity consistency, complete requirement/component accounting, source
  metadata, expected/observed explanations, freshness and status reductions.
  Manual, organization-dependent, conversion-failed, duplicate, static Linux
  and unknown source states cannot be promoted to passes.
- Fixed timestamp admission to preserve the absolute instant when PowerShell
  JSON deserialization produces a DateTime. Converting that value back to a
  culture-formatted string had lost its UTC offset. Regression cases cover
  offset-bearing timestamps, local culture, future/offsetless values and the
  exact freshness boundary.
- Offline synthetic payloads using the pinned candidate inventories retained
  all 262 Windows 11 requirements/282 components and all 446 RHEL 9
  requirements/481 components. Both remained Incomplete with no guest
  collection or native report admission. Private receipts distinguish these
  synthetic results from live evidence.
- The helper always returns `NativeReportAdmitted=false`. Exact VM/assignment/
  package/native-Reasons binding, private publication, normal Policy delivery
  and sovereign-cloud qualification remain unverified. Compute remains held;
  no TLS/Ubuntu guests or shared network resources were used.
- `Import-Module Pester -RequiredVersion 5.3.1; Invoke-Pester -Path
  .\Tests\Unit\Tools\AzureMachineConfiguration -Output Normal -PassThru`:
  passed, 138 tests with zero failed/skipped. Includes 45 new payload cases and
  actual collector serialization with mocked registry reads; it is not a
  guest execution or native service report test.

### 2026-10-28 - Full-window publisher admission, offline only

- Continued PowerStig work independently of the separate TLS solution. Existing
  no-TLS/no-Ubuntu guest boundaries and the publisher004 NO-GO remain intact.
  No new deployment deadline, slot, parameter manifest or What-If was generated.
- Preserved the reviewed controller/transport and all004 artifacts. Created a
  separate private controller candidate; its timing helper is hash-checked
  before loading. The old004 manifest cannot admit this candidate.
- Replaced the permissive startup window with full-window admission at startup
  and immediately before creation, after read-only preflight. Also recheck
  after blocking extension/VM/chunk reads before continuing subsequent work.
  An aged preflight cannot silently renew the fixed deadline.
- The cleanup reserve includes more than its five-minute polling loop:
  three outer 60-second CLI calls plus one final poll sleep/read overrun make
  9m10s. Adding the existing 18-minute collection cutoff (including
  provisioning), a 1m10s in-flight allowance and 40 seconds for transitions
  requires 29 minutes, within the unchanged 30-minute utility ceiling.
  These are conservative local bounds, not a guarantee of backend completion.
- The new public timing helper passes 15 exact-boundary/invalid-clock cases.
  The full focused suite passes 153 tests, zero failed/skipped. Separate
  private mock tests pass all22 cases, including all earlier fault paths,
  timing-helper drift, aged preflight, late extension/VM/chunk results and
  AST checks tying CLI/sleep bounds to the timing model. NUnit receipts are
  retained privately. These tests invoke only the mock Azure helper.
- No Azure write, compute start, Managed Run Command or package publication
  occurred. Future execution still needs independently authorized exclusive
  admission, fresh deadline-bound artifacts/current operation checks, exact
  live Debian agent/control-path proof and terminal power evidence. Normal
  Policy/native-report and target-cloud qualification gates remain open.

### 2026-10-28 - Hosted worker testing and command-version isolation

- The direct compute-approval question returned no affirmative authorization.
  Continued independently without Azure writes or lab guests. All seven pinned
  historical profiles passed actual collector-to-payload validation with mocked
  registry/file reads: 1,829 requirements/1,955 components accounted for, with
  no native Azure admission claim. Both candidate ZIP hashes and their embedded
  catalog/runtime source hashes were checked before these tests.
- Found that GuestConfiguration4.10.0 exports
  Get-GuestConfigurationPackageComplianceStatus, not the legacy
  Test-GuestConfigurationPackage command. Resolving the legacy name could
  auto-load1.19.4; a globally resolved package-creation command could then use
  that version despite4.10.0 already being loaded. Fixed package creation to
  invoke the exact requested module's export; missing/ambiguous modules and
  missing exports fail rather than falling back.
- Added a bounded real-worker CI check on an ephemeral GitHub-hosted Windows
  runner only. It builds an Audit surrogate and calls the pinned compliance
  export without Apply/remediation. Workstation/self-hosted execution is
  rejected. Raw stdout/stderr and observations are not uploaded to the public
  repository; only scalar-redacted structure, source reason codes, counts,
  hashes and safe failure categories can be retained as artifacts.
- Local focused tests pass164 cases, zero failed/skipped. Includes command
  shadow/version regressions, report-shape privacy/depth tests and hosted-only
  safety gates. Actual hosted worker execution/report-mechanics acceptance is
  pending its CI run; it is not replaced by these unit tests.
- A hosted worker result cannot establish private Azure delivery, exact
  VM/assignment/package/native-envelope binding or target-cloud availability.
  The lab compute hold and all004 receipts remain intact.
