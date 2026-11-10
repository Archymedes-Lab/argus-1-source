# Windows publisher trust plan, 2026-11-10

Owner reports “Windows protected your PC” / unknown publisher. This identifies a
SmartScreen reputation warning; it does not establish a malware detection. Other
blocks can coexist and must be diagnosed separately.

## Evidence and constraints

The current release pipeline signs checksums with Archymedes releaser SSH keys.
That authenticates releases to our verifier; it is not Windows Authenticode.
Repository inspection found no executable Authenticode signing step. The existing
signing guide incorrectly suggested EV immediately solves reputation; corrected.
No Windows security setting, exception, certificate store or allow rule was changed.

Preserve these invariants: reviewed immutable build inputs, private signing keys
kept outside artifacts and source, explicit human release authority, verified
publisher and timestamp, signed payloads packaged without later mutation, final
checksums matching distributed bytes, and rollback to a verified prior release.
A valid signature establishes publisher identity, not harmless behavior or a
guarantee that SmartScreen will accept the first download.

## Designs compared

- Broad Defender/ASR exclusions or disabling SmartScreen: weakens the protected
  machine and leaves customers with the same installation problem. Reject.
- Self-signed certificate: useful only for deliberately managed internal trust;
  not public publisher trust and does not solve consumer SmartScreen warnings.
- Publicly trusted Authenticode under one verified publisher: selected for direct
  downloads. Prefer managed signing over an exported private key in CI.
- Microsoft Store distribution: evaluate separately for the desktop UI. Current
  full installer/runtime/task behavior needs a packaging and Store-policy review;
  publishing a UI package alone does not prove all runtime components trusted.

## Implementation sequence

1. Owner enrolls and validates the actual legal publisher. Microsoft Artifact
   Signing Public Trust requires a paid eligible Azure subscription, identity
   validation and an eligible organization/individual. Do not assume eligibility
   from a timezone or a proposed company name. If ineligible, use a public CA's
   supported organization validation and hardware/cloud signing option.
2. Configure a restricted signing identity. For CI, scope workload credentials and
   signing roles to the release environment and approved workflows; do not give
   ordinary PR code access to signing. Keep identity review separate from code review.
3. Build and validate code first. Authenticode-sign and RFC 3161 timestamp Windows
   payload executables/libraries before packaging them. Verify chain, publisher,
   digest and timestamp. Build the installer around those signed payloads, then
   sign and verify the installer. Inventory extracted executables too.
4. Compute release checksums/content manifests from final signed bytes. Perform
   the final human releaser signature and publication only after those gates pass.
   Nothing modifies an executable after it is signed, or after final hashing.
5. Test the actual downloaded release on disposable supported Windows with its
   normal download provenance and protection enabled: verify displayed publisher,
   installation, launch, update, pairing and removal. Record SmartScreen warnings
   even if the signature validates. A local build or CI harness alone cannot
   establish download reputation on customer machines.

Required external dependency: approved public-trust publisher enrollment and
access to its signing service/token. No certificate was bought, identity submitted,
file uploaded or signing credential requested in chat. Pipeline signing remains
unimplemented and no newly signed release is claimed.

## Diagnose simultaneous blocks correctly

| Evidence | Meaning | Next action |
|---|---|---|
| SmartScreen unknown publisher | File/publisher reputation | Verify source/hash and Authenticode; ship consistently signed releases |
| Defender 1116/1117 | Malware detection/action | Inspect exact detection and reviewed artifact locally; submit only approved releasable samples as a software developer if false positive |
| Defender 1121 | ASR block | Identify rule GUID and denied operation; fix unnecessary behavior or test in a disposable VM; signing alone is not guaranteed to resolve it |
| Defender 1123 | Controlled folder access | Inspect attempted write; use the correct application-data location and permissions |
| CodeIntegrity 3077 | Enforced application-control policy | Inspect publisher/signature and effective policy with its administrator |

Process-memory access denials may be legitimate protection. A denied sensitive
operation does not necessarily mean the entire application was blocked. Argus must
report the resulting coverage gap instead of trying to work around the control.

## Sources, checked 2026-11-10

- [SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation): signatures/reputation differ; EV no longer automatically clears warnings.
- [Artifact Signing prerequisites](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart) and [FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq): geography, validation and paid-subscription requirements.
- [Signing integration](https://learn.microsoft.com/en-us/azure/trusted-signing/how-to-signing-integrations): SignTool, digest and timestamp configuration.
- [Developer false-positive process](https://learn.microsoft.com/en-us/defender-xdr/developer-faq): developer submissions are for incorrect detections, not a universal preapproval list.
- [ASR events](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events) and [application-control troubleshooting](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/appcontrol-debugging-and-troubleshooting): distinguish the actual enforcement source.
