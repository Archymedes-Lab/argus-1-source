# ARGUS-2026-003 (DRAFT): hardening of the installers and the elevated broker

Status: **DRAFT, not published.** Prepared 2026-10-30 on branch
`sec/install-hardening`. Severity has not been rated or reviewed yet.

## Summary

After the Argus source was published by accident, we reviewed every script
that runs with administrator or root rights against our own install rules
(ARCHYMEDES-SECURITY-STANDARD DEV-10, APP-1 and INF-5). The review found
places where an administrator step trusted a file or setting that a normal
user account can change. On a PC where malware already runs as the signed-in
user, these could let that malware gain administrator rights or read files it
should not see. Each needs malicious code already running on the PC as that
user, and most need it to act at the moment of installation or within a
15-minute broker run. We know of no use of them.

## What changes

| # | Area | Cause | Fix | Plain-language impact |
|---|---|---|---|---|
| 1 | `argus broker install`, `argus broker remove`, `argus broker sysmon-baseline` | The scripts were copied to the user's TEMP folder and the elevated PowerShell ran them from there. The copy could be changed while the UAC prompt was open. | The elevated side now creates its own administrator-only folder (its permissions are set in the same call that creates it), copies the files there, checks each copy against the SHA-256 Argus computed beforehand, and runs only those copies. Paths and names reach it as quoted data, never as code. | Approving the UAC prompt runs only the files Argus checked. |
| 2 | Elevated broker task | Folder and program paths came from environment variables (`%ProgramData%`, `%SystemRoot%`). The elevated task inherits the user's own environment, which the user can change. | Paths come from the operating system. The module path and TEMP are reset to administrator-only folders. Jobs run only when the protected copy of the broker runs and its folders are still owned by administrators. | The user's settings can no longer steer the elevated task to other code. |
| 3 | Elevated broker collectors that compile code | The collectors compiled C# helpers in the user's TEMP folder while elevated. | TEMP for the broker's jobs is an administrator-only folder. | The compiled helpers cannot be swapped. |
| 4 | Broker folder at install | If `C:\ProgramData\Jarvis` or `...\Broker` already existed, created by a normal user, that user kept ownership and could change its permissions later. | The parent and broker folders get owner Administrators and a fully replaced access list. A broker folder that holds anything not owned by an administrator, or any link, is set aside as evidence and replaced. | A folder made in advance by malware does not become a place it can write elevated code. |
| 5 | Evidence vault job | The elevated job read files from the user's vault inbox by path. A link planted there could point it at a file the user cannot read, which it would then copy into the vault, which the user can read. | Each inbox file is opened once and checked through its handle: the resolved path must be the one requested and the file must have a single link. All reads use that handle. | The vault job cannot be used to read other files. |
| 6 | Sysmon policy apply | The policy file was hashed, then Sysmon was given the original path, which could be swapped in between. A swapped policy was detected and rolled back afterwards, but ran briefly. | The policy is first copied into the administrator-only backup; that copy is hashed, checked and applied. | Only the checked policy is ever applied. |
| 7 | Native sensor installers | The security policy file used to grant the sensor's logon right was written to the user's TEMP folder before being applied elevated. | It is written to a new administrator-only folder under `%SystemRoot%\Temp`. Spool folders get owner Administrators. Paths and system tools are resolved by absolute path. | The installer cannot be made to grant extra rights. |
| 8 | Isolated sensor monitor task | The task ran `powershell.exe` as SYSTEM by bare name, found through `PATH`. | Absolute path to Windows PowerShell. | A folder earlier in `PATH` cannot supply the program. |
| 9 | Windows installer (`Install-Argus.ps1`, `Uninstall-Argus.ps1`) | The elevated step is a script written to the user's TEMP folder, with paths and the user name pasted into its code, and it runs installers from the user's own Argus folder. | To be fixed in the installer package: same verified-copy design as item 1, with data passed as parameters. | Approving the installer's UAC prompt will run only verified files. |

## Affected versions

Compared against the published Windows packages:

| Package | Items present |
|---|---|
| 2026.10.22 (`9d83d1a478de`) | 1, 2, 3, 4, 5, 6, 7, 8 (the elevated steps were run by `argus broker install` / `argus sensor install`) |
| 2026.10.25 (`9d83d1a478de+35419628e380`) | 1 to 9 |
| 2026.10.29 (`9d79f9e9e99e+85a786299464`) | 1 to 9 |
| 2026.10.30 (`7a8301068e6f`) | 1 to 9 |

The Linux server edition (`install.sh`, `uninstall.sh`) was reviewed and is
not affected by these items.

## Fixed in

The first signed release after 2026-10-30. Until then:

- Install only from a package whose `SHA256SUMS` and signature you checked.
- Run `argus broker install` again after upgrading, so the broker's folders and
  scripts are replaced by the hardened versions.

## Credits and references

Internal review. ARCHYMEDES-SECURITY-STANDARD rows DEV-10 (OS/command
injection, path traversal), APP-1, INF-5. Regression tests:
`tests/test_install_hardening.py`.
