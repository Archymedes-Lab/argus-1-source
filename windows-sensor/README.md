# Native Windows sensor prototype

`build.ps1` compiles `JarvisSensor.cs` with the installed .NET Framework compiler.
The resulting Windows GUI-subsystem executable has no console window, no WSL
dependency, no network listener and no command-execution interface.

The sensor reads Sysmon, Defender and Task Scheduler channels directly using
Windows Event Log APIs. Disabled/inaccessible channels are reported in
`health.json`; it does not change channel configuration. Each immutable batch
contains its events and resume bookmark. The next pass resumes from the latest
published batch, never from an independently advanced cursor. Publication uses
write-through, flush and rename. The spool stops collecting at 512 MiB rather
than deleting evidence. Production retention/acknowledgment remains to be added.

For an isolated single-pass test:

```powershell
.\build.ps1 -OutputDirectory "$env:TEMP\JarvisSensorBuild"
$p = Start-Process "$env:TEMP\JarvisSensorBuild\JarvisSensor.exe" -ArgumentList '--once',"`"$env:TEMP\JarvisSensorTest`"" -Wait -PassThru
Get-Content "$env:TEMP\JarvisSensorTest\health.json"
```

Ingest the spool with `python3 -m jarvis.platform.native PATH_TO_SPOOL --db PATH_TO_PRIVATE_DB`.
The importer does not delete or acknowledge source batches. It rejects gaps in
batch sequences and conflicting duplicate identities transactionally.

This is a collection foundation, not a complete defender. The executable is not
signed or automatically installed. Service deployment must use an
administrator-owned executable, protected ProgramData spool, explicit Event Log
Readers permissions and a restricted service identity. Do not register a service
pointing at a user-writable checkout. Off-host authentication, signed updates,
recovery, native event detections and response policy remain migration work.
