# JARVIS live process audit — 2026-10-01

Inventory completed: 2026-10-01T13:03:59.227060+03:00. Counts change as processes start and exit.

## Confirmed runtime and enumeration

The real systemd service is active/running, PID 226, executing the root-owned sealed release under /opt/jarvis/current. The final local health API reports healthy=true, ready=true, protection_healthy=true. Scan and bridge receipts advanced during this audit. Native sensor sequence advanced from 59309 to 59357, with current=true, zero reported importer gaps and zero quarantined batches. These are measured liveness/freshness results, not a compromise verdict.

The installed collectors returned **296 Windows + 102 WSL = 398 process rows**, with no source errors. Independent Windows Get-Process and Win32_Process views were taken before and after collection. Every PID present in both bracketing views was included. This is a PID-level comparison, not a proof against PID reuse or kernel-level hiding.

The /proc bracket had one omitted stable PID, 64094: the Python audit itself. Inspection of the installed Linux collector confirms it deliberately skips os.getpid(). Consequently, the daemon also excludes itself when it performs its own scan. This audit, running separately, includes the actual JARVIS daemon PID 226. Short-lived processes cannot all be captured by a periodic snapshot.

Only Ubuntu was reported as a running WSL distribution. Nine running Docker containers were identified, and their processes visible in Ubuntu were assigned by cgroup. No independent enumeration inside each container PID namespace or WSL VM-root namespace was performed.

## Limits that remain

- The final daemon reconciliation snapshot counted 292 Windows processes: 222 event-history verified, 70 unknown, zero unreconciled. Unknown does not mean malicious or invisible. The API does not expose the full reason for each unknown in this aggregate.
- A historical Sysmon pressure receipt reports 94 ProcessCreate drops at 2026-09-30 17:19:07 UTC. Its current coverage window reports zero dropped creates. Current healthy receipts do not erase that older history loss.
- In the first collector snapshot, 158 Windows image paths and 78 WSL image paths were blank. A later Windows service/configuration lookup reduced unresolved image paths to 43 of 293 rows. Different snapshot times prevent treating those counts as exact before/after coverage changes. Service binary configuration is evidence about the configured file, not proof of the live image bytes.
- The later metadata pass found 238 rows with Valid Authenticode and 12 with NotSigned; 43 lacked a file signature result. Valid signatures identify publishers/files, not benign behavior. Five corresponding Store packages (Widgets, Start experiences, ChatGPT, Intel graphics, WhatsApp) have signature/status values recorded separately in store-packages.json; individual executable NotSigned is not equivalent to an unsigned package. JarvisSensor.exe and RiotClientCrashHandler.exe remain individually unsigned in this pass.
- Many WSL system/container executable paths are unreadable to this user token. Their roles are assigned using process names and service/container context; binary provenance is unverified.

## Product gaps

The deployed `jarvis procs` reads stored historical fingerprints with a default limit of 60. It is not an exhaustive live PID list. The checkout already implements `python3 -m jarvis procs --live --json`, showing all observed rows unless explicitly limited, but the installed release lacks --live. That existing checkout behavior was inspected, not deployed or validated by this audit.

No automatic web-based assignment of every live process was demonstrated. This report performs bounded manual public-name research and combines it with local file descriptions, publisher signatures, services, and container cgroups. Interpreter processes such as PowerShell and Node stay workload-unknown without further local evidence. Names, descriptions and search results are explanations, not authorization or trust decisions.

## Public research

Only generic public executable/product names were searched. Command lines, credentials, documents and raw local evidence were not uploaded. Role descriptions below use these primary sources where applicable; remaining descriptions come from local metadata or clearly qualified name-based interpretation.

- [wsl](https://learn.microsoft.com/en-us/windows/wsl/opensource)
- [services](https://learn.microsoft.com/ka-ge/windows/application-management/svchost-service-refactoring)
- [presentmon](https://github.com/GameTechDev/PresentMon/blob/main/README-Service.md)
- [intel](https://www.intel.com/content/www/us/en/docs/dynamic-application-loader/developer-guide/1-0/host-interface-service.html)
- [ipf](https://www.intel.com/content/www/us/en/download/869519/intel-platform-performance-package.html)
- [cloudflared](https://developers.cloudflare.com/tunnel/)
- [dragonfly](https://www.dragonflydb.io/docs)
- [systemd](https://learn.microsoft.com/en-us/windows/wsl/systemd)

## Every observed process

All 398 collector rows follow. Later local metadata is joined by PID and matching name, without independent start-time validation; treat it as supplemental context, not an atomic process-instance identity proof. Blank image fields retain the audit token’s visibility limit.

| Host | PID | PPID | Name | Role | Identity evidence | Context | Image |
|---|---:|---:|---|---|---|---|---|
| win |  |  | (unattributed) | PID 0 placeholder used by this JARVIS release; independent Windows view names it System Idle Process | Image identity unavailable |  |  |
| win | 4 |  | System | Windows kernel, isolation, registry, memory, or VM component; name-based role, no ordinary image identity established | Image identity unavailable |  |  |
| win | 188 | 4 | Secure System | Windows kernel, isolation, registry, memory, or VM component; name-based role, no ordinary image identity established | Image identity unavailable |  |  |
| win | 232 | 4 | Registry | Windows kernel, isolation, registry, memory, or VM component; name-based role, no ordinary image identity established | Image identity unavailable |  |  |
| win | 256 | 12792 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 632 | 8432 | csrss.exe | Windows client/server runtime subsystem | Image identity unavailable |  |  |
| win | 852 | 4 | smss.exe | Windows session manager | Image identity unavailable |  |  |
| win | 884 | 1608 | RuntimeBroker.exe | Runtime Broker | Authenticode Valid |  | C:\Windows\System32\RuntimeBroker.exe |
| win | 1172 | 1608 | dllhost.exe | Windows COM surrogate host | Image identity unavailable |  |  |
| win | 1196 | 996 | csrss.exe | Windows client/server runtime subsystem | Image identity unavailable |  |  |
| win | 1284 | 996 | wininit.exe | Windows initialization process | Image identity unavailable |  |  |
| win | 1304 | 22060 | conhost.exe | Windows console, pseudoterminal, or terminal host | Image identity unavailable |  | C:\WINDOWS\system32\conhost.exe |
| win | 1420 | 1284 | services.exe | Windows Service Control Manager | Image identity unavailable |  |  |
| win | 1436 | 5904 | ipf_helper.exe | Intel Innovation Platform Framework performance/power service or helper | Authenticode Valid |  | C:\WINDOWS\System32\DriverStore\FileRepository\ipf_cpu.inf_amd64_4bb9da04f87a83ff\ipf_helper.exe |
| win | 1448 | 1284 | LsaIso.exe | Windows authentication / isolated authentication process | Image identity unavailable |  |  |
| win | 1456 | 1284 | lsass.exe | Windows authentication / isolated authentication process | Authenticode Valid; file from service configuration, not a verified live image handle | Services: KeyIso (CNG Key Isolation), SamSs (Security Accounts Manager), VaultSvc (Credential Manager) | C:\WINDOWS\system32\lsass.exe |
| win | 1584 | 4168 | OneDrive.exe | Microsoft OneDrive | Authenticode Valid |  | C:\Users\chris\AppData\Local\Microsoft\OneDrive\OneDrive.exe |
| win | 1604 | 18092 | RiotClientCrashHandler.exe | Riot crash handler; readable image NotSigned, not independently authenticated here | Authenticode NotSigned |  | C:\Riot Games\Riot Client\RiotClientCrashHandler.exe |
| win | 1608 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: BrokerInfrastructure (Background Tasks Infrastructure Service), DcomLaunch (DCOM Server Process Launcher), PlugPlay (Plug and Play), Power (Power), SystemEventsBroker (System Events Broker) | C:\WINDOWS\system32\svchost.exe |
| win | 1632 | 1284 | fontdrvhost.exe | Windows user-mode font driver host | Image identity unavailable |  |  |
| win | 1664 | 1608 | StartMenuExperienceHost.exe | Windows Start Experience Host | Authenticode Valid |  | C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe |
| win | 1736 | 1420 | WUDFHost.exe | Windows user-mode device driver host | Image identity unavailable |  |  |
| win | 1744 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: RpcEptMapper (RPC Endpoint Mapper), RpcSs (Remote Procedure Call (RPC)) | C:\WINDOWS\system32\svchost.exe |
| win | 1824 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Image identity unavailable | Services: LSM (LSM) |  |
| win | 1872 | 1608 | dllhost.exe | Windows COM surrogate host | Authenticode Valid |  | C:\WINDOWS\system32\DllHost.exe |
| win | 1912 | 1420 | WUDFHost.exe | Windows user-mode device driver host | Image identity unavailable |  |  |
| win | 1988 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: HvHost (HV Host Service) | C:\WINDOWS\system32\svchost.exe |
| win | 1996 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: TapiSrv (Telephony) | C:\WINDOWS\System32\svchost.exe |
| win | 2008 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: BDESVC (BitLocker Drive Encryption Service) | C:\WINDOWS\System32\svchost.exe |
| win | 2044 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: nsi (Network Store Interface Service) | C:\WINDOWS\system32\svchost.exe |
| win | 2096 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: TimeBrokerSvc (Time Broker) | C:\WINDOWS\system32\svchost.exe |
| win | 2104 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: NcbService (Network Connection Broker) | C:\WINDOWS\System32\svchost.exe |
| win | 2144 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: Dhcp (DHCP Client) | C:\WINDOWS\system32\svchost.exe |
| win | 2156 | 13740 | firefox.exe | Firefox | Authenticode Valid |  | C:\Program Files\Mozilla Firefox\firefox.exe |
| win | 2268 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: Dnscache (DNS Client) | C:\WINDOWS\system32\svchost.exe |
| win | 2288 | 1420 | IntelCpHDCPSvc.exe | Intel HD Graphics Drivers for Windows(R) | Authenticode Valid; file from service configuration, not a verified live image handle | Services: cplspcon (Intel(R) Content Protection HDCP Service) | C:\WINDOWS\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_8f45d7765bed783c\IntelCpHDCPSvc.exe |
| win | 2300 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: DisplayEnhancementService (Display Enhancement Service) | C:\WINDOWS\system32\svchost.exe |
| win | 2320 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: hidserv (Human Interface Device Service) | C:\WINDOWS\system32\svchost.exe |
| win | 2376 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: netprofm (Network List Service) | C:\WINDOWS\System32\svchost.exe |
| win | 2444 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: CoreMessagingRegistrar (CoreMessaging) | C:\WINDOWS\system32\svchost.exe |
| win | 2468 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: Schedule (Task Scheduler) | C:\WINDOWS\system32\svchost.exe |
| win | 2504 | 1420 | WUDFHost.exe | Windows user-mode device driver host | Image identity unavailable |  |  |
| win | 2600 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: ProfSvc (User Profile Service) | C:\WINDOWS\system32\svchost.exe |
| win | 2756 | 1420 | ELAN_MOC_Service.exe | ELAN MOC Service | Authenticode Valid; file from service configuration, not a verified live image handle | Services: ELAN_MOC_Service (ELAN MOC Service) | C:\WINDOWS\System32\ELAN_MOC_Service.exe |
| win | 2788 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: WinHttpAutoProxySvc (WinHTTP Web Proxy Auto-Discovery Service) | C:\WINDOWS\system32\svchost.exe |
| win | 2848 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: Wcmsvc (Windows Connection Manager) | C:\WINDOWS\system32\svchost.exe |
| win | 2892 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: UserManager (User Manager) | C:\WINDOWS\system32\svchost.exe |
| win | 2940 | 20468 | M365Copilot.exe | Microsoft 365 Copilot App | Authenticode Valid |  | C:\Program Files\WindowsApps\Microsoft.MicrosoftOfficeHub_19.2609.52011.0_x64__8wekyb3d8bbwe\M365Copilot.exe |
| win | 2968 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: CryptSvc (Cryptographic Services) | C:\WINDOWS\system32\svchost.exe |
| win | 3008 | 4168 | SecurityHealthSystray.exe | Windows Security notification icon | Authenticode Valid |  | C:\Windows\System32\SecurityHealthSystray.exe |
| win | 3092 | 12792 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 3104 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: SENS (System Event Notification Service) | C:\WINDOWS\system32\svchost.exe |
| win | 3276 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: hns (Host Network Service) | C:\WINDOWS\system32\svchost.exe |
| win | 3348 | 9868 | ms-teams.exe | Microsoft Teams | Authenticode Valid |  | C:\Program Files\WindowsApps\MSTeams_26246.1604.5133.838_x64__8wekyb3d8bbwe\ms-teams.exe |
| win | 3416 | 6264 | DefenderSessionHelper.exe | Microsoft Defender Session Helper | Authenticode Valid |  | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\DefenderSessionHelper.exe |
| win | 3424 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: nvagent (Network Virtualization Service) | C:\WINDOWS\system32\svchost.exe |
| win | 3440 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: DispBrokerDesktopSvc (Display Policy Service) | C:\WINDOWS\system32\svchost.exe |
| win | 3460 | 4168 | ollama app.exe | Ollama local model application/server; locally signed readable binaries | Authenticode Valid |  | C:\Users\chris\AppData\Local\Programs\Ollama\ollama app.exe |
| win | 3548 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: BFE (Base Filtering Engine), mpssvc (Windows Defender Firewall) | C:\WINDOWS\system32\svchost.exe |
| win | 3572 | 1420 | AppHelperCap.exe | AppHelperCap | Authenticode Valid; file from service configuration, not a verified live image handle | Services: HPAppHelperCap (HP App Helper HSA Service) | C:\WINDOWS\System32\DriverStore\FileRepository\hpcustomcapcomp.inf_amd64_bac3c2b2a2c0d811\x64\AppHelperCap.exe |
| win | 3612 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: FontCache (Windows Font Cache Service) | C:\WINDOWS\system32\svchost.exe |
| win | 3616 | 1420 | SysInfoCap.exe | SysInfoCap | Authenticode Valid; file from service configuration, not a verified live image handle | Services: HPSysInfoCap (HP System Info HSA Service) | C:\WINDOWS\System32\DriverStore\FileRepository\hpcustomcapcomp.inf_amd64_bac3c2b2a2c0d811\x64\SysInfoCap.exe |
| win | 3636 | 1420 | DiagsCap.exe | DiagsCap | Authenticode Valid; file from service configuration, not a verified live image handle | Services: HPDiagsCap (HP Diagnostics HSA Service) | C:\WINDOWS\System32\DriverStore\FileRepository\hpcustomcapcomp.inf_amd64_bac3c2b2a2c0d811\x64\DiagsCap.exe |
| win | 3660 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: Winmgmt (Windows Management Instrumentation) | C:\WINDOWS\system32\svchost.exe |
| win | 3668 | 1420 | NetworkCap.exe | NetworkCap | Authenticode Valid; file from service configuration, not a verified live image handle | Services: HPNetworkCap (HP Network HSA Service) | C:\WINDOWS\System32\DriverStore\FileRepository\hpcustomcapcomp.inf_amd64_bac3c2b2a2c0d811\x64\NetworkCap.exe |
| win | 3676 | 1608 | unsecapp.exe | Windows WMI callback/provider host | Image identity unavailable |  |  |
| win | 3704 | 1420 | TouchpointAnalyticsClientService.exe | HP Insights Analytics Service | Authenticode Valid; file from service configuration, not a verified live image handle | Services: HpTouchpointAnalyticsService (HP Insights Analytics) | C:\WINDOWS\System32\DriverStore\FileRepository\hpanalyticscomp.inf_amd64_b532962506597d3d\x64\TouchpointAnalyticsClientService.exe |
| win | 3732 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: AudioEndpointBuilder (Windows Audio Endpoint Builder) | C:\WINDOWS\System32\svchost.exe |
| win | 3752 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: SharedAccess (Internet Connection Sharing (ICS)) | C:\WINDOWS\System32\svchost.exe |
| win | 3936 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: EventLog (Windows Event Log) | C:\WINDOWS\System32\svchost.exe |
| win | 3976 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: Themes (Themes) | C:\WINDOWS\System32\svchost.exe |
| win | 3984 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: EventSystem (COM+ Event System) | C:\WINDOWS\system32\svchost.exe |
| win | 3992 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: SysMain (SysMain) | C:\WINDOWS\system32\svchost.exe |
| win | 4084 | 4 | Memory Compression | Windows kernel, isolation, registry, memory, or VM component; name-based role, no ordinary image identity established | Image identity unavailable |  |  |
| win | 4168 | 5928 | explorer.exe | Windows Explorer | Authenticode Valid |  | C:\WINDOWS\Explorer.EXE |
| win | 4172 | 1420 | hpsvcsscan.exe | HP Services Scan | Authenticode Valid; file from service configuration, not a verified live image handle | Services: hpsvcsscan (HP Services Scan) | C:\WINDOWS\System32\DriverStore\FileRepository\hpsvcsscancomp.inf_amd64_df5bc9f22dc3c742\x64\hpsvcsscan.exe |
| win | 4288 | 4524 | CrossDeviceResume.exe | Microsoft® Windows® Operating System | Authenticode Valid |  | C:\WINDOWS\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\CrossDeviceResume.exe |
| win | 4328 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: Audiosrv (Windows Audio) | C:\WINDOWS\System32\svchost.exe |
| win | 4384 | 3348 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 4516 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: StateRepository (State Repository Service) | C:\WINDOWS\system32\svchost.exe |
| win | 4524 | 2892 | sihost.exe | Shell Infrastructure Host | Authenticode Valid |  | C:\WINDOWS\system32\sihost.exe |
| win | 4536 | 1608 | WidgetService.exe | WidgetService.exe | Authenticode NotSigned |  | C:\Program Files\WindowsApps\Microsoft.WidgetsPlatformRuntime_1.6.19.0_x64__8wekyb3d8bbwe\WidgetService\WidgetService.exe |
| win | 4620 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: RmSvc (Radio Management Service) | C:\WINDOWS\System32\svchost.exe |
| win | 4728 | 7412 | powershell.exe | PowerShell interpreter; script purpose not inferred from its name | Image identity unavailable |  | C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe |
| win | 4816 | 1608 | SearchHost.exe | Microsoft® Windows® Operating System | Authenticode Valid |  | C:\WINDOWS\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe |
| win | 4848 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: Appinfo (Application Information) | C:\WINDOWS\system32\svchost.exe |
| win | 4928 | 19552 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 4956 | 1608 | RuntimeBroker.exe | Runtime Broker | Authenticode Valid |  | C:\Windows\System32\RuntimeBroker.exe |
| win | 4988 | 1608 | WmiPrvSE.exe | Windows WMI callback/provider host | Image identity unavailable |  |  |
| win | 5028 | 4524 | IntelGraphicsSoftware.exe | Intel® Graphics Software | Authenticode NotSigned |  | C:\Program Files\WindowsApps\AppUp.IntelArcSoftware_26.32.2604.0_x64__8j3eq9eme6ctt\VFS\ProgramFilesX64\Intel\Intel Graphics Software\IntelGraphicsSoftware.exe |
| win | 5076 | 1420 | TrustedInstaller.exe | Windows component servicing / module installer | Image identity unavailable |  |  |
| win | 5192 | 1420 | escsvc64.exe | Epson Scanner Service (64bit) | Authenticode Valid; file from service configuration, not a verified live image handle | Services: EpsonScanSvc (Epson Scanner Service) | C:\WINDOWS\system32\EscSvc64.exe |
| win | 5204 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: LanmanServer (Server) | C:\WINDOWS\system32\svchost.exe |
| win | 5320 | 6020 | wslhost.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Program Files\WSL\wslhost.exe |
| win | 5400 | 1420 | RtkAudUService64.exe | Realtek HD Audio Universal Service; local signed product metadata on readable instances | Authenticode Valid; file from service configuration, not a verified live image handle | Services: RtkAudioUniversalService (Realtek Audio Universal Service) | C:\WINDOWS\System32\DriverStore\FileRepository\realtekservice.inf_amd64_464be4340fa51d6a\RtkAudUService64.exe |
| win | 5436 | 1420 | HotKeyServiceUWP.exe | HP Hotkey UWP Service | Authenticode Valid; file from service configuration, not a verified live image handle | Services: HotKeyServiceUWP (HP Hotkey UWP Service) | C:\WINDOWS\System32\DriverStore\FileRepository\hpqkbsoftwarecompnent.inf_amd64_0d182501a33019e2\HotKeyServiceUWP.exe |
| win | 5472 | 16904 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 5492 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: TextInputManagementService (Text Input Management Service) | C:\WINDOWS\System32\svchost.exe |
| win | 5504 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: LanmanWorkstation (Workstation) | C:\WINDOWS\System32\svchost.exe |
| win | 5520 | 4384 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 5560 | 1420 | WMIRegistrationService.exe | Intel(R) Management Engine WMI Provider Registration | Authenticode Valid; file from service configuration, not a verified live image handle | Services: WMIRegistrationService (Intel(R) Management Engine WMI Provider Registration) | C:\WINDOWS\System32\DriverStore\FileRepository\mewmiprov.inf_amd64_92a56761ef7ba712\WMIRegistrationService.exe |
| win | 5584 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: DiagTrack (Connected User Experiences and Telemetry) | C:\WINDOWS\System32\svchost.exe |
| win | 5740 | 15748 | conhost.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\WINDOWS\system32\conhost.exe |
| win | 5788 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: DusmSvc (Data Usage) | C:\WINDOWS\System32\svchost.exe |
| win | 5796 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: DeviceAssociationService (Device Association Service) | C:\WINDOWS\system32\svchost.exe |
| win | 5800 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: StiSvc (Windows Image Acquisition (WIA)) | C:\WINDOWS\system32\svchost.exe |
| win | 5820 | 13740 | firefox.exe | Firefox | Authenticode Valid |  | C:\Program Files\Mozilla Firefox\firefox.exe |
| win | 5880 | 17952 | wsl.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Windows\system32\wsl.exe |
| win | 5896 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: WlanSvc (WLAN AutoConfig) | C:\WINDOWS\system32\svchost.exe |
| win | 5904 | 1420 | ipf_uf.exe | Intel Innovation Platform Framework performance/power service or helper | Authenticode Valid; file from service configuration, not a verified live image handle | Services: ipfsvc (Intel(R) Innovation Platform Framework Service) | C:\WINDOWS\System32\DriverStore\FileRepository\ipf_cpu.inf_amd64_4bb9da04f87a83ff\ipf_uf.exe |
| win | 5932 | 1420 | FMService64.exe | Expected Fortemedia audio processing/control component; local product metadata where available | Authenticode Valid; file from service configuration, not a verified live image handle | Services: FMAPOService (Fortemedia APO Control Service) | C:\WINDOWS\System32\FMService64.exe |
| win | 5948 | 1420 | RtkBtManServ.exe | Realtek Bluetooth Service Application | Authenticode Valid; file from service configuration, not a verified live image handle | Services: RtkBtManServ (Realtek Bluetooth Device Manager Service) | C:\WINDOWS\RtkBtManServ.exe |
| win | 5956 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: ShellHWDetection (Shell Hardware Detection) | C:\WINDOWS\System32\svchost.exe |
| win | 6020 | 1420 | wslservice.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid; file from service configuration, not a verified live image handle | Services: WSLService (WSL Service) | C:\Program Files\WSL\wslservice.exe |
| win | 6024 | 1420 | HpSfuService64.exe | SFU Service | Authenticode Valid; file from service configuration, not a verified live image handle | Services: SFUService (HP SFU Service) | C:\WINDOWS\System32\DriverStore\FileRepository\hpsfuservice.inf_amd64_03ebfd05b519032c\HpSfuService64.exe |
| win | 6036 | 1420 | IntelAudioService.exe | IntelAudioService | Authenticode Valid; file from service configuration, not a verified live image handle | Services: IntelAudioService (Intel(R) Audio Service) | C:\WINDOWS\System32\DriverStore\FileRepository\intcoed.inf_amd64_2959a83fe72a1f51\AS\IAS\IntelAudioService.exe |
| win | 6044 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: iphlpsvc (IP Helper) | C:\WINDOWS\System32\svchost.exe |
| win | 6060 | 1420 | spoolsv.exe | Spooler SubSystem App | Authenticode Valid; file from service configuration, not a verified live image handle | Services: Spooler (Print Spooler) | C:\WINDOWS\System32\spoolsv.exe |
| win | 6080 | 2468 | conhost.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\WINDOWS\System32\conhost.exe |
| win | 6092 | 17952 | OpenConsole.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.11911.0_x64__8wekyb3d8bbwe\OpenConsole.exe |
| win | 6096 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: smphost (Microsoft Storage Spaces SMP) | C:\WINDOWS\System32\svchost.exe |
| win | 6156 | 1420 | ipfsvc.exe | Intel Innovation Platform Framework performance/power service or helper | Authenticode Valid; file from service configuration, not a verified live image handle | Services: dptftcs (Intel(R) Dynamic Tuning Technology Telemetry Service) | C:\WINDOWS\System32\DriverStore\FileRepository\dtt_sw.inf_amd64_683097297aaa9bb4\ipfsvc.exe |
| win | 6164 | 1420 | jhi_service.exe | Intel Dynamic Application Loader host/firmware interface | Authenticode Valid; file from service configuration, not a verified live image handle | Services: jhi_service (Intel(R) Dynamic Application Loader Host Interface Service) | C:\WINDOWS\System32\DriverStore\FileRepository\dal.inf_amd64_b45f13a105037dbe\jhi_service.exe |
| win | 6172 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: WpnService (Windows Push Notifications System Service) | C:\WINDOWS\system32\svchost.exe |
| win | 6180 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: DPS (Diagnostic Policy Service) | C:\WINDOWS\System32\svchost.exe |
| win | 6188 | 1420 | SNAPOSS64.exe | Sonitude Audio Processing Object service; locally signed Sonitude binary/product | Authenticode Valid; file from service configuration, not a verified live image handle | Services: SNAPOService (Sonitude APO Service) | C:\WINDOWS\System32\DriverStore\FileRepository\snapo64.inf_amd64_fd4aaa60454ea9da\SNAPOSS64.exe |
| win | 6196 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: TrkWks (Distributed Link Tracking Client) | C:\WINDOWS\System32\svchost.exe |
| win | 6212 | 1420 | MpDefenderCoreService.exe | Antimalware Core Service | Authenticode Valid; file from service configuration, not a verified live image handle | Services: MDCoreSvc (Microsoft Defender Core Service) | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\MpDefenderCoreService.exe |
| win | 6220 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: WwanSvc (WWAN AutoConfig) | C:\WINDOWS\system32\svchost.exe |
| win | 6264 | 1420 | MsMpEng.exe | Antimalware Service Executable | Authenticode Valid; file from service configuration, not a verified live image handle | Services: WinDefend (Microsoft Defender Antivirus Service) | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\MsMpEng.exe |
| win | 6392 | 1420 | Sysmon64.exe | System activity monitor | Authenticode Valid; file from service configuration, not a verified live image handle | Services: Sysmon64 (Sysmon64) | C:\WINDOWS\Sysmon64.exe |
| win | 6496 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: webthreatdefsvc (Web Threat Defense Service) | C:\WINDOWS\system32\svchost.exe |
| win | 6572 | 1608 | CrossDeviceService.exe | Microsoft Cross Device Service | Authenticode Valid |  | C:\Program Files\WindowsApps\MicrosoftWindows.CrossDevice_1.26072.116.0_x64__cw5n1h2txyewy\CrossDeviceService.exe |
| win | 6808 | 16904 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 6844 | 1420 | IntelGraphicsSoftware.Service.exe | IntelGraphicsSoftware.Service | Authenticode NotSigned; file from service configuration, not a verified live image handle | Services: IntelGraphicsSoftwareService (Intel® Graphics Software) | C:\Program Files\WindowsApps\AppUp.IntelArcSoftware_26.32.2604.0_x64__8j3eq9eme6ctt\VFS\ProgramFilesX64\Intel\Intel Graphics Software\IntelGraphicsSoftware.Service.exe |
| win | 6852 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: WSAIFabricSvc (Windows AI Components Host) | C:\WINDOWS\system32\svchost.exe |
| win | 6944 | 13740 | firefox.exe | Firefox | Authenticode Valid |  | C:\Program Files\Mozilla Firefox\firefox.exe |
| win | 7092 | 1420 | codex-windows-sandbox-service.exe | OpenAI Codex Windows sandbox service; registered service and signed binary | Authenticode Valid; file from service configuration, not a verified live image handle | Services: CodexSandboxService.OpenAI.Codex (ChatGPT) | C:\Program Files\WindowsApps\OpenAI.Codex_26.924.2738.0_x64__2p2nqsd0c76g0\app\resources\codex-windows-sandbox-service.exe |
| win | 7104 | 1420 | JarvisSensor.exe | JARVIS native Windows sensor; registered JarvisNativeSensor service; binary NotSigned | Authenticode NotSigned; file from service configuration, not a verified live image handle | Services: JarvisNativeSensor (JARVIS native sensor) | C:\Program Files\Jarvis\Sensor\JarvisSensor.exe |
| win | 7148 | 2468 | MicrosoftEdgeUpdate.exe | Expected Microsoft Edge updater; this image path unreadable | Image identity unavailable |  |  |
| win | 7404 | 18532 | conhost.exe | Windows console, pseudoterminal, or terminal host | Image identity unavailable |  |  |
| win | 7412 | 16220 | wsl.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Program Files\WSL\wsl.exe |
| win | 7676 | 6844 | PresentMonService.exe | Intel PresentMon graphics frame/performance telemetry service | Image identity unavailable |  |  |
| win | 7792 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: camsvc (Capability Access Manager Service) | C:\WINDOWS\system32\svchost.exe |
| win | 8064 | 1420 | cowork-svc.exe | Cowork VM service; registered service and readable signed binary, vendor recorded in metadata | Authenticode Valid; file from service configuration, not a verified live image handle | Services: CoworkVMService (Claude) | C:\Program Files\WindowsApps\Claude_2.9939.2.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe |
| win | 8092 | 5400 | RtkAudUService64.exe | Realtek HD Audio Universal Service; local signed product metadata on readable instances | Image identity unavailable |  |  |
| win | 8312 | 1420 | LanWlanWwanSwitchingServiceUWP.exe | HP LAN/WLAN/WWAN Switching UWP Service | Authenticode Valid; file from service configuration, not a verified live image handle | Services: LanWlanWwanSwitchingServiceUWP (HP LAN/WLAN/WWAN Switching UWP Service) | C:\WINDOWS\System32\DriverStore\FileRepository\hpqkbsoftwarecompnent.inf_amd64_0d182501a33019e2\LanWlanWwanSwitchingServiceUWP.exe |
| win | 8360 | 4168 | SnippingTool.exe | SnippingTool.exe | Authenticode Valid |  | C:\Program Files\WindowsApps\Microsoft.ScreenSketch_11.2607.23.0_x64__8wekyb3d8bbwe\SnippingTool\SnippingTool.exe |
| win | 8464 | 10416 | wslhost.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Image identity unavailable |  |  |
| win | 8540 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid | Services: PimIndexMaintenanceSvc_41338e4 (Contact Data_41338e4), UnistoreSvc_41338e4 (User Data Storage_41338e4), UserDataSvc_41338e4 (User Data Access_41338e4) | C:\WINDOWS\System32\svchost.exe |
| win | 8548 | 4524 | WhatsApp.Root.exe | WhatsApp.Root | Authenticode NotSigned |  | C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2637.100.0_x64__cv1g1gvanyjgm\WhatsApp.Root.exe |
| win | 8572 | 4384 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 8580 | 19552 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 8908 | 13740 | firefox.exe | Firefox | Authenticode Valid |  | C:\Program Files\Mozilla Firefox\firefox.exe |
| win | 8932 | 4524 | ChatGPT Classic.exe | ChatGPT Classic | Authenticode NotSigned |  | C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2026.190.0_x64__2p2nqsd0c76g0\app\ChatGPT Classic.exe |
| win | 9048 | 5584 | AggregatorHost.exe | Expected Windows Aggregator Host; exact subsystem remains unverified | Image identity unavailable |  |  |
| win | 9076 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: TokenBroker (Web Account Manager) | C:\WINDOWS\system32\svchost.exe |
| win | 9240 | 5932 | FMAudioMonitor.exe | Expected Fortemedia audio processing/control component; local product metadata where available | Image identity unavailable |  |  |
| win | 9280 | 1608 | TextInputHost.exe | Windows text input framework | Authenticode Valid |  | C:\WINDOWS\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe |
| win | 9284 | 2468 | powershell.exe | PowerShell interpreter; script purpose not inferred from its name | Image identity unavailable |  |  |
| win | 9300 | 7676 | conhost.exe | Windows console, pseudoterminal, or terminal host | Image identity unavailable |  |  |
| win | 9384 | 9284 | conhost.exe | Windows console, pseudoterminal, or terminal host | Image identity unavailable |  |  |
| win | 9464 | 17952 | OpenConsole.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.11911.0_x64__8wekyb3d8bbwe\OpenConsole.exe |
| win | 9500 | 1608 | RuntimeBroker.exe | Runtime Broker | Authenticode Valid |  | C:\Windows\System32\RuntimeBroker.exe |
| win | 9616 | 5320 | conhost.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\WINDOWS\system32\conhost.exe |
| win | 9660 | 3348 | ms-teams.exe | Microsoft Teams | Authenticode Valid |  | C:\Program Files\WindowsApps\MSTeams_26246.1604.5133.838_x64__8wekyb3d8bbwe\ms-teams.exe |
| win | 9712 | 9964 | dwm.exe | Windows desktop compositor | Image identity unavailable |  |  |
| win | 9716 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: CDPSvc (Connected Devices Platform Service) | C:\WINDOWS\system32\svchost.exe |
| win | 9760 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: StorSvc (Storage Service) | C:\WINDOWS\System32\svchost.exe |
| win | 9964 | 8432 | winlogon.exe | Windows sign-in/session manager | Image identity unavailable |  |  |
| win | 10028 | 12812 | vmwp.exe | Windows kernel, isolation, registry, memory, or VM component; name-based role, no ordinary image identity established | Image identity unavailable |  |  |
| win | 10196 | 18440 | wslhost.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Program Files\WSL\wslhost.exe |
| win | 10200 | 1608 | WmiPrvSE.exe | Windows WMI callback/provider host | Image identity unavailable |  |  |
| win | 10372 | 9284 | wsl.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Image identity unavailable |  |  |
| win | 10412 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: WFDSConMgrSvc (Wi-Fi Direct Services Connection Manager Service) | C:\WINDOWS\system32\svchost.exe |
| win | 10416 | 10372 | wsl.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Image identity unavailable |  |  |
| win | 10436 | 13740 | crashhelper.exe | Firefox | Authenticode Valid |  | C:\Program Files\Mozilla Firefox\crashhelper.exe |
| win | 10792 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: WdiSystemHost (Diagnostic System Host) | C:\WINDOWS\System32\svchost.exe |
| win | 10900 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: PcaSvc (Program Compatibility Assistant Service) | C:\WINDOWS\system32\svchost.exe |
| win | 10912 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid | Services: NPSMSvc_41338e4 (Now Playing Session Manager Service_41338e4) | C:\WINDOWS\system32\svchost.exe |
| win | 10940 | 12120 | conhost.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\WINDOWS\system32\conhost.exe |
| win | 11024 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid | Services: CDPUserSvc_41338e4 (Connected Devices Platform User Service_41338e4) | C:\WINDOWS\system32\svchost.exe |
| win | 11084 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid | Services: cbdhsvc_41338e4 (Clipboard User Service_41338e4) | C:\WINDOWS\system32\svchost.exe |
| win | 11232 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: lmhosts (TCP/IP NetBIOS Helper) | C:\WINDOWS\System32\svchost.exe |
| win | 11472 | 1608 | rundll32.exe | Windows host process (Rundll32) | Authenticode Valid |  | C:\WINDOWS\System32\rundll32.exe |
| win | 11532 | 1608 | RuntimeBroker.exe | Runtime Broker | Authenticode Valid |  | C:\Windows\System32\RuntimeBroker.exe |
| win | 11548 | 17952 | wsl.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Windows\system32\wsl.exe |
| win | 11596 | 12792 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 11632 | 22060 | tasklist.exe | Windows process-list utility, possibly a concurrent JARVIS audit | Image identity unavailable |  |  |
| win | 11752 | 1608 | ShellExperienceHost.exe | Windows Shell Experience Host | Authenticode Valid |  | C:\WINDOWS\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe |
| win | 11836 | 4168 | FMToastNotification.exe | Expected Fortemedia audio processing/control component; local product metadata where available | Authenticode Valid |  | C:\WINDOWS\system32\FMToastNotification.exe |
| win | 11880 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: LicenseManager (Windows License Manager Service) | C:\WINDOWS\System32\svchost.exe |
| win | 11908 | 6188 | SNAPOS64.exe | Sonitude Audio Processing Object service; locally signed Sonitude binary/product | Authenticode Valid |  | C:\WINDOWS\System32\DriverStore\FileRepository\snapo64.inf_amd64_fd4aaa60454ea9da\SNAPOS64.exe |
| win | 12120 | 3460 | ollama.exe | Ollama local model application/server; locally signed readable binaries | Authenticode Valid |  | C:\Users\chris\AppData\Local\Programs\Ollama\ollama.exe |
| win | 12196 | 4168 | ProtonDrive.exe | Proton Drive | Authenticode Valid |  | C:\Users\chris\AppData\Local\Programs\Proton\Drive\ProtonDrive.exe |
| win | 12212 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid | Services: WpnUserService_41338e4 (Windows Push Notifications User Service_41338e4) | C:\WINDOWS\system32\svchost.exe |
| win | 12396 | 13740 | firefox.exe | Firefox | Authenticode Valid |  | C:\Program Files\Mozilla Firefox\firefox.exe |
| win | 12744 | 13740 | firefox.exe | Firefox | Authenticode Valid |  | C:\Program Files\Mozilla Firefox\firefox.exe |
| win | 12752 | 13740 | firefox.exe | Firefox | Authenticode Valid |  | C:\Program Files\Mozilla Firefox\firefox.exe |
| win | 12792 | 17708 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 12812 | 1420 | vmcompute.exe | Hyper-V Host Compute Service | Authenticode Valid; file from service configuration, not a verified live image handle | Services: vmcompute (Hyper-V Host Compute Service) | C:\WINDOWS\system32\vmcompute.exe |
| win | 12912 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: DoSvc (Delivery Optimization) | C:\WINDOWS\System32\svchost.exe |
| win | 12960 | 2468 | conhost.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\WINDOWS\System32\conhost.exe |
| win | 13020 | 4384 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 13136 | 1608 | backgroundTaskHost.exe | Background Task Host | Authenticode Valid |  | C:\WINDOWS\system32\backgroundTaskHost.exe |
| win | 13144 | 1608 | RuntimeBroker.exe | Runtime Broker | Authenticode Valid |  | C:\Windows\System32\RuntimeBroker.exe |
| win | 13192 | 1420 | SecurityHealthService.exe | Windows Security Health Service | Authenticode Valid; file from service configuration, not a verified live image handle | Services: SecurityHealthService (Windows Security Service) | C:\WINDOWS\system32\SecurityHealthService.exe |
| win | 13216 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: bthserv (Bluetooth Support Service) | C:\WINDOWS\system32\svchost.exe |
| win | 13236 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: SstpSvc (Secure Socket Tunneling Protocol Service) | C:\WINDOWS\system32\svchost.exe |
| win | 13320 | 12792 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 13440 | 5492 | ctfmon.exe | Windows text input framework | Image identity unavailable |  |  |
| win | 13636 | 20312 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 13740 | 8096 | firefox.exe | Firefox | Authenticode Valid |  | C:\Program Files\Mozilla Firefox\firefox.exe |
| win | 13768 | 4924 | ProtonVPN.Client.exe | Proton VPN | Authenticode Valid |  | C:\Program Files\Proton\VPN\v5.1.8\ProtonVPN.Client.exe |
| win | 13808 | 20980 | wsl.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Program Files\WSL\wsl.exe |
| win | 13900 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: SSDPSRV (SSDP Discovery) | C:\WINDOWS\system32\svchost.exe |
| win | 13912 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: lfsvc (Geolocation Service) | C:\WINDOWS\system32\svchost.exe |
| win | 13964 | 19552 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 14072 | 1608 | RuntimeBroker.exe | Runtime Broker | Authenticode Valid |  | C:\Windows\System32\RuntimeBroker.exe |
| win | 14124 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: InstallService (Microsoft Store Install Service) | C:\WINDOWS\System32\svchost.exe |
| win | 14240 | 20312 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 14280 | 17952 | OpenConsole.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.11911.0_x64__8wekyb3d8bbwe\OpenConsole.exe |
| win | 14468 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid | Services: webthreatdefusersvc_41338e4 (Web Threat Defense User Service_41338e4) | C:\WINDOWS\system32\svchost.exe |
| win | 14548 | 19552 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 14576 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Image identity unavailable |  |  |
| win | 14612 | 8932 | ChatGPT Classic.exe | ChatGPT Classic | Authenticode NotSigned |  | C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2026.190.0_x64__2p2nqsd0c76g0\app\ChatGPT Classic.exe |
| win | 14664 | 1420 | SearchIndexer.exe | Microsoft Windows Search Indexer | Authenticode Valid; file from service configuration, not a verified live image handle | Services: WSearch (Windows Search) | C:\WINDOWS\system32\SearchIndexer.exe |
| win | 14732 | 20312 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 14800 | 20312 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 14912 | 1608 | RuntimeBroker.exe | Runtime Broker | Authenticode Valid |  | C:\Windows\System32\RuntimeBroker.exe |
| win | 15040 | 20312 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 15048 | 11908 | conhost.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\WINDOWS\system32\conhost.exe |
| win | 15052 | 8464 | conhost.exe | Windows console, pseudoterminal, or terminal host | Image identity unavailable |  |  |
| win | 15092 | 1608 | RuntimeBroker.exe | Runtime Broker | Authenticode Valid |  | C:\Windows\System32\RuntimeBroker.exe |
| win | 15164 | 13808 | wslhost.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Program Files\WSL\wslhost.exe |
| win | 15400 | 4168 | RtkAudUService64.exe | Realtek HD Audio Universal Service; local signed product metadata on readable instances | Authenticode Valid |  | C:\Windows\System32\DriverStore\FileRepository\realtekservice.inf_amd64_464be4340fa51d6a\RtkAudUService64.exe |
| win | 15728 | 4524 | ShellHost.exe | ShellHost | Authenticode Valid |  | C:\Windows\System32\ShellHost.exe |
| win | 15748 | 18700 | wslhost.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Program Files\WSL\wslhost.exe |
| win | 15868 | 1420 | ProtonVPNService.exe | Proton VPN | Authenticode Valid; file from service configuration, not a verified live image handle | Services: ProtonVPN Service (ProtonVPN Service) | C:\Program Files\Proton\VPN\v5.1.8\ProtonVPNService.exe |
| win | 15924 | 1420 | NisSrv.exe | Microsoft Network Realtime Inspection Service | Authenticode Valid; file from service configuration, not a verified live image handle | Services: WdNisSvc (Microsoft Defender Antivirus Network Inspection Service) | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\NisSrv.exe |
| win | 16060 | 16904 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 16144 | 1420 | HPAudioAnalytics.exe | HP Hotkey UWP Service | Authenticode Valid; file from service configuration, not a verified live image handle | Services: HPAudioAnalytics (HP Audio Analytics Service) | C:\WINDOWS\System32\DriverStore\FileRepository\hpqkbsoftwarecompnent.inf_amd64_0d182501a33019e2\HPAudioAnalytics.exe |
| win | 16220 | 17952 | wsl.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Windows\system32\wsl.exe |
| win | 16288 | 17952 | OpenConsole.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.11911.0_x64__8wekyb3d8bbwe\OpenConsole.exe |
| win | 16316 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: InventorySvc (Inventory and Compatibility Appraisal service) | C:\WINDOWS\system32\svchost.exe |
| win | 16420 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: whesvc (Windows Health and Optimized Experiences) | C:\WINDOWS\system32\svchost.exe |
| win | 16532 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid | Services: UdkUserSvc_41338e4 (Udk User Service_41338e4) | C:\WINDOWS\system32\svchost.exe |
| win | 16596 | 19552 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 16616 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: UsoSvc (Update Orchestrator Service) | C:\WINDOWS\system32\svchost.exe |
| win | 16744 | 4384 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 16752 | 13740 | firefox.exe | Firefox | Authenticode Valid |  | C:\Program Files\Mozilla Firefox\firefox.exe |
| win | 16904 | 2940 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 17024 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: wscsvc (Security Center) | C:\WINDOWS\System32\svchost.exe |
| win | 17404 | 13740 | firefox.exe | Firefox | Authenticode Valid |  | C:\Program Files\Mozilla Firefox\firefox.exe |
| win | 17576 | 6020 | wslrelay.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Program Files\WSL\wslrelay.exe |
| win | 17616 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: BITS (Background Intelligent Transfer Service) | C:\WINDOWS\System32\svchost.exe |
| win | 17628 | 8932 | ChatGPT Classic.exe | ChatGPT Classic | Authenticode NotSigned |  | C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2026.190.0_x64__2p2nqsd0c76g0\app\ChatGPT Classic.exe |
| win | 17708 | 1608 | WidgetBoard.exe | Microsoft® Windows® Operating System | Authenticode Valid |  | C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience_526.21100.40.0_x64__cw5n1h2txyewy\WidgetBoard.exe |
| win | 17736 | 8932 | ChatGPT Classic.exe | ChatGPT Classic | Authenticode NotSigned |  | C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2026.190.0_x64__2p2nqsd0c76g0\app\ChatGPT Classic.exe |
| win | 17812 | 4728 | conhost.exe | Windows console, pseudoterminal, or terminal host | Image identity unavailable |  | C:\WINDOWS\system32\conhost.exe |
| win | 17952 | 4168 | WindowsTerminal.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.11911.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe |
| win | 18092 | 4168 | RiotClientServices.exe | Riot Client | Authenticode Valid |  | C:\Riot Games\Riot Client\RiotClientServices.exe |
| win | 18140 | 19552 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 18352 | 16904 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 18384 | 16904 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 18424 | 2468 | taskhostw.exe | Host Process for Windows Tasks | Authenticode Valid |  | C:\WINDOWS\system32\taskhostw.exe |
| win | 18440 | 11548 | wsl.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Program Files\WSL\wsl.exe |
| win | 18492 | 1608 | MicrosoftStartFeedProvider.exe | Microsoft\MicrosoftStartFeedProvider | Authenticode NotSigned |  | C:\Program Files\WindowsApps\Microsoft.StartExperiencesApp_1.380.2.0_x64__8wekyb3d8bbwe\MicrosoftStartFeedProvider\MicrosoftStartFeedProvider.exe |
| win | 18532 | 15868 | ProtonVPN.NrptWatchdog.exe | Expected Proton VPN DNS-policy watchdog; name-based role, this image path unreadable | Image identity unavailable |  |  |
| win | 18700 | 5880 | wsl.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Program Files\WSL\wsl.exe |
| win | 18956 | 19140 | conhost.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\WINDOWS\system32\conhost.exe |
| win | 19140 | 7412 | wslhost.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Program Files\WSL\wslhost.exe |
| win | 19144 | 6080 | powershell.exe | PowerShell interpreter; script purpose not inferred from its name | Authenticode Valid |  | C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe |
| win | 19168 | 1608 | RuntimeBroker.exe | Runtime Broker | Authenticode Valid |  | C:\Windows\System32\RuntimeBroker.exe |
| win | 19180 | 12792 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 19196 | 10028 | vmmemWSL | Windows kernel, isolation, registry, memory, or VM component; name-based role, no ordinary image identity established | Image identity unavailable |  |  |
| win | 19204 | 8932 | ChatGPT Classic.exe | ChatGPT Classic | Authenticode NotSigned |  | C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2026.190.0_x64__2p2nqsd0c76g0\app\ChatGPT Classic.exe |
| win | 19240 | 12960 | powershell.exe | PowerShell interpreter; script purpose not inferred from its name | Authenticode Valid |  | C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe |
| win | 19320 | 10196 | conhost.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\WINDOWS\system32\conhost.exe |
| win | 19336 | 4384 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 19452 | 17952 | powershell.exe | PowerShell interpreter; script purpose not inferred from its name | Authenticode Valid |  | C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe |
| win | 19552 | 8548 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 19992 | 9964 | fontdrvhost.exe | Windows user-mode font driver host | Image identity unavailable |  |  |
| win | 20008 | 1608 | SystemSettings.exe | Settings | Authenticode Valid |  | C:\Windows\ImmersiveControlPanel\SystemSettings.exe |
| win | 20116 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: wuauserv (Windows Update) | C:\WINDOWS\system32\svchost.exe |
| win | 20312 | 4816 | msedgewebview2.exe | Microsoft Edge WebView2 | Authenticode Valid |  | C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe |
| win | 20316 | 13740 | firefox.exe | Firefox | Authenticode Valid |  | C:\Program Files\Mozilla Firefox\firefox.exe |
| win | 20456 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid; file from service configuration, not a verified live image handle | Services: RasMan (Remote Access Connection Manager) | C:\WINDOWS\System32\svchost.exe |
| win | 20920 | 15164 | conhost.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\WINDOWS\system32\conhost.exe |
| win | 20980 | 17952 | wsl.exe | Windows Subsystem for Linux launch, hosting, relay, or service component | Authenticode Valid |  | C:\Windows\system32\wsl.exe |
| win | 21128 | 1420 | svchost.exe | Windows service host; per-PID service names listed below | Authenticode Valid | Services: DevicesFlowUserSvc_41338e4 (DevicesFlow_41338e4) | C:\WINDOWS\system32\svchost.exe |
| win | 21188 | 1608 | ApplicationFrameHost.exe | Application Frame Host | Authenticode Valid |  | C:\WINDOWS\system32\ApplicationFrameHost.exe |
| win | 22060 | 5320 | powershell.exe | PowerShell interpreter; script purpose not inferred from its name | Image identity unavailable |  | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| win | 22200 | 1608 | TiWorker.exe | Windows component servicing / module installer | Image identity unavailable |  |  |
| win | 22220 | 1608 | WmiPrvSE.exe | Windows WMI callback/provider host | Image identity unavailable |  |  |
| win | 22308 | 17952 | OpenConsole.exe | Windows console, pseudoterminal, or terminal host | Authenticode Valid |  | C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.11911.0_x64__8wekyb3d8bbwe\OpenConsole.exe |
| wsl | 1 |  | systemd | Linux system/session service manager | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 2 | 1 | init-systemd(Ub | WSL initialization/session infrastructure; name-based role | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 6 | 2 | init | WSL initialization/session infrastructure; name-based role | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 46 | 1 | systemd-journal | Linux journal logging daemon | Image unreadable/unavailable to audit token | 0::/system.slice/systemd-journald.service |  |
| wsl | 94 | 1 | systemd-udevd | Linux device manager or its worker | Image unreadable/unavailable to audit token | 0::/system.slice/systemd-udevd.service/udev |  |
| wsl | 104 | 1 | snapfuse | Snap package management or filesystem mount | Image unreadable/unavailable to audit token | 0::/system.slice/snap-core24-1643.mount |  |
| wsl | 105 | 1 | snapfuse | Snap package management or filesystem mount | Image unreadable/unavailable to audit token | 0::/system.slice/snap-core24-2124.mount |  |
| wsl | 118 | 1 | snapfuse | Snap package management or filesystem mount | Image unreadable/unavailable to audit token | 0::/system.slice/snap-snapd-27710.mount |  |
| wsl | 123 | 1 | snapfuse | Snap package management or filesystem mount | Image unreadable/unavailable to audit token | 0::/system.slice/snap-snapd-27738.mount |  |
| wsl | 129 | 1 | snapfuse | Snap package management or filesystem mount | Image unreadable/unavailable to audit token | 0::/system.slice/snap-terraform-938.mount |  |
| wsl | 132 | 1 | snapfuse | Snap package management or filesystem mount | Image unreadable/unavailable to audit token | 0::/system.slice/snap-terraform-943.mount |  |
| wsl | 218 | 1 | systemd-resolve | Linux DNS resolver service | Image unreadable/unavailable to audit token | 0::/system.slice/systemd-resolved.service |  |
| wsl | 219 | 1 | systemd-timesyn | Linux network time synchronization service | Image unreadable/unavailable to audit token | 0::/system.slice/systemd-timesyncd.service |  |
| wsl | 226 | 1 | python3 | JARVIS live daemon; systemd service PID 226 and jarvis.service cgroup | Image unreadable/unavailable to audit token | 0::/system.slice/jarvis.service |  |
| wsl | 227 | 1 | cron | Linux scheduled-job daemon | Image unreadable/unavailable to audit token | 0::/system.slice/cron.service |  |
| wsl | 229 | 1 | dbus-daemon | Linux interprocess message bus | Image unreadable/unavailable to audit token | 0::/system.slice/dbus.service |  |
| wsl | 240 | 1 | snapd | Snap package management or filesystem mount | Image unreadable/unavailable to audit token | 0::/system.slice/snapd.service |  |
| wsl | 241 | 1 | systemd-logind | Linux login/session management | Image unreadable/unavailable to audit token | 0::/system.slice/systemd-logind.service |  |
| wsl | 260 | 1 | rsyslogd | Linux system-log service | Image unreadable/unavailable to audit token | 0::/system.slice/rsyslog.service |  |
| wsl | 273 | 1 | agetty | Linux terminal login service | Image unreadable/unavailable to audit token | 0::/system.slice/system-getty.slice/getty@tty1.service |  |
| wsl | 282 | 1 | containerd | Docker/container runtime daemon or per-container shim | Image unreadable/unavailable to audit token | 0::/system.slice/containerd.service |  |
| wsl | 293 | 1 | unattended-upgr | Ubuntu unattended package upgrade helper | Image unreadable/unavailable to audit token | 0::/system.slice/unattended-upgrades.service |  |
| wsl | 296 | 1 | systemd | Linux system/session service manager | Image unreadable/unavailable to audit token | 0::/user.slice/user-1000.slice/user@1000.service/init.scope |  |
| wsl | 317 | 296 | (sd-pam) | systemd PAM session helper | Image unreadable/unavailable to audit token | 0::/user.slice/user-1000.slice/user@1000.service/init.scope |  |
| wsl | 346 | 1 | dockerd | Docker/container runtime daemon or per-container shim | Image unreadable/unavailable to audit token | 0::/system.slice/docker.service |  |
| wsl | 448 | 1 | sysmon | Microsoft Sysmon for Linux system-activity sensor; image unreadable from this audit token | Image unreadable/unavailable to audit token | 0::/system.slice/sysmon.service |  |
| wsl | 594 | 2 | SessionLeader | WSL initialization/session infrastructure; name-based role | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 595 | 594 | Relay(601) | WSL interop relay/session infrastructure; name-based role | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 597 | 2 | login | Linux terminal login service | Image unreadable/unavailable to audit token | 0::/user.slice/user-1000.slice/session-2.scope |  |
| wsl | 601 | 595 | bash | Shell interpreter; precise workload not inferred from name | Local path observed; binary not authenticated | 0::/init.scope | /usr/bin/bash |
| wsl | 799 | 597 | bash | Shell interpreter; precise workload not inferred from name | Local path observed; binary not authenticated | 0::/user.slice/user-1000.slice/session-2.scope | /usr/bin/bash |
| wsl | 1167 | 1 | containerd-shim | Docker/container runtime daemon or per-container shim | Image unreadable/unavailable to audit token | 0::/system.slice/containerd.service |  |
| wsl | 1192 | 1 | containerd-shim | Docker/container runtime daemon or per-container shim | Image unreadable/unavailable to audit token | 0::/system.slice/containerd.service |  |
| wsl | 1225 | 1167 | nats-server | NATS messaging server; Docker cgroup identifies messaging container | Image unreadable/unavailable to audit token | Container: aios-nats-1; image nats:2.10-alpine |  |
| wsl | 1228 | 1 | containerd-shim | Docker/container runtime daemon or per-container shim | Image unreadable/unavailable to audit token | 0::/system.slice/containerd.service |  |
| wsl | 1238 | 1192 | haproxy | HAProxy traffic proxy; Docker cgroup identifies proxy container | Image unreadable/unavailable to audit token | Container: aios-haproxy-1; image haproxytech/haproxy-alpine:3.0 |  |
| wsl | 1262 | 1228 | dragonfly | Redis/Memcached-compatible in-memory datastore; Docker cgroup identifies cache container | Image unreadable/unavailable to audit token | Container: aios-dragonfly-1; image docker.dragonflydb.io/dragonflydb/dragonfly:v1.24.0 |  |
| wsl | 1349 | 1 | containerd-shim | Docker/container runtime daemon or per-container shim | Image unreadable/unavailable to audit token | 0::/system.slice/containerd.service |  |
| wsl | 1365 | 1 | containerd-shim | Docker/container runtime daemon or per-container shim | Image unreadable/unavailable to audit token | 0::/system.slice/containerd.service |  |
| wsl | 1408 | 1 | containerd-shim | Docker/container runtime daemon or per-container shim | Image unreadable/unavailable to audit token | 0::/system.slice/containerd.service |  |
| wsl | 1498 | 1365 | uvicorn | Python ASGI application server; Docker cgroup identifies engine container | Image unreadable/unavailable to audit token | Container: aios-engine-1; image ghcr.io/angel-intelligence-os/engine:latest |  |
| wsl | 1503 | 1349 | cloudflared | Cloudflare Tunnel connector; Docker cgroup identifies tunnel container | Image unreadable/unavailable to audit token | Container: aios-cloudflared-1; image cloudflare/cloudflared:2024.10.0 |  |
| wsl | 1529 | 1408 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 1715 | 1238 | haproxy | HAProxy traffic proxy; Docker cgroup identifies proxy container | Image unreadable/unavailable to audit token | Container: aios-haproxy-1; image haproxytech/haproxy-alpine:3.0 |  |
| wsl | 1873 | 1 | containerd-shim | Docker/container runtime daemon or per-container shim | Image unreadable/unavailable to audit token | 0::/system.slice/containerd.service |  |
| wsl | 1896 | 1873 | api | Application API process; identified by Docker cgroup/container, not executable name alone | Image unreadable/unavailable to audit token | Container: aios-core-2; image ghcr.io/angel-intelligence-os/core:latest |  |
| wsl | 1915 | 1 | containerd-shim | Docker/container runtime daemon or per-container shim | Image unreadable/unavailable to audit token | 0::/system.slice/containerd.service |  |
| wsl | 1930 | 1 | containerd-shim | Docker/container runtime daemon or per-container shim | Image unreadable/unavailable to audit token | 0::/system.slice/containerd.service |  |
| wsl | 1963 | 1915 | api | Application API process; identified by Docker cgroup/container, not executable name alone | Image unreadable/unavailable to audit token | Container: aios-core-3; image ghcr.io/angel-intelligence-os/core:latest |  |
| wsl | 1976 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 1979 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 1980 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 1981 | 1930 | api | Application API process; identified by Docker cgroup/container, not executable name alone | Image unreadable/unavailable to audit token | Container: aios-core-1; image ghcr.io/angel-intelligence-os/core:latest |  |
| wsl | 1986 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 1988 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 2001 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 2002 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 2003 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 3331 | 2 | SessionLeader | WSL initialization/session infrastructure; name-based role | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 3332 | 3331 | Relay(3338) | WSL interop relay/session infrastructure; name-based role | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 3338 | 3332 | bash | Shell interpreter; precise workload not inferred from name | Local path observed; binary not authenticated | 0::/init.scope | /usr/bin/bash |
| wsl | 8304 | 3338 | claude | Claude CLI; local installed executable path observed | Local path observed; binary not authenticated | 0::/init.scope | /home/chris/.local/share/claude/versions/2.1.285 |
| wsl | 14922 | 2 | SessionLeader | WSL initialization/session infrastructure; name-based role | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 14923 | 14922 | Relay(14926) | WSL interop relay/session infrastructure; name-based role | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 14926 | 14923 | bash | Shell interpreter; precise workload not inferred from name | Local path observed; binary not authenticated | 0::/init.scope | /usr/bin/bash |
| wsl | 20206 | 14926 | claude | Claude CLI; local installed executable path observed | Local path observed; binary not authenticated | 0::/init.scope | /home/chris/.local/share/claude/versions/2.1.286 |
| wsl | 31591 | 14923 | npm exec serve@ | Node/npm serve launcher; name/path role, exact served application not collected | Local path observed; binary not authenticated | 0::/init.scope | /home/chris/.nvm/versions/node/v22.22.0/bin/node |
| wsl | 31752 | 296 | dbus-daemon | Linux interprocess message bus | Local path observed; binary not authenticated | 0::/user.slice/user-1000.slice/user@1000.service/session.slice/dbus.service | /usr/bin/dbus-daemon |
| wsl | 31790 | 296 | xdg-document-po | Desktop document/permission portal | Local path observed; binary not authenticated | 0::/user.slice/user-1000.slice/user@1000.service/session.slice/xdg-document-portal.service | /usr/libexec/xdg-document-portal |
| wsl | 31795 | 296 | xdg-permission- | Desktop document/permission portal | Local path observed; binary not authenticated | 0::/user.slice/user-1000.slice/user@1000.service/session.slice/xdg-permission-store.service | /usr/libexec/xdg-permission-store |
| wsl | 31804 | 31790 | fusermount3 | FUSE mount/unmount helper | Image unreadable/unavailable to audit token | 0::/user.slice/user-1000.slice/user@1000.service/session.slice/xdg-document-portal.service |  |
| wsl | 31923 | 31591 | sh | Shell interpreter; precise workload not inferred from name | Local path observed; binary not authenticated | 0::/init.scope | /usr/bin/dash |
| wsl | 31924 | 31923 | node | Node.js runtime; exact application purpose not inferred from runtime name | Local path observed; binary not authenticated | 0::/init.scope | /home/chris/.nvm/versions/node/v22.22.0/bin/node |
| wsl | 46652 | 2 | SessionLeader | WSL initialization/session infrastructure; name-based role | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 46653 | 46652 | Relay(46655) | WSL interop relay/session infrastructure; name-based role | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 46655 | 46653 | bash | Shell interpreter; precise workload not inferred from name | Local path observed; binary not authenticated | 0::/init.scope | /usr/bin/bash |
| wsl | 59135 | 46655 | claude | Claude CLI; local installed executable path observed | Local path observed; binary not authenticated | 0::/init.scope | /home/chris/.local/share/claude/versions/2.1.286 |
| wsl | 59516 | 2 | SessionLeader | WSL initialization/session infrastructure; name-based role | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 59517 | 59516 | Relay(59518) | WSL interop relay/session infrastructure; name-based role | Image unreadable/unavailable to audit token | 0::/init.scope |  |
| wsl | 59518 | 59517 | bash | Shell interpreter; precise workload not inferred from name | Local path observed; binary not authenticated | 0::/init.scope | /usr/bin/bash |
| wsl | 59892 | 59518 | node | Node.js runtime; exact application purpose not inferred from runtime name | Local path observed; binary not authenticated | 0::/init.scope | /home/chris/.nvm/versions/node/v22.22.0/bin/node |
| wsl | 59899 | 59892 | codex | Codex CLI/app-server/code execution helper; local executable path observed | Local path observed; binary not authenticated | 0::/init.scope | /home/chris/.nvm/versions/node/v22.22.0/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex |
| wsl | 59964 | 59899 | codex | Codex CLI/app-server/code execution helper; local executable path observed | Local path observed; binary not authenticated | 0::/init.scope | /home/chris/.codex/packages/app-server-daemon/releases/0.159.2-x86_64-unknown-linux-musl/bin/codex |
| wsl | 60067 | 59899 | codex | Codex CLI/app-server/code execution helper; local executable path observed | Local path observed; binary not authenticated | 0::/init.scope | /home/chris/.codex/packages/app-server-daemon/releases/0.159.2-x86_64-unknown-linux-musl/bin/codex |
| wsl | 62159 | 59899 | systemd-inhibit | systemd sleep/shutdown inhibition helper | Local path observed; binary not authenticated | 0::/init.scope | /usr/bin/systemd-inhibit |
| wsl | 62171 | 1 | polkitd | Linux authorization-policy service | Image unreadable/unavailable to audit token | 0::/system.slice/polkit.service |  |
| wsl | 62237 | 62159 | sleep | Timer/wait helper; precise workload not inferred from name | Local path observed; binary not authenticated | 0::/init.scope | /usr/bin/sleep |
| wsl | 62422 | 59964 | codex-code-mode | Codex CLI/app-server/code execution helper; local executable path observed | Local path observed; binary not authenticated | 0::/init.scope | /home/chris/.codex/packages/app-server-daemon/releases/0.159.2-x86_64-unknown-linux-musl/bin/codex-code-mode-host |
| wsl | 63205 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 63206 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 63207 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 63208 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 63209 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 63210 | 1529 | postgres | PostgreSQL database process; Docker cgroup identifies database container | Image unreadable/unavailable to audit token | Container: aios-postgres-1; image pgvector/pgvector:pg18 |  |
| wsl | 63672 | 94 | (udev-worker) | Linux device manager or its worker | Image unreadable/unavailable to audit token |  |  |
| wsl | 63675 | 94 | (udev-worker) | Linux device manager or its worker | Image unreadable/unavailable to audit token |  |  |
| wsl | 63713 | 94 | (udev-worker) | Linux device manager or its worker | Image unreadable/unavailable to audit token |  |  |
| wsl | 63714 | 94 | (udev-worker) | Linux device manager or its worker | Image unreadable/unavailable to audit token |  |  |
| wsl | 63764 | 94 | (udev-worker) | Linux device manager or its worker | Image unreadable/unavailable to audit token |  |  |
| wsl | 63944 | 94 | (udev-worker) | Linux device manager or its worker | Image unreadable/unavailable to audit token |  |  |
| wsl | 64093 | 226 | powershell.exe | PowerShell interpreter; script purpose not inferred from its name | Local path observed; binary not authenticated |  | /init |
| wsl | 64103 | 601 | sleep | Timer/wait helper; precise workload not inferred from name | Local path observed; binary not authenticated |  | /usr/bin/sleep |

## Artifacts and scope

Raw local metadata and health receipts are in the adjacent process-audit-2026-10-01 directory, mode 0700; each artifact is mode 0600. annotated-inventory.csv and annotated-inventory.json contain the full annotated rows. inventory.json retains the first snapshot unchanged. No service restart, deployment, security policy change, process termination, or product implementation change was performed. This was a read-only runtime investigation; Jev and regression tests were not needed for product changes because none were made.
