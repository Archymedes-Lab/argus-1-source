; Argus-Setup.exe: one installer for Windows 10/11 x64.
;
; Contains the desktop app and the compiled monitoring program (argus.exe, no
; Python, no scripts). Installs for the signed-in user: no administrator
; prompt, no service, no firewall or Defender change. Everything below is done
; by this installer itself; nothing is delegated to a script that a release
; may not contain (release/policy.json denies .ps1).
;
;   Argus-Setup.exe        the installer window
;   Argus-Setup.exe /S     silent. The exit code is 0 only when monitoring was
;                          verified to answer after the install (see "verify").
;   Uninstall.exe /S       silent removal; add /PURGE to delete history too.
;
; Built by release/build_windows.py:
;   makensis -DVERSION=... -DPRODUCT_VERSION=a.b.c.d -DSRC=<staged folder>
;            -DOUTFILE=<exe> [-DICON=<ico>] Argus-Setup.nsi
;
; Layout under $LOCALAPPDATA\Programs\Argus: argus.exe (daemon and CLI, with
; its libraries), argus-desktop.exe (window, tray, notifications), Uninstall.exe.
; History and settings live in the user's profile (.argus) and are kept on
; upgrade and, unless asked, on uninstall.

Unicode true
; The standard NSIS release ships only 32-bit stubs, so this is a 32-bit
; installer that runs on 64-bit Windows. It installs 64-bit programs, and it
; turns off file-system redirection (below) so $SYSDIR is the real System32 and
; the 64-bit schtasks and taskkill run.
SetCompressor /SOLID lzma
SetDateSave off

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"

!insertmacro un.GetParameters
!insertmacro un.GetOptions

!define APP "Argus"
!define TASK "argus native service"
!define ARP "Software\Microsoft\Windows\CurrentVersion\Uninstall\Argus"
!define RUNKEY "Software\Microsoft\Windows\CurrentVersion\Run"
!define PORT 8787

Name "${APP}"
Caption "${APP} ${VERSION} Setup"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\Argus"
RequestExecutionLevel user
ShowInstDetails show
ShowUninstDetails show
BrandingText "${APP} ${VERSION}"

!ifdef ICON
  !define MUI_ICON "${ICON}"
  !define MUI_UNICON "${ICON}"
!endif
!define MUI_ABORTWARNING

!define MUI_WELCOMEPAGE_TITLE "Install ${APP} ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "${APP} watches what runs on this PC and tells you when something looks wrong. It runs on this PC only.$\r$\n$\r$\nThis installs the ${APP} window and its monitoring program for your account. It does not ask for administrator rights and changes no firewall or Windows Defender setting.$\r$\n$\r$\nSome checks need administrator access to read protected parts of Windows. Those are not installed here; ${APP} will say which areas it cannot watch and why."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TITLE "${APP} is installed"
!define MUI_FINISHPAGE_TEXT "${APP} starts when you sign in. Open it from the Start menu.$\r$\n$\r$\nIf the log lists problems, they are what still needs attention; nothing was hidden."
!define MUI_FINISHPAGE_RUN "$INSTDIR\argus-desktop.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Open ${APP} now"
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

VIProductVersion "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "${APP}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "${APP} Setup"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName" "Archymedes"
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalCopyright" "Archymedes"

Var Result
Var Previous

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP|MB_OK "Argus needs 64-bit Windows 10 or 11." /SD IDOK
    SetErrorLevel 5
    Abort
  ${EndIf}
  SetRegView 64
FunctionEnd

Function un.onInit
  SetRegView 64
FunctionEnd

; Stop every running part of Argus so its files can be replaced or removed:
; the logon task first (so it cannot restart the program), then the processes.
!macro StopArgus
  nsExec::Exec '"$SYSDIR\schtasks.exe" /End /TN "${TASK}"'
  Pop $Result
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /T /IM argus-desktop.exe'
  Pop $Result
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /T /IM argus.exe'
  Pop $Result
  Sleep 1500
!macroend

Section "Argus" SecMain
  ${DisableX64FSRedirection}
  ; Not inside the install folder: a process cannot rename or delete the
  ; directory it is standing in.
  SetOutPath "$TEMP"

  ; --- stop the running version; keep it until the new one is in place -------
  DetailPrint "stopping the running Argus"
  !insertmacro StopArgus
  StrCpy $Previous ""
  ${If} ${FileExists} "$INSTDIR\argus.exe"
    RMDir /r "$INSTDIR.previous"
    ClearErrors
    Rename "$INSTDIR" "$INSTDIR.previous"
    ${IfNot} ${Errors}
      StrCpy $Previous "$INSTDIR.previous"
    ${Else}
      DetailPrint "the old files are still in use; closing them did not work"
      MessageBox MB_ICONSTOP|MB_OK "Argus could not replace its old files because something is still using them. Restart the computer and run this installer again." /SD IDOK
      SetErrorLevel 2
      Abort "files in use"
    ${EndIf}
  ${EndIf}
  CreateDirectory "$INSTDIR"
  SetOutPath "$INSTDIR"

  ; --- files ----------------------------------------------------------------
  DetailPrint "installing Argus ${VERSION}"
  ClearErrors
  File /r "${SRC}\*"
  ${If} ${Errors}
    Goto rollback
  ${EndIf}
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  FileOpen $0 "$INSTDIR\VERSION" w
  FileWrite $0 "${VERSION}$\r$\n"
  FileClose $0

  ; --- the monitoring program runs at every sign-in and is restarted if it stops
  ; One instance only (IgnoreNew); restarts on failure; no time limit; hidden.
  DetailPrint "registering the background task"
  InitPluginsDir
  ExpandEnvStrings $1 "%USERDOMAIN%\%USERNAME%"
  FileOpen $0 "$PLUGINSDIR\task.xml" w
  FileWriteUTF16LE /BOM $0 '<?xml version="1.0" encoding="UTF-16"?>$\r$\n'
  FileWriteUTF16LE $0 '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">$\r$\n'
  FileWriteUTF16LE $0 '<RegistrationInfo><Description>Argus monitoring program (${VERSION})</Description></RegistrationInfo>$\r$\n'
  FileWriteUTF16LE $0 '<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>$1</UserId></LogonTrigger></Triggers>$\r$\n'
  FileWriteUTF16LE $0 '<Principals><Principal id="Author"><UserId>$1</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>$\r$\n'
  FileWriteUTF16LE $0 '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
  FileWriteUTF16LE $0 '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><AllowHardTerminate>true</AllowHardTerminate>'
  FileWriteUTF16LE $0 '<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Hidden>true</Hidden><RestartOnFailure><Interval>PT1M</Interval><Count>5</Count></RestartOnFailure></Settings>$\r$\n'
  FileWriteUTF16LE $0 '<Actions Context="Author"><Exec><Command>$INSTDIR\argus.exe</Command><Arguments>serve --port ${PORT}</Arguments><WorkingDirectory>$INSTDIR</WorkingDirectory></Exec></Actions>$\r$\n'
  FileWriteUTF16LE $0 '</Task>$\r$\n'
  FileClose $0
  nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Create /F /TN "${TASK}" /XML "$PLUGINSDIR\task.xml"'
  Pop $Result
  ${If} $Result != "0"
    DetailPrint "could not register the background task ($Result)"
    Goto rollback
  ${EndIf}

  ; --- the app: Start menu, start at sign-in (tray), Settings > Apps entry ------
  CreateDirectory "$SMPROGRAMS\Argus"
  CreateShortcut "$SMPROGRAMS\Argus\Argus.lnk" "$INSTDIR\argus-desktop.exe" "" "$INSTDIR\argus-desktop.exe" 0
  CreateShortcut "$SMPROGRAMS\Argus\Uninstall Argus.lnk" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "${RUNKEY}" "Argus" '"$INSTDIR\argus-desktop.exe" --hidden'
  WriteRegStr HKCU "${ARP}" "DisplayName" "Argus"
  WriteRegStr HKCU "${ARP}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${ARP}" "Publisher" "Archymedes"
  WriteRegStr HKCU "${ARP}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${ARP}" "DisplayIcon" "$INSTDIR\argus-desktop.exe"
  WriteRegStr HKCU "${ARP}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKCU "${ARP}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKCU "${ARP}" "NoModify" 1
  WriteRegDWORD HKCU "${ARP}" "NoRepair" 1

  ; --- start monitoring, then verify that it really answers -------------------
  ; The app's own self-test: pairs this account with the program, asks it for
  ; its state, and exits 0 only when monitoring data comes back. A start that
  ; does not answer is reported, never assumed.
  DetailPrint "starting monitoring"
  nsExec::Exec '"$SYSDIR\schtasks.exe" /Run /TN "${TASK}"'
  Pop $Result
  DetailPrint "verifying that monitoring answers"
  nsExec::ExecToLog '"$INSTDIR\argus-desktop.exe" --check'
  Pop $Result
  ${If} $Result == "0"
    DetailPrint "verified: Argus is monitoring this PC"
    ; The old version is only removed once the new one has proven itself.
    ${If} $Previous != ""
      RMDir /r "$Previous"
    ${EndIf}
    Goto done
  ${EndIf}
  DetailPrint "Argus is installed but monitoring did not answer (check result $Result)."
  DetailPrint "  2 = this account could not be paired; 3 = the program did not start answering."
  ${If} $Previous != ""
    RMDir /r "$Previous"
  ${EndIf}
  ${IfNot} ${Silent}
    MessageBox MB_ICONEXCLAMATION|MB_OK "Argus is installed, but monitoring did not start answering. Details are in the install log (Show details). Restart your computer, then open Argus; it will say what is wrong if it still cannot start."
  ${EndIf}
  SetErrorLevel 3
  Goto done

rollback:
  DetailPrint "the install failed; restoring the previous version"
  SetOutPath "$TEMP"
  RMDir /r "$INSTDIR"
  ${If} $Previous != ""
    Rename "$Previous" "$INSTDIR"
    nsExec::Exec '"$SYSDIR\schtasks.exe" /Run /TN "${TASK}"'
    Pop $Result
  ${EndIf}
  ${IfNot} ${Silent}
    MessageBox MB_ICONSTOP|MB_OK "Argus did not install. The reason is in the log of this window (Show details). Your previous version, if you had one, was restored."
  ${EndIf}
  SetErrorLevel 1
  Abort "Argus was not installed"

done:
  SetOutPath "$TEMP"
SectionEnd

; --- uninstall ------------------------------------------------------------------
Var Purge

Section "Uninstall"
  ${DisableX64FSRedirection}
  SetOutPath "$TEMP"
  !insertmacro StopArgus
  nsExec::Exec '"$SYSDIR\schtasks.exe" /Delete /F /TN "${TASK}"'
  Pop $Result
  DeleteRegValue HKCU "${RUNKEY}" "Argus"
  DeleteRegKey HKCU "${ARP}"
  Delete "$SMPROGRAMS\Argus\Argus.lnk"
  Delete "$SMPROGRAMS\Argus\Uninstall Argus.lnk"
  RMDir "$SMPROGRAMS\Argus"
  ; The app's pairing token is useless without the program: remove it.
  RMDir /r "$APPDATA\local.argus.desktop"
  RMDir /r "$LOCALAPPDATA\local.argus.desktop"
  ; History and settings stay unless the person says otherwise.
  ${un.GetParameters} $0
  ClearErrors
  ${un.GetOptions} $0 "/PURGE" $1
  ${IfNot} ${Errors}
    StrCpy $Purge "1"
  ${Else}
    StrCpy $Purge "0"
    ${IfNot} ${Silent}
      MessageBox MB_YESNO|MB_ICONQUESTION "Also delete Argus's saved history and settings (in your user folder)?" IDNO keep
      StrCpy $Purge "1"
      keep:
    ${EndIf}
  ${EndIf}
  ${If} $Purge == "1"
    RMDir /r "$PROFILE\.argus"
  ${EndIf}
  ; The install folder last: this very program lives in it.
  Delete "$INSTDIR\Uninstall.exe"
  RMDir /r "$INSTDIR"
  RMDir /r "$INSTDIR.previous"
SectionEnd
