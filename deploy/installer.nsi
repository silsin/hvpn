; HVPN VPN Client NSIS installer script
; Requires NSIS 3.x — download from https://nsis.sourceforge.io/

!define APP_NAME "HVPN VPN Client"
!define APP_VERSION "0.1.0"
!define INSTALLER_NAME "hvpn-setup.exe"
!define INSTALL_DIR "$PROGRAMFILES64\HVPN"

Name "${APP_NAME}"
OutFile "dist\${INSTALLER_NAME}"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel admin
SetCompressor lzma

!include "MUI2.nsh"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install" SecInstall
  SetOutPath "$INSTDIR"

  ; Copy main binaries
  File "staging\hvpn-client.exe"
  File "staging\hvpn-tray.exe"
  File "staging\hvpn-ctl.exe"
  File "staging\wintun.dll"

  ; Create APPDATA config directory
  CreateDirectory "$APPDATA\HVPN"

  ; Copy default config if not already present
  IfFileExists "$APPDATA\HVPN\client.toml" skip_config
    File "/oname=$APPDATA\HVPN\client.toml" "staging\example-client.toml"
  skip_config:

  ; Register tray app for auto-start
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "HVPN" '"$INSTDIR\hvpn-tray.exe"'

  ; Install service
  ExecWait '"$INSTDIR\hvpn-client.exe" --install'

  ; Create Start Menu shortcut
  CreateDirectory "$SMPROGRAMS\HVPN"
  CreateShortcut "$SMPROGRAMS\HVPN\HVPN.lnk" "$INSTDIR\hvpn-tray.exe"
  CreateShortcut "$SMPROGRAMS\HVPN\Uninstall HVPN.lnk" "$INSTDIR\Uninstall.exe"

  ; Create Desktop shortcut
  CreateShortcut "$DESKTOP\HVPN.lnk" "$INSTDIR\hvpn-tray.exe"

  ; Write uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Write Add/Remove Programs entry
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\HVPN" \
    "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\HVPN" \
    "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\HVPN" \
    "DisplayVersion" "${APP_VERSION}"
SectionEnd

Section "Uninstall"
  ; Stop and remove service
  ExecWait '"$INSTDIR\hvpn-client.exe" --uninstall'

  ; Remove auto-start entry
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "HVPN"

  ; Remove Add/Remove Programs entry
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\HVPN"

  ; Delete files
  Delete "$INSTDIR\hvpn-client.exe"
  Delete "$INSTDIR\hvpn-tray.exe"
  Delete "$INSTDIR\hvpn-ctl.exe"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\Uninstall.exe"

  ; Delete shortcuts
  Delete "$SMPROGRAMS\HVPN\HVPN.lnk"
  Delete "$SMPROGRAMS\HVPN\Uninstall HVPN.lnk"
  RMDir "$SMPROGRAMS\HVPN"
  Delete "$DESKTOP\HVPN.lnk"

  ; Remove install directory
  RMDir "$INSTDIR"
SectionEnd
