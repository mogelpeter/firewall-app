; Inno Setup script. Build: ISCC /DAppVersion=3.0.0 installer\FirewallManager.iss  (after cargo build --release)
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6C1F6B0E-4B8A-4C55-9E52-5F1A7D3B2C90}
AppName=Firewall Manager
AppVersion={#AppVersion}
AppPublisher=mogelpeter
AppPublisherURL=https://github.com/mogelpeter/firewall-app
DefaultDirName={autopf}\FirewallManager
DefaultGroupName=Firewall Manager
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
Compression=lzma2
SolidCompression=yes
OutputDir=..\target\installer
OutputBaseFilename=FirewallManager-Setup
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\FirewallManager.exe
CloseApplications=yes
RestartApplications=no
WizardStyle=modern

[Files]
Source: "..\target\release\firewall-manager.exe"; DestDir: "{app}"; DestName: "FirewallManager.exe"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Firewall Manager"; Filename: "{app}\FirewallManager.exe"
Name: "{autodesktop}\Firewall Manager"; Filename: "{app}\FirewallManager.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; Flags: unchecked

[Run]
Filename: "{app}\FirewallManager.exe"; Description: "Start Firewall Manager"; Flags: nowait postinstall

; The blocked list (blocked.txt / blocked.bak) lives in the install folder but is not part of the
; install, so uninstalling or updating keeps it. The update downloads are removed.
[UninstallDelete]
Type: filesandordirs; Name: "{app}\update"
