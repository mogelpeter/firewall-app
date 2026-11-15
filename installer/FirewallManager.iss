; Inno Setup script. Build: ISCC /DAppVersion=3.1.0 installer\FirewallManager.iss  (after cargo build --release)
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

[Run]
Filename: "{app}\FirewallManager.exe"; Description: "Start Firewall Manager"; Flags: nowait postinstall

; The blocked list (blocked.txt / blocked.bak) lives in the install folder but is not part of the
; install, so uninstalling or updating keeps it. The update downloads and the desktop shortcut are removed.
[UninstallDelete]
Type: filesandordirs; Name: "{app}\update"
Type: files; Name: "{autodesktop}\Firewall Manager.lnk"

[Code]
{ After the files are installed, ask whether to put a shortcut on the desktop.
  Silent runs (the updater) never ask, and keep a shortcut that already exists. }
procedure CurStepChanged(CurStep: TSetupStep);
var
  Shell, Lnk: Variant;
begin
  if (CurStep = ssPostInstall) and (not WizardSilent) then
    if MsgBox('Firewall Manager is installed.' + #13#10#13#10 + 'Create a shortcut on the desktop?',
              mbConfirmation, MB_YESNO) = IDYES then
    begin
      Shell := CreateOleObject('WScript.Shell');
      Lnk := Shell.CreateShortcut(ExpandConstant('{autodesktop}\Firewall Manager.lnk'));
      Lnk.TargetPath := ExpandConstant('{app}\FirewallManager.exe');
      Lnk.WorkingDirectory := ExpandConstant('{app}');
      Lnk.IconLocation := ExpandConstant('{app}\FirewallManager.exe') + ',0';
      Lnk.Description := 'Firewall Manager';
      Lnk.Save;
    end;
end;
