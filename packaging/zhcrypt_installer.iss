; zhcrypt 3.1.0 installer (Inno Setup 6)
; Single runtime directory with GUI + CLI entries.
#define MyAppName "zhcrypt"
#define MyAppVersion "3.1.0"
#define MyAppExeName "zhcrypt-gui.exe"

[Setup]
AppId={{8F3C2A1B-4D2E-4F5A-9B3C-zhcrypt310}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=zhcrypt
DefaultDirName={autopf}\zhcrypt
DisableProgramGroupPage=yes
OutputDir=dist_installer
OutputBaseFilename=zhcrypt-setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
WizardStyle=modern

[Languages]
Name: "chinesesimp"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"

[Files]
Source: "dist\zhcrypt\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\zhcrypt GUI"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\zhcrypt GUI"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "启动 zhcrypt GUI"; Flags: nowait postinstall skipifsilent
