; zhcrypt Windows 安装包脚本
; 用 Inno Setup 6 编译: ISCC.exe zhcrypt_installer.iss
; 产物: ..\dist_installer\zhcrypt-setup.exe
; 注意: 从 packaging 目录上一级 (项目根目录) 编译

[Setup]
AppId={{zhcrypt-9F2A1C4D-7B3E-4D6A-8C5F-1A2B3C4D5E6F}
AppName=zhcrypt
AppVersion=3.0.0
AppPublisher=zhcrypt
AppComments=中文加密通信系统 (Argon2id + AES-256-GCM + RSA-4096 + X3DH)
DefaultDirName={autopf}\zhcrypt
DefaultGroupName=zhcrypt
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist_installer
OutputBaseFilename=zhcrypt-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallFilesDir={autopf}\zhcrypt\uninstall

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\dist\zhcrypt-gui\*"; DestDir: "{app}\gui"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\zhcrypt\*"; DestDir: "{app}\cli"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\manual.md"; DestDir: "{app}"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "快捷方式:"

[Icons]
Name: "{group}\zhcrypt GUI"; Filename: "{app}\gui\zhcrypt-gui.exe"; WorkingDir: "{app}\gui"
Name: "{group}\zhcrypt 使用说明"; Filename: "{app}\manual.md"
Name: "{group}\卸载 zhcrypt"; Filename: "{uninstallexe}"
Name: "{autodesktop}\zhcrypt GUI"; Filename: "{app}\gui\zhcrypt-gui.exe"; WorkingDir: "{app}\gui"; Tasks: desktopicon
