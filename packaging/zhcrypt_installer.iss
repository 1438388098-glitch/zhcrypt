; zhcrypt Windows 安装包脚本
; 用 Inno Setup 6 编译: ISCC.exe zhcrypt_installer.iss
; 产物: dist_installer\zhcrypt-setup.exe

[Setup]
AppId={{zhcrypt-9F2A1C4D-7B3E-4D6A-8C5F-1A2B3C4D5E6F}
AppName=zhcrypt
AppVersion=1.0
AppPublisher=zhcrypt
AppComments=中文加密通信系统 (Argon2id + AES-256-GCM + RSA-4096 + X3DH)
DefaultDirName={autopf}\zhcrypt
DefaultGroupName=zhcrypt
; 安装到 Program Files 需要管理员权限 (标准安装包行为)
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=C:\Users\20579\zhcrypt\dist_installer
OutputBaseFilename=zhcrypt-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; 卸载时清理安装目录 (用户数据在 %USERPROFILE%\zhcrypt, 不在此列)
UninstallFilesDir={autopf}\zhcrypt\uninstall

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; GUI 客户端 (Tkinter, 无控制台)
Source: "C:\Users\20579\zhcrypt\dist\zhcrypt-gui\*"; DestDir: "{app}\gui"; Flags: ignoreversion recursesubdirs createallsubdirs
; CLI 工具 (控制台)
Source: "C:\Users\20579\zhcrypt\dist\zhcrypt\*"; DestDir: "{app}\cli"; Flags: ignoreversion recursesubdirs createallsubdirs
; 使用说明
Source: "C:\Users\20579\zhcrypt\manual.md"; DestDir: "{app}"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "快捷方式:"

[Icons]
Name: "{group}\zhcrypt GUI"; Filename: "{app}\gui\zhcrypt-gui.exe"; WorkingDir: "{app}\gui"
Name: "{group}\zhcrypt 使用说明"; Filename: "{app}\manual.md"
Name: "{group}\卸载 zhcrypt"; Filename: "{uninstallexe}"
Name: "{autodesktop}\zhcrypt GUI"; Filename: "{app}\gui\zhcrypt-gui.exe"; WorkingDir: "{app}\gui"; Tasks: desktopicon
