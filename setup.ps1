param(
    [string]$Dir = "$Home\Desktop\zhcrypt",
    [switch]$NoShortcut
)

$ErrorActionPreference = "Stop"
$OldEncoding = [Console]::OutputEncoding
[Console]::OutputEncoding = [Text.Encoding]::UTF8

Write-Host "╔══════════════════════════════════════════╗" -Foreground Cyan
Write-Host "║     zhcrypt 一键安装                     ║" -Foreground Cyan
Write-Host "╚══════════════════════════════════════════╝" -Foreground Cyan
Write-Host ""

# ── 1. 克隆 ──
if (-not (Test-Path "$Dir\cli.py")) {
    Write-Host "▸ 克隆仓库..." -Foreground Yellow
    if (Test-Path $Dir) { Remove-Item -Recurse -Force $Dir }
    git clone https://github.com/1438388098-glitch/zhcrypt.git $Dir
} else {
    Write-Host "▸ 仓库已存在，跳过克隆" -Foreground Green
}

Set-Location $Dir

# ── 2. 依赖 ──
Write-Host "▸ 安装依赖..." -Foreground Yellow
pip install -r requirements.txt -q
pip install websocket-client -q
Write-Host "  ✓ 依赖安装完成" -Foreground Green

# ── 3. 添加到 PATH ──
Write-Host "▸ 添加到 PATH..." -Foreground Yellow
$current = [Environment]::GetEnvironmentVariable("Path", "User")
if ($current -split ";" -notcontains $Dir) {
    [Environment]::SetEnvironmentVariable("Path", "$current;$Dir", "User")
    Write-Host "  ✓ 已添加到 PATH（重启终端生效）" -Foreground Green
} else {
    Write-Host "  ✓ 已在 PATH 中" -Foreground Green
}

# ── 4. 桌面快捷方式 ──
if (-not $NoShortcut) {
    Write-Host "▸ 创建桌面快捷方式..." -Foreground Yellow
    $batPath = "$Dir\zhcrypt.bat"
    
    # GUI 快捷方式
    $ws = New-Object -ComObject WScript.Shell
    $shortcutPath = "$Home\Desktop\zhcrypt-GUI.lnk"
    $s = $ws.CreateShortcut($shortcutPath)
    $s.TargetPath = $batPath
    $s.Arguments = "gui"
    $s.WorkingDirectory = $Dir
    $s.Description = "zhcrypt 中文加密系统 - GUI"
    $s.Save()
    Write-Host "  ✓ 桌面快捷方式已创建: $shortcutPath" -Foreground Green
    
    # CLI 快捷方式（指向交互式终端，方便右键「以交互式终端打开」）
    $cliShortcut = "$Home\Desktop\zhcrypt-CLI.lnk"
    $s2 = $ws.CreateShortcut($cliShortcut)
    $s2.TargetPath = "powershell.exe"
    $s2.Arguments = "-NoExit -Command Set-Location '$Dir'; python cli.py"
    $s2.WorkingDirectory = $Dir
    $s2.Description = "zhcrypt 中文加密系统 - CLI 交互式终端"
    $s2.Save()
    Write-Host "  ✓ CLI 快捷方式已创建: $cliShortcut" -Foreground Green
}

Write-Host ""
Write-Host "╔══════════════════════════════════════════╗" -Foreground Cyan
Write-Host "║  安装完成！                               ║" -Foreground Cyan
Write-Host "║                                          ║" -Foreground Cyan
Write-Host "║  双击桌面 zhcrypt-GUI 启动图形界面         ║" -Foreground Cyan
Write-Host "║  双击桌面 zhcrypt-CLI 启动交互式终端       ║" -Foreground Cyan
Write-Host "║  或重启终端后直接输入: zhcrypt             ║" -Foreground Cyan
Write-Host "╚══════════════════════════════════════════╝" -Foreground Cyan

[Console]::OutputEncoding = $OldEncoding
