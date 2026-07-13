param([string]$Dir = "$Home\Desktop\zhcrypt", [switch]$NoShortcut)

$ErrorActionPreference = "Stop"

function title($t) { Write-Host "==> $t" -Foreground Cyan }
function step($s) { Write-Host "  -> $s" -Foreground Yellow }
function ok($s) { Write-Host "  [OK] $s" -Foreground Green }
function fail($s) { Write-Host "  [FAIL] $s" -Foreground Red; exit 1 }

title "zhcrypt One-Click Setup"

# 1. clone
step "Cloning repository..."
if (-not (Test-Path "$Dir\cli.py")) {
    if (Test-Path $Dir) { Remove-Item -Recurse -Force $Dir }
    git clone https://github.com/1438388098-glitch/zhcrypt.git $Dir 2>$null
    if (-not (Test-Path "$Dir\cli.py")) { fail "git clone failed - is git installed?" }
    ok "repository cloned to $Dir"
} else {
    ok "repository already exists"
}

Set-Location $Dir

# 2. deps
step "Installing dependencies..."
if (!(Get-Command pip -ErrorAction SilentlyContinue)) { fail "pip not found - install Python first" }
pip install -r requirements.txt -q 2>$null
pip install websocket-client -q 2>$null
ok "dependencies installed"

# 3. PATH
step "Adding to PATH (restart terminal after)..."
$current = [Environment]::GetEnvironmentVariable("Path", "User")
if ($current -split ";" -notcontains $Dir) {
    [Environment]::SetEnvironmentVariable("Path", "$current;$Dir", "User")
    ok "added to PATH"
} else {
    ok "already in PATH"
}

# 4. desktop shortcuts
if (-not $NoShortcut) {
    step "Creating desktop shortcuts..."
    try {
        $ws = New-Object -ComObject WScript.Shell
        $bat = "$Dir\zhcrypt.bat"
        $gui = $ws.CreateShortcut("$Home\Desktop\zhcrypt-GUI.lnk")
        $gui.TargetPath = $bat
        $gui.Arguments = "gui"
        $gui.WorkingDirectory = $Dir
        $gui.Description = "zhcrypt GUI - double-click to launch"
        $gui.Save()
        ok "desktop: zhcrypt-GUI"
        $cli = $ws.CreateShortcut("$Home\Desktop\zhcrypt-CLI.lnk")
        $cli.TargetPath = "powershell.exe"
        $cli.Arguments = "-NoExit -Command Set-Location '$Dir'; python cli.py"
        $cli.WorkingDirectory = $Dir
        $cli.Description = "zhcrypt CLI - interactive terminal"
        $cli.Save()
        ok "desktop: zhcrypt-CLI"
    } catch {
        fail "shortcut creation failed: $_"
    }
}

title "Done!"
Write-Host ""
Write-Host "  zhcrypt-GUI   -> double-click to launch GUI" -Foreground Green
Write-Host "  zhcrypt-CLI   -> double-click to launch interactive shell" -Foreground Green
Write-Host "  zhcrypt       -> type in any terminal (after restart)" -Foreground Green
