# zhcrypt 3.1.0 build script (ASCII-only comments for PS 5.1 ANSI parsing)
# Usage: powershell -ExecutionPolicy Bypass -File packaging\build.ps1
# Output: packaging\dist\zhcrypt\  (single runtime dir, GUI + CLI entries)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$Root = Split-Path -Parent $PSScriptRoot
$BuildEnv = Join-Path $PSScriptRoot "buildenv"
$Python = Join-Path $BuildEnv "Scripts\python.exe"
$Dist = Join-Path $PSScriptRoot "dist"
$Final = Join-Path $Dist "zhcrypt"

if (-not (Test-Path $Python)) {
    Write-Host "Build env missing: run py -3.13 -m venv packaging\buildenv first"
    exit 1
}

# 1. cleanup
Remove-Item -Recurse -Force (Join-Path $PSScriptRoot "build"), $Dist -ErrorAction SilentlyContinue

# 2. GUI build
& $Python -m PyInstaller --noconfirm --clean --distpath $Dist --workpath (Join-Path $PSScriptRoot "build\gui") (Join-Path $PSScriptRoot "zhcrypt-gui.spec")
if ($LASTEXITCODE -ne 0) { throw "GUI build failed" }

# 3. CLI build
& $Python -m PyInstaller --noconfirm --clean --distpath $Dist --workpath (Join-Path $PSScriptRoot "build\cli") (Join-Path $PSScriptRoot "zhcrypt-cli.spec")
if ($LASTEXITCODE -ne 0) { throw "CLI build failed" }

# 4. merge into single runtime (GUI base + CLI extras)
Remove-Item -Recurse -Force $Final -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $Final | Out-Null

$GuiDist = Join-Path $Dist "zhcrypt_gui"
$CliDist = Join-Path $Dist "zhcrypt_cli"

# 4a. copy GUI dist contents
Copy-Item -Recurse -Force (Join-Path $GuiDist "*") $Final

# 4b. CLI exe -> zhcrypt.exe
Copy-Item (Join-Path $CliDist "zhcrypt.exe") (Join-Path $Final "zhcrypt.exe") -Force

# 4c. merge _internal (add CLI-only files)
$InternalFinal = Join-Path $Final "_internal"
foreach ($file in Get-ChildItem (Join-Path $CliDist "_internal") -File) {
    $target = Join-Path $InternalFinal $file.Name
    if (-not (Test-Path $target)) {
        Copy-Item $file.FullName $target -Force
    } elseif ((Get-FileHash $file.FullName).Hash -ne (Get-FileHash $target).Hash) {
        Copy-Item $file.FullName $target -Force
    }
}
foreach ($dir in Get-ChildItem (Join-Path $CliDist "_internal") -Directory) {
    $dest = Join-Path $Final "_internal"
    if (-not (Test-Path (Join-Path $dest $dir.Name))) {
        Copy-Item -Recurse -Force $dir.FullName $dest
    }
}

# 5. remove per-app build dirs
Remove-Item -Recurse -Force $GuiDist, $CliDist -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $PSScriptRoot "build") -ErrorAction SilentlyContinue

# 6. UCRT slimming (ZC-22/23): Win10 1709+ ships UCRT in system,
#    delete api-ms-* forwarding dlls and bundled ucrtbase (keep VCRUNTIME140)
Get-ChildItem $InternalFinal -Filter "api-ms-win-*.dll" -ErrorAction SilentlyContinue | Remove-Item -Force
Remove-Item (Join-Path $InternalFinal "ucrtbase.dll") -Force -ErrorAction SilentlyContinue

# 7. SHA256 manifest (supply-chain integrity until code signing cert available)
$Manifest = Join-Path $Final "SHA256SUMS.txt"
Get-ChildItem -Recurse -File $Final | Where-Object { $_.Name -ne "SHA256SUMS.txt" } |
    ForEach-Object {
        $rel = $_.FullName.Substring($Final.Length + 1)
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
        "$hash  $rel"
    } | Sort-Object | Set-Content $Manifest -Encoding ascii

# 8. summary
$sizeMB = [math]::Round(((Get-ChildItem -Recurse -File $Final | Measure-Object Length -Sum).Sum / 1MB), 2)
Write-Host "Build OK: $Final  ($sizeMB MB)"
