param(
    [Parameter(ValueFromRemainingArguments=$true)][string[]]$CommandArgs
)

$ZHCRYPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PYTHONIOENCODING = "utf-8"

# Prefer buildenv Python 3.13 (Textual needs 3.8+; system Anaconda 3.6 not supported)
$BuildPy = Join-Path $ZHCRYPT_DIR "packaging\buildenv\Scripts\python.exe"
if (Test-Path $BuildPy) {
    $Python = $BuildPy
} else {
    $Python = "python"
}

# gui shortcut (positional, matches bat behaviour)
if ($CommandArgs.Count -eq 1 -and $CommandArgs[0] -ieq "gui") {
    & $Python "$ZHCRYPT_DIR\gui.py"
    exit $LASTEXITCODE
}

if ($CommandArgs.Count -eq 0) {
    & $Python "$ZHCRYPT_DIR\cli.py"
} else {
    & $Python "$ZHCRYPT_DIR\cli.py" @CommandArgs
}
exit $LASTEXITCODE
