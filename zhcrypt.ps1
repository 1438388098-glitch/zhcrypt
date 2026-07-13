param(
    [switch]$Gui,
    [switch]$Help
)

$ZHCRYPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Help) {
    & python "$ZHCRYPT_DIR\cli.py" "--help"
    return
}

if ($Gui) {
    & python "$ZHCRYPT_DIR\gui.py"
    return
}

if ($args.Count -eq 0) {
    & python "$ZHCRYPT_DIR\cli.py"
} else {
    & python "$ZHCRYPT_DIR\cli.py" @args
}
