@echo off
set PYTHONIOENCODING=utf-8
if /i "%1"=="gui" (
    python "%~dp0gui.py"
) else if "%1"=="" (
    python "%~dp0cli.py"
) else (
    python "%~dp0cli.py" %*
)
