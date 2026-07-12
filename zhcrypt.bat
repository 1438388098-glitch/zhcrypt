@echo off
set PYTHONIOENCODING=utf-8
if "%1"=="gui" (
    python "%~dp0gui.py"
) else (
    python "%~dp0cli.py" %*
)
