@echo off
setlocal
set PYTHONIOENCODING=utf-8

rem Prefer buildenv Python 3.13 (Textual needs 3.8+; system Python 3.6 not supported)
set "ZHCRYPT_BUILD_PY=%~dp0packaging\buildenv\Scripts\python.exe"
if exist "%ZHCRYPT_BUILD_PY%" (
    set "PYTHON=%ZHCRYPT_BUILD_PY%"
) else (
    set "PYTHON=python"
)

if /i "%1"=="gui" (
    "%PYTHON%" "%~dp0gui.py"
    set "RC=%errorlevel%"
) else if "%1"=="" (
    "%PYTHON%" "%~dp0cli.py"
    set "RC=%errorlevel%"
) else (
    "%PYTHON%" "%~dp0cli.py" %*
    set "RC=%errorlevel%"
)
endlocal & exit /b %RC%
