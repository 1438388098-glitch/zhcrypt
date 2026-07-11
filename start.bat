@echo off
cd /d "%~dp0"

REM ============================================================
REM  zhcrypt 智能启动器
REM  优先级：内置便携版（已含 Python 运行时，零依赖） > 系统 Python
REM  无论哪种情况都不会出现 9009（命令未找到）错误
REM ============================================================

REM ---- 1) 优先使用内置便携版（朋友解压即用，无需安装任何环境）----
if exist "dist\zhcrypt-gui\zhcrypt-gui.exe" (
    echo 正在启动内置便携版（已包含 Python 与全部依赖，无需安装）...
    start "" "dist\zhcrypt-gui\zhcrypt-gui.exe"
    exit /b 0
)

REM ---- 2) 源码方式：检测系统 Python 命令 ----
set "PY="
where python >nul 2>nul && set "PY=python"
if "%PY%"=="" ( where py >nul 2>nul && set "PY=py" )

if "%PY%"=="" (
    echo ============================================================
    echo   未能找到 Python 运行环境，无法以源码方式启动。
    echo.
    echo   推荐做法：直接使用便携版
    echo     打开 dist\zhcrypt-gui\ 文件夹，双击其中的 start.bat
    echo     （该版本已内置 Python 与全部依赖，无需安装任何软件）
    echo.
    echo   或自行安装 Python：https://www.python.org/downloads/
    echo     安装时务必勾选 "Add Python to PATH"
    echo ============================================================
    pause
    exit /b 1
)

REM ---- 3) 用找到的 Python 运行源码（需本机已安装依赖）----
"%PY%" -W ignore -X utf8 gui.py
if %errorlevel% neq 0 (
    echo.
    echo [Error] gui.py exited with code %errorlevel%
    pause
)
