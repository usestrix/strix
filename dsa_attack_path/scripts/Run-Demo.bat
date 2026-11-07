@echo off
setlocal EnableExtensions
title Strix DSA Attack Path — thesis demo
cd /d "%~dp0"

REM Prepend common Windows lab toolchain paths (harmless if missing).
set "PATH=C:\Program Files\CMake\bin;C:\TDM-GCC-64\bin;%APPDATA%\Python\Python314\Scripts;%PATH%"

echo.
echo ============================================================
echo  Strix DSA Attack Path — one-click thesis demo
echo  MODELED graph only — not a confirmed multi-hop exploit chain.
echo  Simulated lateral: OFF
echo ============================================================
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo [ERROR] python not found on PATH.
  echo Install Python 3.12+ and retry.
  goto :pause_fail
)

python "%~dp0run_demo.py" %*
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" (
  echo Demo finished with exit code %RC%.
  goto :pause_fail
)
echo Demo launcher finished OK.
goto :pause_ok

:pause_fail
echo.
pause
exit /b %RC%

:pause_ok
REM Keep window open when double-clicked so the viewer URL / messages are visible.
pause
exit /b 0
