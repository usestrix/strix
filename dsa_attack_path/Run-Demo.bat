@echo off
REM Convenience entry at module root — forwards to scripts\Run-Demo.bat
cd /d "%~dp0"
call "%~dp0scripts\Run-Demo.bat" %*
exit /b %ERRORLEVEL%
