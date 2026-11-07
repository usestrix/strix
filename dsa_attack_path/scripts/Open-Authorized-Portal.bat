@echo off
setlocal
cd /d "%~dp0"
set "PATH=%APPDATA%\Python\Python314\Scripts;%PATH%"
echo Opening authorized-target portal (URL field + checkbox gate)…
echo Only scan systems you own or have written permission to test.
python "%~dp0demo_portal.py"
pause
