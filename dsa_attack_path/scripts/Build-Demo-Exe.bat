@echo off
setlocal
cd /d "%~dp0"
echo Building optional one-file Run-DSA-Demo.exe via PyInstaller…
python -m pip install --user pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --console --name Run-DSA-Demo run_demo.py
if exist "dist\Run-DSA-Demo.exe" (
  echo.
  echo OK: %~dp0dist\Run-DSA-Demo.exe
) else (
  echo FAILED — use Run-Demo.bat instead.
  exit /b 1
)
pause
