@echo off
chcp 65001 >nul

echo.
echo  =========================================
echo   SecuX  ^|  Multi-Agent Security Auditor
echo  =========================================
echo.

:: Verify Python is available
where python >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Install Python 3.10+ and try again.
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  [OK] Python %PYVER% found

:: Install dependencies
echo  [..] Installing dependencies...
pip install -r requirements.txt --quiet --disable-pip-version-check
if errorlevel 1 (
    echo  [ERROR] pip install failed. Check your network or requirements.txt.
    pause
    exit /b 1
)
echo  [OK] Dependencies installed

:: Install secux package
echo  [..] Installing SecuX package...
pip install -e . --quiet --disable-pip-version-check
if errorlevel 1 (
    echo  [ERROR] SecuX package install failed.
    pause
    exit /b 1
)
echo  [OK] SecuX package installed

:: Launch CLI
echo.
echo  Launching SecuX...
echo.
secux

echo.
pause
