@echo off
REM PYMEs Unified Security Toolkit Launcher (Windows)
REM Launches the unified GUI for TrusLAN, trusClamAV, and trustMITRE
REM
REM Author: Volodymyr Dubetskyy
REM Organization: TRUST Lab UPCT
REM © 2025 TRUST Lab UPCT

setlocal enabledelayedexpansion

echo ================================================================
echo    PYMEs Unified Security Toolkit Launcher
echo    TrusLAN * trusClamAV * trustMITRE
echo ================================================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Not running as Administrator
    echo Some operations may require elevated privileges:
    echo   - TrusLAN: Network scanning, UDP ports
    echo   - trusClamAV: Installing ClamAV, updating databases
    echo   - trustMITRE: Live Sysmon collection
    echo.
    echo To run as Administrator:
    echo   Right-click this file and select "Run as administrator"
    echo.
    choice /C YN /M "Continue without Administrator privileges"
    if errorlevel 2 exit /b 0
    echo.
)

REM Get script directory
set SCRIPT_DIR=%~dp0
set BASE_DIR=%SCRIPT_DIR%..

REM Check Python installation
echo Checking Python installation...
where python >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python
    goto :python_found
)

where python3 >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python3
    goto :python_found
)

where py >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=py
    goto :python_found
)

echo [X] Python not found!
echo Please install Python 3.9 or higher from python.org
pause
exit /b 1

:python_found
for /f "tokens=2" %%i in ('%PYTHON_CMD% --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [OK] Found Python %PYTHON_VERSION%

REM Check Python version (simplified check)
%PYTHON_CMD% -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python 3.9+ required (found %PYTHON_VERSION%^)
    pause
    exit /b 1
)

REM Check for tkinter
echo Checking tkinter...
%PYTHON_CMD% -c "import tkinter" >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] tkinter not found!
    echo.
    echo Please reinstall Python and ensure "tcl/tk and IDLE" is selected
    pause
    exit /b 1
)
echo [OK] tkinter is available

REM Check for tools
echo Checking integrated tools...
set TOOLS_FOUND=0

if exist "%BASE_DIR%\truslan" (
    echo [OK] TrusLAN found
    set /a TOOLS_FOUND+=1
) else (
    echo [!] TrusLAN not found at %BASE_DIR%\truslan
)

if exist "%BASE_DIR%\trusClamAV" (
    echo [OK] trusClamAV found
    set /a TOOLS_FOUND+=1
) else (
    echo [!] trusClamAV not found at %BASE_DIR%\trusClamAV
)

if exist "%BASE_DIR%\trusMITRE" (
    echo [OK] trustMITRE found
    set /a TOOLS_FOUND+=1
) else (
    echo [!] trustMITRE not found at %BASE_DIR%\trusMITRE
)

if %TOOLS_FOUND% equ 0 (
    echo [X] No tools found!
    echo Please ensure tools are installed in the correct directory structure
    pause
    exit /b 1
)

echo Found %TOOLS_FOUND%/3 tools

REM Check for venv
if exist "%BASE_DIR%\trusMITRE\.venv\Scripts\activate.bat" (
    echo Virtual environment found, activating...
    call "%BASE_DIR%\trusMITRE\.venv\Scripts\activate.bat"
    echo [OK] Using venv Python
)

echo.
echo ================================================================
echo    Starting PYMEs Unified Security Toolkit...
echo ================================================================
echo.

REM Launch the application
cd /d "%SCRIPT_DIR%"
%PYTHON_CMD% main.py %*

if %errorlevel% neq 0 (
    echo.
    echo [X] Application exited with error code %errorlevel%
    pause
)

endlocal
