@echo off
REM PYMEs Unified Security Toolkit - Installation Script (Windows Batch)
REM Direct installation with module selection
REM
REM Author: Volodymyr Dubetskyy
REM Organization: Trust Lab UPCT
REM © 2025 Trust Lab UPCT

setlocal enabledelayedexpansion

REM Get script directory
set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
for %%I in ("%SCRIPT_DIR%\..") do set "BASE_DIR=%%~fI"

REM Default: install all modules
set "INSTALL_TRUSLAN=0"
set "INSTALL_TRUSCLAMAV=0"
set "INSTALL_TRUSTMITRE=0"
set "INSTALL_ALL=0"

REM Parse arguments
if "%~1"=="" (
    set "INSTALL_ALL=1"
) else (
    :parse_args
    if "%~1"=="" goto :args_done

    if /i "%~1"=="truslan" (
        set "INSTALL_TRUSLAN=1"
    ) else if /i "%~1"=="trusclamav" (
        set "INSTALL_TRUSCLAMAV=1"
    ) else if /i "%~1"=="trustmitre" (
        set "INSTALL_TRUSTMITRE=1"
    ) else if /i "%~1"=="all" (
        set "INSTALL_ALL=1"
    ) else (
        echo [ERROR] Unknown module: %~1
        echo Usage: install.bat [truslan] [trusclamav] [trustmitre] [all]
        echo No arguments = install all
        exit /b 1
    )

    shift
    goto :parse_args
    :args_done
)

REM Set all to true if INSTALL_ALL is true
if "%INSTALL_ALL%"=="1" (
    set "INSTALL_TRUSLAN=1"
    set "INSTALL_TRUSCLAMAV=1"
    set "INSTALL_TRUSTMITRE=1"
)

echo.
echo [96mPYMEs Unified Security Toolkit - Installation[0m
echo [96m=============================================[0m
echo.

REM Check Python
set "PYTHON_CMD="
where python3 >nul 2>&1
if %errorlevel%==0 (
    set "PYTHON_CMD=python3"
) else (
    where python >nul 2>&1
    if %errorlevel%==0 (
        set "PYTHON_CMD=python"
    ) else (
        where py >nul 2>&1
        if %errorlevel%==0 (
            set "PYTHON_CMD=py"
        )
    )
)

if "%PYTHON_CMD%"=="" (
    echo [91mERROR: Python not found[0m
    echo Please install Python 3.9 or higher from https://www.python.org/
    exit /b 1
)

for /f "tokens=*" %%v in ('%PYTHON_CMD% --version 2^>^&1') do set "PYTHON_VERSION=%%v"
echo [92mPython: %PYTHON_VERSION%[0m

REM Check pip
set "PIP_CMD=pip"
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    set "PIP_CMD=pip3"
)

REM Check tkinter
echo Checking tkinter...
%PYTHON_CMD% -c "import tkinter; print('OK')" >nul 2>&1
if %errorlevel% neq 0 (
    echo [91mERROR: tkinter not found[0m
    echo Please reinstall Python with 'tcl/tk and IDLE' option checked
    echo Download from: https://www.python.org/downloads/
    exit /b 1
)

echo.

REM Install TrusLAN
if "%INSTALL_TRUSLAN%"=="1" (
    if exist "%BASE_DIR%\truslan\" (
        echo [96m[TrusLAN][0m
        cd /d "%BASE_DIR%\truslan"

        REM Create or use existing venv
        if not exist ".venv\" (
            echo Creating virtual environment for TrusLAN...
            %PYTHON_CMD% -m venv .venv
        )

        REM Activate and install
        call .venv\Scripts\activate.bat
        if exist "requirements.txt" (
            pip install -r requirements.txt
            if %errorlevel%==0 (
                echo [92mTrusLAN dependencies installed[0m
            )
        )
        call deactivate

        REM Check nmap
        where nmap >nul 2>&1
        if %errorlevel% neq 0 (
            echo [93mnmap not found. Install manually if needed from https://nmap.org/download.html[0m
        )
        echo.
    ) else (
        echo [93mTrusLAN directory not found[0m
    )
)

REM Install trusClamAV
if "%INSTALL_TRUSCLAMAV%"=="1" (
    if exist "%BASE_DIR%\trusClamAV\" (
        echo [96m[trusClamAV][0m
        cd /d "%BASE_DIR%\trusClamAV"

        REM Create or use existing venv
        if not exist ".venv\" (
            echo Creating virtual environment for trusClamAV...
            %PYTHON_CMD% -m venv .venv
        )

        REM Activate and install
        call .venv\Scripts\activate.bat
        if exist "requirements.txt" (
            pip install -r requirements.txt
            if %errorlevel%==0 (
                echo [92mtrusClamAV dependencies installed[0m
            )
        )
        call deactivate

        REM Check ClamAV
        where clamscan >nul 2>&1
        if %errorlevel% neq 0 (
            echo [93mClamAV not found. Use 'doctor' command in UI to install.[0m
            echo Or download from: https://www.clamav.net/downloads
        )
        echo.
    ) else (
        echo [93mtrusClamAV directory not found[0m
    )
)

REM Install trustMITRE
if "%INSTALL_TRUSTMITRE%"=="1" (
    if exist "%BASE_DIR%\trusMITRE\" (
        echo [96m[trustMITRE][0m
        cd /d "%BASE_DIR%\trusMITRE"

        REM Create or use existing venv
        if not exist ".venv\" (
            echo Creating virtual environment for trustMITRE...
            %PYTHON_CMD% -m venv .venv
        )

        REM Activate and install
        call .venv\Scripts\activate.bat
        if exist "requirements.txt" (
            pip install -r requirements.txt
        )
        if exist "requirements-dev.txt" (
            pip install -r requirements-dev.txt
        )
        pip install -e .
        if %errorlevel%==0 (
            echo [92mtrustMITRE dependencies installed[0m
        )
        call deactivate
        echo.
    ) else (
        echo [93mtrustMITRE directory not found[0m
    )
)

cd /d "%SCRIPT_DIR%"

echo [92m=============================================[0m
echo [92mInstallation complete[0m
echo [92m=============================================[0m
echo.
echo Launch: launch.bat or python main.py
echo Check: python check_system.py
echo.
echo Note: If you encounter execution policy errors with PowerShell scripts,
echo       run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
echo.

endlocal
