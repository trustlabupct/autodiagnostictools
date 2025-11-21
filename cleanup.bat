@echo off
REM Cleanup Script for PYMEs Projects (Windows Version)
REM Removes temporary files, caches, and build artifacts
REM Safe to run - only removes generated/temporary files

setlocal enabledelayedexpansion

echo ================================================================================
echo                     PYMEs Projects Cleanup Script
echo ================================================================================
echo.

REM Get script directory
cd /d "%~dp0"
echo Working directory: %CD%
echo.

REM Counter for removed items
set REMOVED_COUNT=0

echo ================================================================================
echo 1. Python Cache Files (__pycache__, *.pyc, *.pyo)
echo ================================================================================

REM Remove __pycache__ directories
set PYCACHE_COUNT=0
for /d /r %%i in (__pycache__) do (
    echo %%i | findstr /i ".venv" >nul
    if errorlevel 1 (
        if exist "%%i" (
            rd /s /q "%%i" 2>nul
            set /a PYCACHE_COUNT+=1
        )
    )
)
if !PYCACHE_COUNT! gtr 0 (
    echo [OK] Removed !PYCACHE_COUNT! __pycache__ directories
    set /a REMOVED_COUNT+=!PYCACHE_COUNT!
) else (
    echo   (no __pycache__ directories found)
)

REM Remove .pyc files
set PYC_COUNT=0
for /r %%i in (*.pyc) do (
    echo %%i | findstr /i ".venv" >nul
    if errorlevel 1 (
        if exist "%%i" (
            del /f /q "%%i" 2>nul
            set /a PYC_COUNT+=1
        )
    )
)
if !PYC_COUNT! gtr 0 (
    echo [OK] Removed !PYC_COUNT! .pyc files
    set /a REMOVED_COUNT+=!PYC_COUNT!
) else (
    echo   (no .pyc files found)
)

REM Remove .pyo files
set PYO_COUNT=0
for /r %%i in (*.pyo) do (
    echo %%i | findstr /i ".venv" >nul
    if errorlevel 1 (
        if exist "%%i" (
            del /f /q "%%i" 2>nul
            set /a PYO_COUNT+=1
        )
    )
)
if !PYO_COUNT! gtr 0 (
    echo [OK] Removed !PYO_COUNT! .pyo files
    set /a REMOVED_COUNT+=!PYO_COUNT!
) else (
    echo   (no .pyo files found)
)

echo.
echo ================================================================================
echo 2. Build Artifacts (*.egg-info, build/, dist/)
echo ================================================================================

REM Remove egg-info directories
if exist "truslan\src\truslan.egg-info" (
    rd /s /q "truslan\src\truslan.egg-info" 2>nul
    echo [OK] Removed: truslan\src\truslan.egg-info
    set /a REMOVED_COUNT+=1
)
if exist "trusClamAV\src\trusClamAV.egg-info" (
    rd /s /q "trusClamAV\src\trusClamAV.egg-info" 2>nul
    echo [OK] Removed: trusClamAV\src\trusClamAV.egg-info
    set /a REMOVED_COUNT+=1
)
if exist "trusMITRE\src\trustmitre.egg-info" (
    rd /s /q "trusMITRE\src\trustmitre.egg-info" 2>nul
    echo [OK] Removed: trusMITRE\src\trustmitre.egg-info
    set /a REMOVED_COUNT+=1
)

REM Remove build and dist directories
for %%d in (truslan trusClamAV trusMITRE) do (
    if exist "%%d\build" (
        rd /s /q "%%d\build" 2>nul
        echo [OK] Removed: %%d\build
        set /a REMOVED_COUNT+=1
    )
    if exist "%%d\dist" (
        rd /s /q "%%d\dist" 2>nul
        echo [OK] Removed: %%d\dist
        set /a REMOVED_COUNT+=1
    )
)

echo.
echo ================================================================================
echo 3. Test Artifacts (.pytest_cache, .coverage, .tox)
echo ================================================================================

REM Remove pytest cache
for %%d in (truslan trusClamAV trusMITRE .) do (
    if exist "%%d\.pytest_cache" (
        rd /s /q "%%d\.pytest_cache" 2>nul
        echo [OK] Removed: %%d\.pytest_cache
        set /a REMOVED_COUNT+=1
    )
)

REM Remove coverage and tox
if exist ".coverage" (
    del /f /q ".coverage" 2>nul
    echo [OK] Removed: .coverage
    set /a REMOVED_COUNT+=1
)
if exist "htmlcov" (
    rd /s /q "htmlcov" 2>nul
    echo [OK] Removed: htmlcov
    set /a REMOVED_COUNT+=1
)
if exist ".tox" (
    rd /s /q ".tox" 2>nul
    echo [OK] Removed: .tox
    set /a REMOVED_COUNT+=1
)

REM Remove test compiled files
if exist "trusMITRE\.compiled_test" (
    rd /s /q "trusMITRE\.compiled_test" 2>nul
    echo [OK] Removed: trusMITRE\.compiled_test
    set /a REMOVED_COUNT+=1
)

REM Remove benchmark directories
for %%d in (truslan trusClamAV trusMITRE .) do (
    if exist "%%d\.benchmarks" (
        rd /s /q "%%d\.benchmarks" 2>nul
        echo [OK] Removed: %%d\.benchmarks
        set /a REMOVED_COUNT+=1
    )
)

REM Remove mypy and ruff cache directories
for %%d in (truslan trusClamAV trusMITRE .) do (
    if exist "%%d\.mypy_cache" (
        rd /s /q "%%d\.mypy_cache" 2>nul
        echo [OK] Removed: %%d\.mypy_cache
        set /a REMOVED_COUNT+=1
    )
    if exist "%%d\.ruff_cache" (
        rd /s /q "%%d\.ruff_cache" 2>nul
        echo [OK] Removed: %%d\.ruff_cache
        set /a REMOVED_COUNT+=1
    )
)

echo.
echo ================================================================================
echo 4. Temporary Files (*.tmp, *.bak, *~, scan results)
echo ================================================================================

REM Remove temporary scan results
if exist "trusClamAV\scan_result.txt" (
    del /f /q "trusClamAV\scan_result.txt" 2>nul
    if !errorlevel! equ 0 (
        echo [OK] Removed: trusClamAV\scan_result.txt
        set /a REMOVED_COUNT+=1
    ) else (
        echo [WARNING] trusClamAV\scan_result.txt requires admin (skipped)
    )
)

REM Remove backup files (*~)
set BACKUP_COUNT=0
for /r %%i in (*~) do (
    echo %%i | findstr /i ".venv" >nul
    if errorlevel 1 (
        if exist "%%i" (
            del /f /q "%%i" 2>nul
            set /a BACKUP_COUNT+=1
        )
    )
)
if !BACKUP_COUNT! gtr 0 (
    echo [OK] Removed !BACKUP_COUNT! backup files (*~)
    set /a REMOVED_COUNT+=!BACKUP_COUNT!
)

REM Remove .bak files
set BAK_COUNT=0
for /r %%i in (*.bak) do (
    echo %%i | findstr /i ".venv" >nul
    if errorlevel 1 (
        if exist "%%i" (
            del /f /q "%%i" 2>nul
            set /a BAK_COUNT+=1
        )
    )
)
if !BAK_COUNT! gtr 0 (
    echo [OK] Removed !BAK_COUNT! .bak files
    set /a REMOVED_COUNT+=!BAK_COUNT!
)

REM Remove .tmp files
set TMP_COUNT=0
for /r %%i in (*.tmp) do (
    echo %%i | findstr /i ".venv" >nul
    if errorlevel 1 (
        if exist "%%i" (
            del /f /q "%%i" 2>nul
            set /a TMP_COUNT+=1
        )
    )
)
if !TMP_COUNT! gtr 0 (
    echo [OK] Removed !TMP_COUNT! .tmp files
    set /a REMOVED_COUNT+=!TMP_COUNT!
)

echo.
echo ================================================================================
echo 5. IDE/Editor Files (.vscode, .idea, *.swp, Thumbs.db)
echo ================================================================================

REM Remove IDE directories
if exist ".vscode" (
    rd /s /q ".vscode" 2>nul
    echo [OK] Removed: .vscode
    set /a REMOVED_COUNT+=1
)
if exist ".idea" (
    rd /s /q ".idea" 2>nul
    echo [OK] Removed: .idea
    set /a REMOVED_COUNT+=1
)

REM Remove Vim swap files
set SWP_COUNT=0
for /r %%i in (.*.swp) do (
    echo %%i | findstr /i ".venv" >nul
    if errorlevel 1 (
        if exist "%%i" (
            del /f /q "%%i" 2>nul
            set /a SWP_COUNT+=1
        )
    )
)
if !SWP_COUNT! gtr 0 (
    echo [OK] Removed !SWP_COUNT! Vim swap files
    set /a REMOVED_COUNT+=!SWP_COUNT!
)

REM Remove macOS .DS_Store files
set DS_COUNT=0
for /r %%i in (.DS_Store) do (
    if exist "%%i" (
        del /f /q "%%i" 2>nul
        set /a DS_COUNT+=1
    )
)
if !DS_COUNT! gtr 0 (
    echo [OK] Removed !DS_COUNT! .DS_Store files
    set /a REMOVED_COUNT+=!DS_COUNT!
)

REM Remove Windows Thumbs.db files
set THUMBS_COUNT=0
for /r %%i in (Thumbs.db) do (
    if exist "%%i" (
        del /f /q "%%i" 2>nul
        set /a THUMBS_COUNT+=1
    )
)
if !THUMBS_COUNT! gtr 0 (
    echo [OK] Removed !THUMBS_COUNT! Thumbs.db files
    set /a REMOVED_COUNT+=!THUMBS_COUNT!
)

REM Remove desktop.ini files
set INI_COUNT=0
for /r %%i in (desktop.ini) do (
    if exist "%%i" (
        attrib -h -s "%%i" 2>nul
        del /f /q "%%i" 2>nul
        set /a INI_COUNT+=1
    )
)
if !INI_COUNT! gtr 0 (
    echo [OK] Removed !INI_COUNT! desktop.ini files
    set /a REMOVED_COUNT+=!INI_COUNT!
)

echo.
echo ================================================================================
echo Summary
echo ================================================================================
echo.
echo [OK] Cleanup complete!
echo [OK] Removed approximately !REMOVED_COUNT! items
echo.
echo Preserved (important files/directories):
echo   [OK] Virtual environments (.venv)
echo   [OK] Source code (all .py files)
echo   [OK] Configuration files (pyproject.toml, requirements.txt)
echo   [OK] Documentation (README.md, etc.)
echo   [OK] Analytics data (trusMITRE\analytics\)
echo   [OK] Compiled analytics (trusMITRE\.compiled\)
echo   [OK] Output directories (trusMITRE\output\, trusMITRE\logs\)
echo   [OK] Test data (trusMITRE\logs\test.jsonl)
echo   [OK] Issue examples (trusClamAV\issue\)
echo.
echo ================================================================================
echo                           Cleanup Complete!
echo ================================================================================
echo.
echo Note: Virtual environments (.venv) were preserved.
echo       Run install.bat in pymes_ui if you need to reinstall.
echo.
pause
