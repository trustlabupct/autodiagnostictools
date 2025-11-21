# trusClamAV Build Script for Windows
# Creates a standalone executable using PyInstaller
#
# Author: Volodymyr Dubetskyy
# Date: October 13, 2025

param(
    [string]$Mode = "onefile",  # onefile or onedir
    [switch]$Debug = $false,
    [switch]$Clean = $false
)

# Script configuration
$ErrorActionPreference = "Stop"
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptPath
$BuildDir = Join-Path $ProjectRoot "build"
$DistDir = Join-Path $ProjectRoot "dist"
$SpecFile = Join-Path $ProjectRoot "trusClamAV.spec"

# Application info
$AppName = "trusClamAV"
$AppVersion = "2.0.0"
$AppDescription = "Windows ClamAV Integration Tool"
$AppIcon = Join-Path $ProjectRoot "assets\icon.ico"  # Optional

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "trusClamAV Build Script v$AppVersion" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Function to check if command exists
function Test-Command {
    param([string]$Command)
    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

# Clean build artifacts
if ($Clean) {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow

    if (Test-Path $BuildDir) {
        Remove-Item -Path $BuildDir -Recurse -Force
        Write-Host "  [OK] Removed build directory" -ForegroundColor Green
    }

    if (Test-Path $DistDir) {
        Remove-Item -Path $DistDir -Recurse -Force
        Write-Host "  [OK] Removed dist directory" -ForegroundColor Green
    }

    if (Test-Path $SpecFile) {
        Remove-Item -Path $SpecFile -Force
        Write-Host "  [OK] Removed spec file" -ForegroundColor Green
    }

    # Clean __pycache__ directories
    Get-ChildItem -Path $ProjectRoot -Directory -Recurse -Filter "__pycache__" | ForEach-Object {
        Remove-Item -Path $_.FullName -Recurse -Force
    }
    Write-Host "  [OK] Removed __pycache__ directories" -ForegroundColor Green

    if ($Clean -and -not $Mode) {
        Write-Host ""
        Write-Host "Clean completed successfully!" -ForegroundColor Green
        exit 0
    }
}

# Check Python installation
Write-Host "Checking environment..." -ForegroundColor Yellow

if (-not (Test-Command "python")) {
    Write-Error "Python is not installed or not in PATH"
    exit 1
}

$PythonVersion = python --version 2>&1
Write-Host "  [OK] Python found: $PythonVersion" -ForegroundColor Green

# Check PyInstaller installation
if (-not (Test-Command "pyinstaller")) {
    Write-Host "  ! PyInstaller not found. Installing..." -ForegroundColor Yellow
    python -m pip install pyinstaller

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install PyInstaller"
        exit 1
    }
    Write-Host "  [OK] PyInstaller installed successfully" -ForegroundColor Green
} else {
    $PyInstallerVersion = pyinstaller --version 2>&1
    Write-Host "  [OK] PyInstaller found: v$PyInstallerVersion" -ForegroundColor Green
}

# Install required dependencies
Write-Host ""
Write-Host "Installing dependencies..." -ForegroundColor Yellow

$RequirementsFile = Join-Path $ProjectRoot "requirements.txt"
if (Test-Path $RequirementsFile) {
    python -m pip install -r $RequirementsFile --quiet
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Dependencies installed" -ForegroundColor Green
    } else {
        Write-Host "  ! Some dependencies may have failed to install" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ! requirements.txt not found, skipping dependency installation" -ForegroundColor Yellow
}

# Prepare build arguments
Write-Host ""
Write-Host "Preparing build configuration..." -ForegroundColor Yellow

$BuildArgs = @(
    "--name=$AppName",
    "--distpath=$DistDir",
    "--workpath=$BuildDir",
    "--specpath=$ProjectRoot",
    "--noconfirm",
    "--clean"
)

# Add mode-specific arguments
if ($Mode -eq "onefile") {
    $BuildArgs += "--onefile"
    Write-Host "  • Building as single executable" -ForegroundColor Cyan
} else {
    $BuildArgs += "--onedir"
    Write-Host "  • Building as directory bundle" -ForegroundColor Cyan
}

# Add Windows-specific arguments
$BuildArgs += @(
    "--windowed",  # No console window for GUI
    "--console",   # But keep console for CLI (PyInstaller will handle both)
    "--noupx"      # Don't use UPX compression (more reliable)
)

# Add icon if exists
if (Test-Path $AppIcon -ErrorAction SilentlyContinue) {
    $BuildArgs += "--icon=$AppIcon"
    Write-Host "  • Using custom icon" -ForegroundColor Cyan
}

# Add hidden imports for dependencies that might not be detected
$HiddenImports = @(
    "tkinter",
    "tkinter.ttk",
    "tkinter.messagebox",
    "tkinter.filedialog",
    "customtkinter",
    "yaml",
    "json",
    "logging.handlers",
    "subprocess",
    "pathlib",
    "ctypes",
    "winreg"
)

foreach ($Import in $HiddenImports) {
    $BuildArgs += "--hidden-import=$Import"
}

# Add data files
$DataFiles = @(
    "README.md",
    "requirements.txt"
)

foreach ($File in $DataFiles) {
    $FilePath = Join-Path $ProjectRoot $File
    if (Test-Path $FilePath) {
        $BuildArgs += "--add-data=`"$FilePath;.`""
    }
}

# Debug mode
if ($Debug) {
    $BuildArgs += "--debug=all"
    $BuildArgs += "--log-level=DEBUG"
    Write-Host "  • Debug mode enabled" -ForegroundColor Yellow
}

# Main entry point
$EntryPoint = Join-Path $ProjectRoot "__main__.py"

# Build the application
Write-Host ""
Write-Host "Building $AppName..." -ForegroundColor Yellow
Write-Host "This may take a few minutes..." -ForegroundColor Gray
Write-Host ""

# Change to project directory
Push-Location $ProjectRoot

try {
    # Run PyInstaller
    $BuildCommand = "pyinstaller $($BuildArgs -join ' ') $EntryPoint"

    if ($Debug) {
        Write-Host "Build command: $BuildCommand" -ForegroundColor Gray
        Write-Host ""
    }

    # Execute build
    Invoke-Expression $BuildCommand

    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller build failed with exit code $LASTEXITCODE"
    }

    # Verify output
    if ($Mode -eq "onefile") {
        $OutputFile = Join-Path $DistDir "$AppName.exe"
    } else {
        $OutputFile = Join-Path $DistDir $AppName "$AppName.exe"
    }

    if (Test-Path $OutputFile) {
        $FileInfo = Get-Item $OutputFile
        $FileSizeMB = [math]::Round($FileInfo.Length / 1MB, 2)

        # Create versioned artifact name
        $BuildDate = Get-Date -Format "yyyyMMdd"
        $VersionedName = "$AppName-v$AppVersion-$BuildDate"

        if ($Mode -eq "onefile") {
            $VersionedFile = Join-Path $DistDir "$VersionedName.exe"
            Copy-Item -Path $OutputFile -Destination $VersionedFile -Force
            $FinalOutput = $VersionedFile
        } else {
            $VersionedDir = Join-Path $DistDir $VersionedName
            if (Test-Path $VersionedDir) {
                Remove-Item -Path $VersionedDir -Recurse -Force
            }
            $SourceDir = Join-Path $DistDir $AppName
            Copy-Item -Path $SourceDir -Destination $VersionedDir -Recurse -Force
            $FinalOutput = Join-Path $VersionedDir "$AppName.exe"
        }

        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Build completed successfully!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Output file: $OutputFile" -ForegroundColor Cyan
        Write-Host "Versioned artifact: $FinalOutput" -ForegroundColor Cyan
        Write-Host "File size: $FileSizeMB MB" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "To run the application:" -ForegroundColor Yellow
        Write-Host "  $FinalOutput" -ForegroundColor White
        Write-Host ""
        Write-Host "To run with arguments:" -ForegroundColor Yellow
        Write-Host "  $FinalOutput doctor" -ForegroundColor White
        Write-Host "  $FinalOutput scan --targets C:\Users" -ForegroundColor White
        Write-Host "  $FinalOutput gui" -ForegroundColor White
    } else {
        throw "Build succeeded but output file not found"
    }

} catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "Build failed!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $_" -ForegroundColor Red

    if ($Debug) {
        Write-Host ""
        Write-Host "Check the build log for details:" -ForegroundColor Yellow
        Write-Host "  $BuildDir\$AppName\warn-$AppName.txt" -ForegroundColor Gray
    }

    exit 1

} finally {
    Pop-Location
}

# Optional: Create installer (requires NSIS or similar)
if (Get-Command makensis -ErrorAction SilentlyContinue) {
    Write-Host ""
    Write-Host "NSIS detected. Create installer? (y/n): " -NoNewline -ForegroundColor Yellow
    $CreateInstaller = Read-Host

    if ($CreateInstaller -eq 'y') {
        # TODO: Add NSIS installer creation logic
        Write-Host "Installer creation not yet implemented" -ForegroundColor Yellow
    }
}
