#
# PYMEs Unified Security Toolkit - Installation Script (Windows)
# Direct installation with module selection
#
# Author: Volodymyr Dubetskyy
# Organization: TRUST Lab UPCT
# © 2025 TRUST Lab UPCT

param(
    [switch]$TrusLAN,
    [switch]$TrusClamAV,
    [switch]$TrustMITRE,
    [switch]$All
)

# Colors
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BaseDir = Split-Path -Parent $ScriptDir

# Default: install all modules if no arguments
$InstallTrusLAN = $false
$InstallTrusClamAV = $false
$InstallTrustMITRE = $false

if (-not $TrusLAN -and -not $TrusClamAV -and -not $TrustMITRE -and -not $All) {
    $All = $true
}

if ($All) {
    $InstallTrusLAN = $true
    $InstallTrusClamAV = $true
    $InstallTrustMITRE = $true
} else {
    $InstallTrusLAN = $TrusLAN
    $InstallTrusClamAV = $TrusClamAV
    $InstallTrustMITRE = $TrustMITRE
}

Write-ColorOutput "PYMEs Unified Security Toolkit - Installation" "Cyan"
Write-ColorOutput "=============================================" "Cyan"
Write-Host ""

# Check Python
$PythonCmd = $null
$PythonVersions = @("python3", "python", "py")

foreach ($cmd in $PythonVersions) {
    try {
        $version = & $cmd --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $PythonCmd = $cmd
            break
        }
    } catch {
        continue
    }
}

if (-not $PythonCmd) {
    Write-ColorOutput "ERROR: Python not found" "Red"
    Write-Host "Please install Python 3.9 or higher from https://www.python.org/"
    exit 1
}

$PythonVersion = & $PythonCmd --version 2>&1
Write-ColorOutput "Python: $PythonVersion" "Green"

# Extract version number
$VersionMatch = $PythonVersion -match '(\d+)\.(\d+)'
if ($VersionMatch) {
    $MajorVersion = [int]$Matches[1]
    $MinorVersion = [int]$Matches[2]

    if ($MajorVersion -lt 3 -or ($MajorVersion -eq 3 -and $MinorVersion -lt 9)) {
        Write-ColorOutput "WARNING: Python 3.9+ recommended, found $MajorVersion.$MinorVersion" "Yellow"
    }
}

# Check pip
$PipCmd = "pip"
try {
    & $PipCmd --version 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $PipCmd = "pip3"
    }
} catch {
    $PipCmd = "pip3"
}

# Check tkinter
Write-Host "Checking tkinter..."
$TkinterCheck = & $PythonCmd -c "import tkinter; print('OK')" 2>&1
if ($TkinterCheck -notmatch "OK") {
    Write-ColorOutput "ERROR: tkinter not found" "Red"
    Write-Host "Please reinstall Python with 'tcl/tk and IDLE' option checked"
    Write-Host "Download from: https://www.python.org/downloads/"
    exit 1
}

Write-Host ""

# Install TrusLAN
if ($InstallTrusLAN) {
    $TrusLANPath = Join-Path $BaseDir "truslan"
    if (Test-Path $TrusLANPath) {
        Write-ColorOutput "[TrusLAN]" "Cyan"
        Push-Location $TrusLANPath

        # Create or use existing venv
        $VenvPath = Join-Path $TrusLANPath ".venv"
        if (-not (Test-Path $VenvPath)) {
            Write-Host "Creating virtual environment for TrusLAN..."
            & $PythonCmd -m venv .venv
        }

        # Activate venv
        $ActivateScript = Join-Path $VenvPath "Scripts\Activate.ps1"
        if (Test-Path $ActivateScript) {
            & $ActivateScript

            # Install requirements
            $RequirementsPath = Join-Path $TrusLANPath "requirements.txt"
            if (Test-Path $RequirementsPath) {
                & pip install -r requirements.txt
                Write-ColorOutput "TrusLAN dependencies installed" "Green"
            }

            deactivate
        }

        Pop-Location

        # Check nmap
        $NmapCheck = Get-Command nmap -ErrorAction SilentlyContinue
        if (-not $NmapCheck) {
            Write-ColorOutput "nmap not found. Install manually if needed from https://nmap.org/download.html" "Yellow"
        }
        Write-Host ""
    } else {
        Write-ColorOutput "TrusLAN directory not found at $TrusLANPath" "Yellow"
    }
}

# Install trusClamAV
if ($InstallTrusClamAV) {
    $TrusClamAVPath = Join-Path $BaseDir "trusClamAV"
    if (Test-Path $TrusClamAVPath) {
        Write-ColorOutput "[trusClamAV]" "Cyan"
        Push-Location $TrusClamAVPath

        # Create or use existing venv
        $VenvPath = Join-Path $TrusClamAVPath ".venv"
        if (-not (Test-Path $VenvPath)) {
            Write-Host "Creating virtual environment for trusClamAV..."
            & $PythonCmd -m venv .venv
        }

        # Activate venv
        $ActivateScript = Join-Path $VenvPath "Scripts\Activate.ps1"
        if (Test-Path $ActivateScript) {
            & $ActivateScript

            # Install requirements
            $RequirementsPath = Join-Path $TrusClamAVPath "requirements.txt"
            if (Test-Path $RequirementsPath) {
                & pip install -r requirements.txt
                Write-ColorOutput "trusClamAV dependencies installed" "Green"
            }

            deactivate
        }

        Pop-Location

        # Check ClamAV
        $ClamScanCheck = Get-Command clamscan -ErrorAction SilentlyContinue
        if (-not $ClamScanCheck) {
            Write-ColorOutput "ClamAV not found. Use 'doctor' command in UI to install." "Yellow"
            Write-Host "Or download from: https://www.clamav.net/downloads"
        }
        Write-Host ""
    } else {
        Write-ColorOutput "trusClamAV directory not found at $TrusClamAVPath" "Yellow"
    }
}

# Install trustMITRE
if ($InstallTrustMITRE) {
    $TrustMITREPath = Join-Path $BaseDir "trusMITRE"
    if (Test-Path $TrustMITREPath) {
        Write-ColorOutput "[trustMITRE]" "Cyan"
        Push-Location $TrustMITREPath

        # Create or use existing venv
        $VenvPath = Join-Path $TrustMITREPath ".venv"
        if (-not (Test-Path $VenvPath)) {
            Write-Host "Creating virtual environment for trustMITRE..."
            & $PythonCmd -m venv .venv
        }

        # Activate venv
        $ActivateScript = Join-Path $VenvPath "Scripts\Activate.ps1"
        if (Test-Path $ActivateScript) {
            & $ActivateScript

            # Install requirements
            $RequirementsPath = Join-Path $TrustMITREPath "requirements.txt"
            if (Test-Path $RequirementsPath) {
                & pip install -r requirements.txt
            }

            # Install dev requirements if exists
            $RequirementsDevPath = Join-Path $TrustMITREPath "requirements-dev.txt"
            if (Test-Path $RequirementsDevPath) {
                & pip install -r requirements-dev.txt
            }

            # Install in editable mode
            & pip install -e .
            Write-ColorOutput "trustMITRE dependencies installed" "Green"

            deactivate
        }

        Pop-Location
        Write-Host ""
    } else {
        Write-ColorOutput "trustMITRE directory not found at $TrustMITREPath" "Yellow"
    }
}

Write-ColorOutput "=============================================" "Green"
Write-ColorOutput "Installation complete" "Green"
Write-ColorOutput "=============================================" "Green"
Write-Host ""
Write-Host "Launch: .\launch.bat or python main.py"
Write-Host "Check: python check_system.py"
Write-Host ""
Write-Host "Note: You may need to set execution policy to run scripts:"
Write-Host "      Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"
Write-Host ""
