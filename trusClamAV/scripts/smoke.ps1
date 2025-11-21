# trusClamAV Smoke Test Script
# Runs basic tests to validate functionality
#
# Author: Volodymyr Dubetskyy
# Date: January 2025

param(
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Continue"
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptPath

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "trusClamAV Smoke Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Track results
$TestsPassed = 0
$TestsFailed = 0
$TestResults = @()

# Function to run a test
function Test-Command {
    param(
        [string]$Name,
        [string]$Command,
        [array]$ExpectedExitCodes = @(0),
        [switch]$AllowFailure = $false
    )

    Write-Host "Running: $Name" -ForegroundColor Yellow
    Write-Host "  Command: $Command" -ForegroundColor Gray

    try {
        $Output = Invoke-Expression $Command 2>&1
        $ExitCode = $LASTEXITCODE

        if ($Verbose) {
            Write-Host "  Output:" -ForegroundColor Gray
            $Output | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        }

        $Success = $ExpectedExitCodes -contains $ExitCode

        if ($Success) {
            Write-Host "  [OK] PASS (exit code: $ExitCode)" -ForegroundColor Green
            $script:TestsPassed++
            $script:TestResults += [PSCustomObject]@{
                Name = $Name
                Status = "PASS"
                ExitCode = $ExitCode
                AllowFailure = $AllowFailure
            }
        } else {
            if ($AllowFailure) {
                Write-Host "  ~ WARN (exit code: $ExitCode, expected: $($ExpectedExitCodes -join ','))" -ForegroundColor Yellow
                $script:TestsPassed++
                $script:TestResults += [PSCustomObject]@{
                    Name = $Name
                    Status = "WARN"
                    ExitCode = $ExitCode
                    AllowFailure = $AllowFailure
                }
            } else {
                Write-Host "  [ERROR] FAIL (exit code: $ExitCode, expected: $($ExpectedExitCodes -join ','))" -ForegroundColor Red
                $script:TestsFailed++
                $script:TestResults += [PSCustomObject]@{
                    Name = $Name
                    Status = "FAIL"
                    ExitCode = $ExitCode
                    AllowFailure = $AllowFailure
                }
            }
        }
    } catch {
        Write-Host "  [ERROR] ERROR: $_" -ForegroundColor Red
        $script:TestsFailed++
        $script:TestResults += [PSCustomObject]@{
            Name = $Name
            Status = "ERROR"
            ExitCode = -1
            AllowFailure = $AllowFailure
        }
    }

    Write-Host ""
}

# Change to project directory
Push-Location $ProjectRoot

try {
    # Test 1: Check if Python is available
    Test-Command -Name "Python Version Check" -Command "python --version"

    # Test 2: Version command
    Test-Command -Name "Version Command" -Command "python -m trusClamAV --version"

    # Test 3: Help command
    Test-Command -Name "Help Command" -Command "python -m trusClamAV --help"

    # Test 4: Doctor command (basic)
    Test-Command -Name "Doctor Command" -Command "python -m trusClamAV doctor"

    # Test 5: Doctor command with JSON output
    Test-Command -Name "Doctor JSON Output" -Command "python -m trusClamAV doctor --json"

    # Test 6: Update command (may fail if no internet or ClamAV not installed - non-fatal)
    Test-Command -Name "Update Command" -Command "python -m trusClamAV update" -ExpectedExitCodes @(0, 1, 2) -AllowFailure

    # Test 7: Dry-run scan of current directory
    $TempDir = Join-Path $env:TEMP "trusclamav_smoke_test"
    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

    # Create a test file with safe content
    $TestFile = Join-Path $TempDir "test.txt"
    "This is a test file for trusClamAV smoke test." | Out-File -FilePath $TestFile -Encoding UTF8

    Test-Command -Name "Dry-Run Scan" -Command "python -m trusClamAV scan --targets `"$TempDir`" --dry-run"

    # Test 8: Actual scan of temp directory (may fail if ClamAV not installed)
    Test-Command -Name "Real Scan (Temp Dir)" -Command "python -m trusClamAV scan --targets `"$TempDir`" --out `"$TempDir\smoke_scan`"" -ExpectedExitCodes @(0, 2) -AllowFailure

    # Test 9: Cleanup dry-run
    Test-Command -Name "Cleanup Dry-Run" -Command "python -m trusClamAV cleanup --dry-run"

    # Clean up test directory
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Summary
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "SMOKE TEST SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $TotalTests = $TestsPassed + $TestsFailed
    Write-Host "Total Tests: $TotalTests" -ForegroundColor White
    Write-Host "Passed: $TestsPassed" -ForegroundColor Green
    Write-Host "Failed: $TestsFailed" -ForegroundColor $(if ($TestsFailed -gt 0) { "Red" } else { "Green" })
    Write-Host ""

    # Detailed results
    Write-Host "Detailed Results:" -ForegroundColor Yellow
    $TestResults | Format-Table -Property Name, Status, ExitCode, AllowFailure -AutoSize

    # Exit code
    if ($TestsFailed -gt 0) {
        Write-Host "Some tests failed!" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "All tests passed!" -ForegroundColor Green
        exit 0
    }

} catch {
    Write-Host "Smoke test encountered an error: $_" -ForegroundColor Red
    exit 1
} finally {
    Pop-Location
}
