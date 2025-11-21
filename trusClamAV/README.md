# trusClamAV

[![CI](https://github.com/trustlabupct/trusClamAV/actions/workflows/ci.yml/badge.svg)](https://github.com/trustlabupct/trusClamAV/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](#platform-compatibility)
[![ClamAV](https://img.shields.io/badge/ClamAV-1.0%2B-orange.svg)](https://www.clamav.net/)

> **Cross-platform companion that installs, diagnoses, and drives ClamAV while capturing real TXT/JSON scan reports.**

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Platform Compatibility](#platform-compatibility)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)

---

## Overview

**trusClamAV** is a production-ready Python toolkit that simplifies ClamAV deployment and operation across Linux and Windows environments. Unlike simple wrappers, trusClamAV provides:

- **Intelligent Installation:** Automatic ClamAV setup using native package managers
- **Smart Discovery:** Detects binaries, databases, and configurations with automatic fallbacks
- **Real Scanning:** Executes actual ClamAV scans (no mocks) with schema-versioned JSON reports
- **CI-Ready:** Exit codes, timeouts, and structured outputs designed for automation
- **Cross-Platform:** Unified API for Linux (apt/dnf/yum/pacman/zypper) and Windows (Chocolatey/ZIP)

**Project Information:**
- **Author:** Volodymyr Dubetskyy
- **Contact:** volodymyr.dubetskyy@upct.es
- **Institution:** Universidad Politécnica de Cartagena (UPCT)
- **Version:** 1.2
- **Last Updated:** October 14, 2025
- **GitHub:** Private repository (institutional use)

---

## Features

### Core Capabilities

- **Automated Installation**
  - Linux: `apt-get`, `dnf`, `yum`, `pacman`, `zypper` detection
  - Windows: Chocolatey or direct ZIP downloads with SHA-256 verification
  - Graceful degradation: prints manual commands when lacking permissions

- **Environment Diagnostics**
  - OS and architecture detection
  - Binary location discovery (`clamscan`, `clamdscan`, `freshclam`)
  - Database health checks (signature count, last update)
  - JSON output for automated auditing

- **Real ClamAV Scanning**
  - Support for both `clamscan` and `clamdscan` (daemon)
  - Glob-based exclusion patterns
  - Multi-target scanning
  - Dual-format reports: human-readable TXT + machine-parsable JSON

- **Schema-Versioned Reports**
  - Consistent JSON structure (v1.0) for reliable parsing
  - Includes: timestamp, tool version, ClamAV version, scan statistics, infected files
  - Exit codes: 0 (clean), 1 (infected), 2 (error/timeout/cancelled)

- **Database Management**
  - Automatic `freshclam` updates with retry logic
  - Conflict detection (stops auto-updaters to avoid locks)
  - Signature verification and fallback handling

- **Cleanup Operations**
  - Log rotation and report archival
  - Selective database purging
  - Dry-run mode for safe previews

- **Flexible Configuration**
  - CLI arguments, environment variables, and config files (JSON/YAML)
  - Precedence: CLI > env > config file > defaults
  - Per-command and global options

---

## Platform Compatibility

| Platform | Versions | Package Managers | Status |
|----------|----------|------------------|--------|
| **Ubuntu/Debian** | 20.04+, 11+ | `apt-get` | Fully Tested |
| **Red Hat/CentOS/Rocky** | 8+, 9+ | `dnf`, `yum` | Fully Tested |
| **Fedora** | 35+ | `dnf` | Supported |
| **Arch Linux** | Rolling | `pacman` | Supported |
| **openSUSE** | Leap 15+, Tumbleweed | `zypper` | Supported |
| **Windows 10/11** | 21H2+ | Chocolatey, ZIP | Fully Tested |
| **Windows Server** | 2019+ | Chocolatey, ZIP | Supported |

### Python Compatibility

- **Minimum:** Python 3.8
- **Recommended:** Python 3.10+
- **Tested:** Python 3.8, 3.9, 3.10, 3.11, 3.12

### ClamAV Compatibility

- **Minimum:** ClamAV 1.0.0
- **Recommended:** ClamAV 1.4.0+
- **Tested:** ClamAV 1.2.x, 1.3.x, 1.4.x

---

## Prerequisites

### Linux

```bash
# Python 3.8+ with pip
python3 --version  # Should be 3.8 or higher

# Optional: jq for JSON parsing
sudo apt-get install jq  # Debian/Ubuntu
sudo dnf install jq      # Fedora/RHEL
```

### Windows

```powershell
# Python 3.8+ from python.org or Microsoft Store
python --version  # Should be 3.8 or higher

# Optional: Chocolatey (for automated ClamAV installation)
# See installation steps below
```

### System Requirements

- **Disk Space:** 500 MB minimum (for ClamAV + virus databases)
- **RAM:** 512 MB minimum (2 GB recommended for large scans)
- **Network:** Internet access for database updates

---

## Installation

### Install trusClamAV

#### Option 1: From Source (Development)

```bash
# Clone repository (if you have access)
git clone https://github.com/trustlabupct/trusClamAV.git
cd trusClamAV

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate  # Windows

# Install in development mode
pip install -e .
```

#### Option 2: Direct Installation

```bash
# Install from local directory
pip install /path/to/trusClamAV

# Or from wheel/sdist
pip install trusClamAV-1.2-py3-none-any.whl
```

#### Option 3: System-Wide (Linux)

```bash
# Install for all users
sudo pip3 install /path/to/trusClamAV

# Verify installation
python3 -m trusClamAV --help
```

### Install ClamAV (Using trusClamAV)

#### Linux

```bash
# Check current state
python3 -m trusClamAV doctor

# Install ClamAV (requires sudo)
sudo python3 -m trusClamAV install

# Update virus database
sudo python3 -m trusClamAV update
```

#### Windows (Administrator PowerShell)

```powershell
# Check current state
python -m trusClamAV doctor

# Install ClamAV via Chocolatey
python -m trusClamAV install

# Update virus database
python -m trusClamAV update
```

### Manual ClamAV Installation

If automated installation fails, use native package managers:

#### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y clamav clamav-daemon
```

#### Linux (Red Hat/Fedora)
```bash
sudo dnf install -y clamav clamav-update clamd
```

#### Windows (Chocolatey)
```powershell
choco install clamav -y
```

---

## Quick Start

### Linux Example

```bash
# 1. Verify environment
python3 -m trusClamAV doctor

# 2. Install ClamAV (if needed)
sudo apt-get update && sudo apt-get install -y clamav clamav-daemon

# 3. Update virus database
sudo systemctl stop clamav-freshclam  # Prevent lock conflicts
sudo freshclam
# OR use trusClamAV
sudo python3 -m trusClamAV update

# 4. Scan test directories
python3 -m trusClamAV scan \
  --targets examples/linux/clean \
  --out examples/linux/clean_scan

python3 -m trusClamAV scan \
  --targets examples/linux/eicar \
  --out examples/linux/eicar_scan

# 5. View results
cat examples/linux/clean_scan.txt
cat examples/linux/eicar_scan.json | jq '.'
```

### Windows Example

```powershell
# 1. Verify environment
python -m trusClamAV doctor

# 2. Install ClamAV (elevated PowerShell)
if (-not (Get-Command clamscan.exe -ErrorAction SilentlyContinue)) {
  python -m trusClamAV install
}

# 3. Update database
freshclam.exe
# OR use trusClamAV
python -m trusClamAV update

# 4. Scan test directories
python -m trusClamAV scan `
  --targets examples\windows\clean `
  --out examples\windows\clean_scan

python -m trusClamAV scan `
  --targets examples\windows\eicar `
  --out examples\windows\eicar_scan

# 5. View results
Get-Content examples\windows\clean_scan.txt
Get-Content examples\windows\eicar_scan.json | ConvertFrom-Json
```

### Test with EICAR

```bash
# Download EICAR test file (harmless malware test signature)
curl -o /tmp/eicar.txt https://secure.eicar.org/eicar.com.txt

# Scan it
python3 -m trusClamAV scan --targets /tmp/eicar.txt --out /tmp/eicar_test

# Check exit code
echo $?  # Should be 1 (infected)

# View detection
cat /tmp/eicar_test.json | jq '.infected_files'
```

---

## Command Reference

### Global Options

Place **before** the subcommand:

```bash
python -m trusClamAV [GLOBAL_OPTIONS] <command> [COMMAND_OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--config PATH` | Load settings from JSON/YAML file |
| `--log-file PATH` | Override log destination |
| `--log-level {DEBUG,INFO,WARNING,ERROR}` | Set verbosity (default: INFO) |
| `--timeout SECONDS` | Operation timeout (default: 300) |
| `--quiet` | Suppress console output |
| `--dry-run` | Preview without executing |
| `--clamav-dir PATH` | Hint for binary location |
| `--db-dir PATH` | Force database directory |

### Commands

| Command | Purpose | Exit Codes |
|---------|---------|------------|
| `doctor [--json]` | Inspect environment | 0 |
| `install [--zip-url URL] [--sha256 HASH]` | Install ClamAV | 0 (success), 2 (error) |
| `update [--retries N]` | Update virus database | 0 (success), 2 (error) |
| `scan --targets PATH [...] [options]` | Run malware scan | 0 (clean), 1 (infected), 2 (error) |
| `cleanup [--purge-db-dir PATH]` | Remove cached files | 0 |

### Detailed Usage

See [USAGE.md](USAGE.md) for comprehensive documentation, examples, and CI/CD patterns.

---

## Examples

### Example 1: Basic Home Directory Scan

```bash
python3 -m trusClamAV scan \
  --targets ~/Downloads ~/Documents \
  --exclude "*.log" "*.cache" \
  --out ~/scans/home_scan
```

### Example 2: Web Server Scanning

```bash
python3 -m trusClamAV scan \
  --targets /var/www/html /var/www/uploads \
  --exclude "cache/*" "logs/*" "*.tmp" \
  --use-clamd \
  --out /var/log/clamav/web_scan_$(date +%Y%m%d)
```

### Example 3: Quiet Cron Job

```bash
# Add to crontab
0 2 * * * /usr/bin/python3 -m trusClamAV --quiet scan --targets /data --out /var/log/scans/daily_$(date +\%Y\%m\%d)
```

### Example 4: CI Pipeline Integration

```bash
#!/bin/bash
# security_scan.sh

set -e

echo "Updating ClamAV database..."
python3 -m trusClamAV update

echo "Scanning build artifacts..."
python3 -m trusClamAV scan \
  --targets ./dist ./build \
  --exclude "*.log" \
  --out ./scan_results

EXIT_CODE=$?

if [ $EXIT_CODE -eq 1 ]; then
  echo "ERROR: Malware detected!"
  cat ./scan_results.json | jq '.infected_files'
  exit 1
elif [ $EXIT_CODE -eq 2 ]; then
  echo "ERROR: Scan failed"
  exit 1
fi

echo "Scan completed successfully - no threats detected"
exit 0
```

### Example 5: Limit Size and Whitelist Extensions

```bash
python3 -m trusClamAV scan \
  --targets ~/shared_drive ~/inbox \
  --include-ext .pdf .docx .pptx \
  --max-filesize 25M \
  --use-clamd \
  --out ~/scans/documents_only
```

This scan ignores everything except Office/PDF files and skips attachments above 25 MB so the daemon stays fast while still covering the high-risk formats.

### Example 5: JSON Parsing

```bash
# Scan and parse results
python3 -m trusClamAV scan --targets /tmp --out scan1 --format json

# Extract information
INFECTED_COUNT=$(jq -r '.infected_count' scan1.json)
STATUS=$(jq -r '.status' scan1.json)
ELAPSED=$(jq -r '.elapsed_seconds' scan1.json)

echo "Status: $STATUS"
echo "Files scanned: $(jq -r '.files_scanned' scan1.json)"
echo "Infected: $INFECTED_COUNT"
echo "Duration: ${ELAPSED}s"

# List infected files
if [ "$INFECTED_COUNT" -gt 0 ]; then
  echo "Infected files:"
  jq -r '.infected_files[] | "\(.path) - \(.signature)"' scan1.json
fi
```

---

## Troubleshooting

### Issue: ClamAV not found after installation

```bash
# Verify PATH
which clamscan  # Linux
where clamscan  # Windows

# Manual hint
python3 -m trusClamAV --clamav-dir /usr/local/bin doctor
```

### Issue: Database update fails with "locked"

```bash
# Stop auto-updater
sudo systemctl stop clamav-freshclam

# Update manually
sudo freshclam

# Restart service
sudo systemctl start clamav-freshclam
```

### Issue: Permission denied

```bash
# Use sudo for system operations
sudo python3 -m trusClamAV install
sudo python3 -m trusClamAV update

# Or use user directories
python3 -m trusClamAV --log-file ~/trusClamAV.log scan --targets ~/Downloads
```

### Issue: Scan timeout on large directories

```bash
# Increase timeout
python3 -m trusClamAV --timeout 3600 scan --targets /large/directory

# Use daemon for better performance
python3 -m trusClamAV scan --targets /large/directory --use-clamd
```

For more troubleshooting, see [USAGE.md](USAGE.md#troubleshooting).

---

## FAQ

### Q: Does trusClamAV work offline?

**A:** Yes, once ClamAV and virus databases are installed. Database updates require internet access.

### Q: How often should I update the virus database?

**A:** Daily updates are recommended. Set up a cron job:
```bash
0 3 * * * /usr/bin/python3 -m trusClamAV --quiet update
```

### Q: Can I scan network drives?

**A:** Yes, mount the network drive and scan it like any local path:
```bash
python3 -m trusClamAV scan --targets /mnt/network_share
```

### Q: What's the difference between `clamscan` and `clamdscan`?

**A:**
- `clamscan`: Standalone scanner, loads database each time (slower)
- `clamdscan`: Daemon client, uses persistent in-memory database (2-5x faster)

Use `--use-clamd` for repeated scans.

### Q: How do I integrate with Slack/email notifications?

**A:** Parse the JSON output and use your notification tool:
```bash
python3 -m trusClamAV scan --targets /data --out scan1
if [ $? -eq 1 ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"Malware detected: $(jq -r '.infected_count' scan1.json) files\"}" \
    YOUR_SLACK_WEBHOOK_URL
fi
```

### Q: Can I customize the scan report format?

**A:** The JSON schema is fixed for consistency, but you can post-process it:
```bash
# Convert to CSV
jq -r '.infected_files[] | [.path, .signature] | @csv' scan1.json > report.csv
```

### Q: Does it support other antivirus engines?

**A:** No, trusClamAV is specifically designed for ClamAV. For multi-engine scanning, consider calling trusClamAV alongside other tools.

### Q: How do I exclude entire directories?

**A:** Use glob patterns:
```bash
python3 -m trusClamAV scan \
  --targets /var \
  --exclude "/var/log/*" "/var/cache/*" "*.log"
```

---

## Contributing

### Development Setup

```bash
# Clone repository
git clone https://github.com/trustlabupct/trusClamAV.git
cd trusClamAV

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -e .[dev]

# Run tests
pytest tests/ -v

# Run linters
flake8 .
black --check .
mypy .
```

### Testing

```bash
# Unit tests
pytest tests/test_backend.py

# Integration tests
pytest tests/test_integration_scan.py

# Coverage report
pytest --cov=trusClamAV --cov-report=html
```

### Code Style

- **Formatter:** Black (line length: 100)
- **Linter:** Flake8
- **Type Hints:** mypy
- **Docstrings:** Google style

### Submitting Changes

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Write tests for new functionality
3. Ensure all tests pass: `pytest`
4. Format code: `black .`
5. Commit with clear messages
6. Submit pull request with description

### Reporting Issues

Include the following in bug reports:
1. Output of `python -m trusClamAV doctor --json`
2. Command that failed
3. Complete error message
4. Operating system and Python version

---

## Support

**Primary Contact:**
- **Email:** volodymyr.dubetskyy@upct.es
- **Institution:** Universidad Politécnica de Cartagena (UPCT)

**Documentation:**
- [USAGE.md](USAGE.md) - Comprehensive usage guide
- [examples/](examples/) - Sample outputs and test files

**Bug Reports:**
Please include `doctor --json` output and complete error messages.

---

## License

Copyright © 2025 Volodymyr Dubetskyy, Universidad Politécnica de Cartagena

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **ClamAV Team** - For the excellent open-source antivirus engine
- **Universidad Politécnica de Cartagena** - For institutional support
- **Contributors** - For testing and feedback

---

**Built with care for secure software development**

*Last updated: October 14, 2025 • Version 1.2*
