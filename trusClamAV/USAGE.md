# trusClamAV Usage Guide

**Author:** Volodymyr Dubetskyy
**Last Updated:** October 14, 2025
**Version:** 1.2

---

## Table of Contents

1. [Global Syntax](#global-syntax)
2. [Global Options](#global-options)
3. [Environment Variables](#environment-variables)
4. [Configuration Files](#configuration-files)
5. [Commands Reference](#commands-reference)
   - [doctor](#doctor)
   - [install](#install)
   - [update](#update)
   - [scan](#scan)
   - [cleanup](#cleanup)
6. [JSON Report Schema](#json-report-schema-v1)
7. [Advanced Usage Examples](#advanced-usage-examples)
8. [CI/CD Integration Patterns](#cicd-integration-patterns)
9. [Troubleshooting](#troubleshooting)
10. [Performance Tips](#performance-tips)

---

## Global Syntax

```
python -m trusClamAV [GLOBAL OPTIONS] <command> [COMMAND OPTIONS]
```

**Important:** Global options must be placed **before** the subcommand.

### Example

```bash
# Correct
python -m trusClamAV --quiet --timeout 300 scan --targets /home/user/Downloads

# Incorrect - global flags after command won't work
python -m trusClamAV scan --targets /home/user/Downloads --quiet
```

---

## Global Options

Place these flags before the subcommand to control overall behavior:

| Flag | Type | Purpose | Default |
| --- | --- | --- | --- |
| `--config PATH` | Path | Load settings from JSON/YAML file | Auto-detect |
| `--log-file PATH` | Path | Override rotating log destination | Platform-specific |
| `--log-level LEVEL` | Choice | Control verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` |
| `--timeout SECONDS` | Integer | Default timeout for long operations | 300 |
| `--quiet` | Flag | Suppress informational console output (logs still written) | False |
| `--dry-run` | Flag | Preview actions without changing the system | False |
| `--clamav-dir PATH` | Path | Hint where ClamAV binaries are located | Auto-detect |
| `--db-dir PATH` | Path | Force a specific database directory | Auto-detect |

### Examples

```bash
# Debug mode with custom timeout
python -m trusClamAV --log-level DEBUG --timeout 600 update

# Dry-run to preview installation steps
python -m trusClamAV --dry-run install

# Use custom configuration file
python -m trusClamAV --config /etc/trusClamAV/config.yaml doctor

# Quiet mode for cron jobs
python -m trusClamAV --quiet scan --targets /var/www --out /var/log/scans/daily
```

---

## Environment Variables

Environment variables override built-in defaults but are themselves overridden by CLI arguments.

| Variable | Type | Description | Example |
| --- | --- | --- | --- |
| `TRUSCLAMAV_CLAMAV_DIR` | Path | Binary search hint | `/opt/clamav/bin` |
| `TRUSCLAMAV_DB_DIR` | Path | Database directory override | `/var/lib/clamav` |
| `TRUSCLAMAV_TARGETS` | Paths | Colon-separated scan targets | `/home:/var/www` |
| `TRUSCLAMAV_EXCLUDE` | Globs | Comma-separated exclusion patterns | `*.log,*.tmp,node_modules` |
| `TRUSCLAMAV_TIMEOUT` | Integer | Default timeout in seconds | `600` |
| `TRUSCLAMAV_LOG_LEVEL` | String | Logging verbosity | `DEBUG` |
| `TRUSCLAMAV_LOG_FILE` | Path | Custom log file location | `/var/log/trusClamAV.log` |
| `TRUSCLAMAV_USE_CLAMD` | Boolean | Prefer `clamdscan` over `clamscan` | `true` |
| `TRUSCLAMAV_DRY_RUN` | Boolean | Simulate operations | `true` |

### Configuration Precedence

**CLI arguments** > **Environment variables** > **Config file** > **Built-in defaults**

### Example Usage

```bash
# Linux/macOS
export TRUSCLAMAV_TIMEOUT=900
export TRUSCLAMAV_LOG_LEVEL=DEBUG
export TRUSCLAMAV_EXCLUDE="*.log,*.cache,__pycache__"
python3 -m trusClamAV scan --targets /opt/app

# Windows PowerShell
$env:TRUSCLAMAV_TIMEOUT = "900"
$env:TRUSCLAMAV_LOG_LEVEL = "DEBUG"
python -m trusClamAV scan --targets C:\Projects
```

---

## Configuration Files

trusClamAV supports JSON and YAML configuration files for persistent settings.

### Default Locations

- **Linux:** `${XDG_CONFIG_HOME:-$HOME/.config}/trusClamAV/config.yaml`
- **Windows:** `%APPDATA%\trusClamAV\config.yaml`

### JSON Configuration Example

```json
{
  "clamav_dir": "/usr/bin",
  "db_dir": "/var/lib/clamav",
  "log_level": "INFO",
  "log_file": "/var/log/trusClamAV/app.log",
  "timeout": 600,
  "use_clamd": true,
  "scan": {
    "targets": ["/home/user/Downloads", "/var/www"],
    "exclude": ["*.log", "*.tmp", "node_modules", ".git"],
    "output_prefix": "/var/log/scans/latest",
    "formats": ["txt", "json"]
  },
  "update": {
    "retries": 3,
    "auto_restart_daemon": true
  }
}
```

### YAML Configuration Example

```yaml
clamav_dir: /usr/bin
db_dir: /var/lib/clamav
log_level: INFO
log_file: /var/log/trusClamAV/app.log
timeout: 600
use_clamd: true

scan:
  targets:
    - /home/user/Downloads
    - /var/www
  exclude:
    - "*.log"
    - "*.tmp"
    - node_modules
    - .git
  output_prefix: /var/log/scans/latest
  formats:
    - txt
    - json

update:
  retries: 3
  auto_restart_daemon: true
```

### Using Custom Config Files

```bash
# Specify config file explicitly
python -m trusClamAV --config /etc/trusClamAV/production.yaml scan --targets /data

# Validate configuration
python -m trusClamAV --config ./config.json doctor --json
```

---

## Commands Reference

### doctor

Inspect the current environment and ClamAV installation status.

#### Syntax

```
python -m trusClamAV doctor [OPTIONS]
```

#### Options

| Flag | Purpose |
| --- | --- |
| `--json` | Output structured JSON (ideal for automation) |

#### What It Reports

- Operating system and architecture
- Detected ClamAV binaries (`clamscan`, `clamdscan`, `freshclam`)
- Database location and status
- Signature count and last update time
- Configuration/log/state directory paths
- Installation hints and recommendations

#### Examples

```bash
# Human-readable diagnostic
python3 -m trusClamAV doctor

# Machine-readable output
python3 -m trusClamAV doctor --json

# Extract specific information with jq
python3 -m trusClamAV doctor --json | jq '.paths'
python3 -m trusClamAV doctor --json | jq '.clamav.versions'
python3 -m trusClamAV doctor --json | jq '.database.signature_count'

# Check if ClamAV is properly installed
python3 -m trusClamAV doctor --json | jq -e '.clamav.clamscan != null'
```

#### Sample Output (Text Mode)

```
=== trusClamAV Doctor Report ===
OS: Linux (Ubuntu 22.04)
Architecture: x86_64

ClamAV Binaries:
  clamscan: /usr/bin/clamscan (v1.4.3)
  clamdscan: /usr/bin/clamdscan (v1.4.3)
  freshclam: /usr/bin/freshclam

Database:
  Location: /var/lib/clamav
  Signatures: 8,654,321
  Last Updated: 2025-10-14 08:32:15 UTC

Paths:
  Config: /home/user/.config/trusClamAV
  Logs: /home/user/.local/state/trusClamAV/logs
  Reports: /home/user/.local/state/trusClamAV/reports

Status: [OK] Ready for scanning
```

---

### install

Install ClamAV using native package managers or direct downloads.

#### Syntax

```
python -m trusClamAV install [OPTIONS]
```

#### Options

| Flag | Type | Purpose |
| --- | --- | --- |
| `--zip-url URL` | String | Direct ZIP download URL (Windows) |
| `--sha256 HASH` | String | Verify ZIP integrity |

#### Platform Behavior

**Linux:**
- Auto-detects: `apt-get`, `dnf`, `yum`, `pacman`, `zypper`
- Requires `sudo` privileges
- Without admin rights, prints commands for manual execution
- Installs both engine and daemon packages

**Windows:**
- Prefers Chocolatey when available
- Falls back to ZIP download with `--zip-url`
- Optional SHA-256 verification with `--sha256`
- Requires elevated PowerShell for Chocolatey

#### Examples

```bash
# Linux - automatic installation
sudo python3 -m trusClamAV install

# Linux - dry-run to preview commands
python3 -m trusClamAV --dry-run install

# Windows - using Chocolatey (run as Administrator)
python -m trusClamAV install

# Windows - manual ZIP installation
python -m trusClamAV install --zip-url https://example.com/clamav-1.4.3-win-x64.zip --sha256 abc123...

# Check installation success
python -m trusClamAV doctor
```

---

### update

Refresh the ClamAV virus signature database.

#### Syntax

```
python -m trusClamAV update [OPTIONS]
```

#### Options

| Flag | Type | Purpose | Default |
| --- | --- | --- | --- |
| `--retries N` | Integer | Number of retry attempts | 3 |

#### Behavior

1. Stops conflicting auto-update services (`clamav-freshclam` on Linux)
2. Runs `freshclam` with configured timeout
3. Retries on transient failures
4. Returns success (exit code 0) if database already exists, even on update errors

#### Examples

```bash
# Standard update
python3 -m trusClamAV update

# Extended timeout with retries
python3 -m trusClamAV --timeout 900 update --retries 5

# Quiet mode for cron
python3 -m trusClamAV --quiet update

# Check update success
python3 -m trusClamAV update && echo "Database updated successfully"
```

#### Cron Integration

```bash
# Daily update at 3 AM
0 3 * * * /usr/bin/python3 -m trusClamAV --quiet --log-file /var/log/trusClamAV/update.log update
```

---

### scan

Execute a real ClamAV scan and generate comprehensive reports.

#### Syntax

```
python -m trusClamAV scan --targets PATH [PATH ...] [OPTIONS]
```

#### Required Arguments

| Argument | Description |
| --- | --- |
| `--targets PATH [...]` | One or more files/directories to scan |

#### Optional Arguments

| Flag | Type | Purpose | Default |
| --- | --- | --- | --- |
| `--exclude GLOB [...]` | Patterns | Skip matching paths | None |
| `--include REGEX [...]` | Patterns | Only scan matching files | None |
| `--include-ext EXT [...]` | Extensions | Convenience wrapper for common suffixes | None |
| `--max-filesize SIZE` | Size | Ignore files above SIZE (e.g. 50M, 200MB) | ClamAV default |
| `--max-scansize SIZE` | Size | Cap bytes scanned per file/stream | ClamAV default |
| `--out PREFIX` | String | Report filename prefix | `scan` (stored under `output/trusclamav/`) |
| `--format {txt,json}` | Choices | Report formats to generate | Both |
| `--use-clamd` | Flag | Prefer daemon scanner | `clamscan` |

#### Validation

- All target paths are validated before scanning
- Nonexistent paths raise `ClamAVScanError`
- Empty directories are allowed

#### Output Files

Reports are written beneath `output/trusclamav/` by default.  
For `--out reports/myscan` this yields:
- `output/trusclamav/reports/myscan.txt` – Human-readable report
- `output/trusclamav/reports/myscan.json` – Machine-readable (schema v1)

#### Exit Codes

| Code | Meaning | CI Action |
| --- | --- | --- |
| `0` | Clean (no threats) | [OK] Pass |
| `1` | Infected files found | [ERROR] Fail |
| `2` | Error/timeout/cancelled | [ERROR] Fail |

#### Signal Handling

- **Ctrl+C / SIGINT:** Graceful cancellation, writes report with `status: "cancelled"`, exits with code 2

#### Examples

```bash
# Basic scan
python3 -m trusClamAV scan --targets /home/user/Downloads

# Multiple targets with exclusions
python3 -m trusClamAV scan \
  --targets /var/www /home/user/Documents \
  --exclude "*.log" "*.cache" "node_modules" \
  --out /var/log/scans/daily

# JSON-only report for automation
python3 -m trusClamAV scan \
  --targets /opt/app \
  --format json \
  --out /tmp/scan_results

# Use daemon for faster scans
python3 -m trusClamAV scan \
  --targets /data \
  --use-clamd \
  --out /reports/daemon_scan

# Only scan Office/PDF documents under 25 MB
python3 -m trusClamAV scan \
  --targets /mnt/maildrop \
  --include-ext .pdf .doc .docx .xls .xlsx \
  --max-filesize 25M \
  --use-clamd \
  --out /reports/maildrop_scan

# Quiet mode with custom timeout
python3 -m trusClamAV --quiet --timeout 1800 scan \
  --targets /mnt/storage \
  --out /logs/storage_scan

# Scan EICAR test file
curl https://secure.eicar.org/eicar.com.txt > /tmp/eicar.txt
python3 -m trusClamAV scan --targets /tmp/eicar.txt --out /tmp/eicar_test
echo $?  # Should be 1 (infected)
```

---

### cleanup

Remove cached artifacts, logs, and optionally databases.

#### Syntax

```
python -m trusClamAV cleanup [OPTIONS]
```

#### Options

| Flag | Type | Purpose |
| --- | --- | --- |
| `--purge-db-dir PATH` | Path | Forcibly delete specific database directory |

#### What Gets Cleaned

- Rotating log files
- Generated scan reports (`.txt`, `.json`)
- Temporary files under state directories
- Optional: virus signature databases (with `--purge-db-dir`)

#### Safety

- Use `--dry-run` to preview deletions
- Database purge requires explicit path for safety

#### Examples

```bash
# Standard cleanup
python3 -m trusClamAV cleanup

# Preview what would be deleted
python3 -m trusClamAV --dry-run cleanup

# Remove specific database copy
python3 -m trusClamAV cleanup --purge-db-dir /tmp/clamav_test_db

# Aggressive cleanup (logs + reports + db)
python3 -m trusClamAV cleanup --purge-db-dir /var/lib/clamav
```

---

## JSON Report Schema v1

All scan reports adhere to a versioned schema for reliable parsing.

### Schema Structure

```json
{
  "schema_version": "1.0",
  "timestamp": "2025-10-14T12:34:56Z",
  "tool": {
    "name": "trusClamAV",
    "version": "1.2",
    "clamav_version": "ClamAV 1.4.3/27792/Tue Oct 14 08:32:15 2025",
    "engine": "clamscan"
  },
  "targets": ["/absolute/path/to/scan"],
  "exclusions": ["*.log", "*.tmp"],
  "files_scanned": 42,
  "infected_count": 1,
  "infected_files": [
    {
      "path": "/absolute/path/to/malware.exe",
      "signature": "Win.Trojan.Generic-12345"
    }
  ],
  "elapsed_seconds": 19.31,
  "status": "infected",
  "errors": []
}
```

### Field Definitions

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | String | Report format version (currently `"1.0"`) |
| `timestamp` | ISO-8601 | UTC scan start time |
| `tool.name` | String | Always `"trusClamAV"` |
| `tool.version` | String | trusClamAV release version |
| `tool.clamav_version` | String | ClamAV engine version string |
| `tool.engine` | String | `"clamscan"` or `"clamdscan"` |
| `targets` | Array | Absolute paths scanned |
| `exclusions` | Array | Glob patterns excluded |
| `includes` | Array | Regex patterns included (may be empty) |
| `files_scanned` | Integer | Total files examined |
| `infected_count` | Integer | Number of infected files |
| `infected_files` | Array | Details of each threat |
| `elapsed_seconds` | Float | Scan duration |
| `status` | Enum | `"clean"`, `"infected"`, `"error"`, `"cancelled"` |
| `errors` | Array | Error messages (empty on success) |

### Status Values

| Status | Meaning | Exit Code |
| --- | --- | --- |
| `clean` | No threats detected | 0 |
| `infected` | One or more threats found | 1 |
| `error` | Scan failed (timeout, missing db, etc.) | 2 |
| `cancelled` | User interrupted (Ctrl+C) | 2 |

---

## Advanced Usage Examples

### Scenario 1: Web Server Scanning

```bash
#!/bin/bash
# Scan web directories daily with detailed logging

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_PREFIX="/var/log/clamav/web_scan_${TIMESTAMP}"

python3 -m trusClamAV \
  --log-level INFO \
  --timeout 3600 \
  scan \
  --targets /var/www/html /var/www/uploads \
  --exclude "*.log" "cache/*" "tmp/*" \
  --out "${REPORT_PREFIX}"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 1 ]; then
  echo "ALERT: Malware detected!" | mail -s "ClamAV Alert" admin@example.com
  cat "${REPORT_PREFIX}.txt" | mail -s "Scan Report" security@example.com
fi

exit $EXIT_CODE
```

### Scenario 2: User Home Directory Scan

```bash
#!/bin/bash
# Scan all user home directories

for HOME_DIR in /home/*; do
  USERNAME=$(basename "$HOME_DIR")
  echo "Scanning $USERNAME..."

  python3 -m trusClamAV scan \
    --targets "$HOME_DIR" \
    --exclude ".cache" ".local/share/Trash" \
    --out "/var/log/scans/user_${USERNAME}" \
    --quiet
done
```

### Scenario 3: Network Share Monitoring

```bash
#!/bin/bash
# Monitor network shares with incremental scanning

MOUNT_POINT="/mnt/shared"
BASELINE="/var/lib/trusClamAV/baseline.txt"
CURRENT="/tmp/current_scan.txt"

# Full scan
python3 -m trusClamAV scan \
  --targets "$MOUNT_POINT" \
  --format txt \
  --out "$CURRENT"

# Compare with baseline
if [ -f "$BASELINE" ]; then
  diff "$BASELINE" "$CURRENT" > /tmp/changes.diff
  if [ -s /tmp/changes.diff ]; then
    echo "Changes detected in $MOUNT_POINT"
    cat /tmp/changes.diff | mail -s "Share Changes" admin@example.com
  fi
fi

# Update baseline
cp "$CURRENT.txt" "$BASELINE"
```

### Scenario 4: CI/CD Pipeline Integration

```yaml
# .gitlab-ci.yml example
security_scan:
  stage: test
  script:
    - python3 -m pip install /path/to/trusClamAV
    - python3 -m trusClamAV update
    - python3 -m trusClamAV scan --targets ./dist --out scan_results
  artifacts:
    when: always
    paths:
      - scan_results.txt
      - scan_results.json
    reports:
      junit: scan_results.json  # Convert if needed
  allow_failure: false
```

---

## CI/CD Integration Patterns

### GitHub Actions

```yaml
name: ClamAV Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install ClamAV
        run: |
          sudo apt-get update
          sudo apt-get install -y clamav clamav-daemon
          sudo systemctl stop clamav-freshclam

      - name: Install trusClamAV
        run: pip install -e /path/to/trusClamAV

      - name: Update virus database
        run: python -m trusClamAV update --retries 3
        timeout-minutes: 15

      - name: Scan repository
        id: scan
        run: |
          python -m trusClamAV scan \
            --targets . \
            --exclude ".git" "node_modules" "*.log" \
            --out scan_results
        continue-on-error: true

      - name: Upload scan results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: clamav-scan-results
          path: |
            scan_results.txt
            scan_results.json

      - name: Check scan status
        run: |
          STATUS=$(jq -r '.status' scan_results.json)
          if [ "$STATUS" = "infected" ]; then
            echo "::error::Malware detected!"
            exit 1
          fi
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    environment {
        SCAN_OUTPUT = "scan_${BUILD_NUMBER}"
    }

    stages {
        stage('Setup ClamAV') {
            steps {
                sh '''
                    python3 -m trusClamAV doctor --json > doctor_output.json
                    if ! jq -e '.clamav.clamscan' doctor_output.json; then
                        echo "ClamAV not found, installing..."
                        python3 -m trusClamAV install
                    fi
                '''
            }
        }

        stage('Update Database') {
            steps {
                timeout(time: 20, unit: 'MINUTES') {
                    sh 'python3 -m trusClamAV --timeout 900 update --retries 5'
                }
            }
        }

        stage('Security Scan') {
            steps {
                script {
                    def scanStatus = sh(
                        script: """
                            python3 -m trusClamAV scan \
                                --targets ${WORKSPACE} \
                                --exclude ".git" "target" "*.class" \
                                --out ${SCAN_OUTPUT}
                        """,
                        returnStatus: true
                    )

                    if (scanStatus == 1) {
                        error("Malware detected in build!")
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: "${SCAN_OUTPUT}.*", allowEmptyArchive: false

            script {
                def report = readJSON file: "${SCAN_OUTPUT}.json"
                if (report.status == 'infected') {
                    emailext(
                        subject: "Security Alert: Malware Detected in Build #${BUILD_NUMBER}",
                        body: readFile("${SCAN_OUTPUT}.txt"),
                        to: 'security@example.com'
                    )
                }
            }
        }
    }
}
```

### GitLab CI

```yaml
stages:
  - security

variables:
  SCAN_TIMEOUT: "1800"

clamav_scan:
  stage: security
  image: python:3.10
  before_script:
    - apt-get update && apt-get install -y clamav clamav-daemon
    - pip install -e /builds/path/to/trusClamAV
    - python -m trusClamAV update
  script:
    - |
      python -m trusClamAV \
        --timeout ${SCAN_TIMEOUT} \
        scan \
        --targets . \
        --exclude ".git" "venv" "__pycache__" \
        --out ${CI_PROJECT_DIR}/scan_results
  after_script:
    - |
      if [ -f scan_results.json ]; then
        STATUS=$(jq -r '.status' scan_results.json)
        INFECTED=$(jq -r '.infected_count' scan_results.json)
        echo "Scan completed with status: ${STATUS}"
        echo "Infected files: ${INFECTED}"
      fi
  artifacts:
    when: always
    paths:
      - scan_results.txt
      - scan_results.json
    expire_in: 30 days
  allow_failure: false
  only:
    - branches
    - merge_requests
```

---

## Troubleshooting

### Database Issues

**Problem:** `freshclam` fails with "Database not found"

```bash
# Solution 1: Manual freshclam run
sudo freshclam --verbose

# Solution 2: Force database directory
python3 -m trusClamAV --db-dir /var/lib/clamav update

# Solution 3: Check permissions
ls -la /var/lib/clamav
sudo chown -R clamav:clamav /var/lib/clamav
```

**Problem:** "Database is locked" error

```bash
# Stop conflicting services
sudo systemctl stop clamav-freshclam
sudo systemctl stop clamav-daemon

# Run update
python3 -m trusClamAV update

# Restart services
sudo systemctl start clamav-freshclam
sudo systemctl start clamav-daemon
```

### Permission Errors

**Problem:** Cannot write to default directories

```bash
# Check current paths
python3 -m trusClamAV doctor --json | jq '.paths'

# Use custom directories
mkdir -p ~/trusClamAV/{logs,reports,config}
python3 -m trusClamAV \
  --log-file ~/trusClamAV/logs/app.log \
  scan --targets /tmp --out ~/trusClamAV/reports/scan1
```

### Scan Failures

**Problem:** Scan times out on large directories

```bash
# Increase timeout
python3 -m trusClamAV --timeout 7200 scan --targets /large/directory

# Use daemon for better performance
sudo systemctl start clamav-daemon
python3 -m trusClamAV scan --targets /large/directory --use-clamd
```

**Problem:** Excessive memory usage

```bash
# Exclude large irrelevant files
python3 -m trusClamAV scan \
  --targets /data \
  --exclude "*.iso" "*.vmdk" "*.vdi" "*.log"
```

### Installation Issues

**Problem:** `install` command fails without sudo

```bash
# Run with sudo on Linux
sudo python3 -m trusClamAV install

# Or execute printed commands manually
python3 -m trusClamAV --dry-run install
# Then run the displayed commands with sudo
```

**Problem:** Windows Chocolatey not found

```powershell
# Install Chocolatey first (elevated PowerShell)
Set-ExecutionPolicy Bypass -Scope Process -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
iex ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Then install ClamAV
python -m trusClamAV install
```

### Report Issues

**Problem:** Cannot find generated reports

```bash
# Check active report directory
python3 -m trusClamAV doctor --json | jq -r '.paths.reports_dir'

# Use absolute path for --out
python3 -m trusClamAV scan --targets /tmp --out /var/log/clamav/scan1

# Check default report directory
ls -la output/trusclamav/scan.*
```

---

## Performance Tips

### 1. Use the ClamAV Daemon

The daemon (`clamd`) is **significantly faster** for repeated scans:

```bash
# Start daemon (Linux)
sudo systemctl start clamav-daemon

# Use daemon for scanning
python3 -m trusClamAV scan --targets /data --use-clamd
```

**Performance gain:** 2-5x faster for multiple scans.

### 2. Strategic Exclusions

Exclude known-safe and irrelevant file types:

```bash
python3 -m trusClamAV scan \
  --targets /project \
  --exclude \
    "*.log" "*.cache" "*.tmp" \
    ".git" ".svn" \
    "node_modules" "vendor" "venv" \
    "*.min.js" "*.min.css"
```

### 3. Parallel Scanning

For multiple independent targets:

```bash
# Scan directories in parallel
python3 -m trusClamAV scan --targets /data1 --out scan1 &
python3 -m trusClamAV scan --targets /data2 --out scan2 &
python3 -m trusClamAV scan --targets /data3 --out scan3 &
wait
```

### 4. Incremental Scanning

Scan only changed files using `find`:

```bash
# Scan files modified in last 24 hours
find /var/www -type f -mtime -1 > /tmp/recent_files.txt
python3 -m trusClamAV scan --targets $(cat /tmp/recent_files.txt) --out recent_scan
```

### 5. Database Optimization

Keep signatures up-to-date but avoid excessive updates:

```bash
# Update once daily (cron)
0 3 * * * /usr/bin/python3 -m trusClamAV update

# Reuse daemon's database for scans
python3 -m trusClamAV --db-dir /var/lib/clamav scan --targets /data
```

---

## Operational Notes

1. **Report Locations:** Generated reports are written next to the `--out` prefix or in the default reports directory (check with `doctor --json`).

2. **Log Rotation:** Logs automatically rotate when reaching size limits. Check log locations with `python -m trusClamAV doctor --json | jq '.paths.logs_dir'`.

3. **Fallback Directories:** If default state/config/log directories are not writable:
   - **Linux:** Falls back to `/tmp/trusClamAV`
   - **Windows:** Falls back to `%LOCALAPPDATA%\trusClamAV`

4. **Exit Codes in Automation:**
   ```bash
   python3 -m trusClamAV scan --targets /data --out scan1
   case $? in
     0) echo "Clean" ;;
     1) echo "Infected - quarantine required!" ;;
     2) echo "Error - check logs" ;;
   esac
   ```

5. **JSON Parsing in Scripts:**
   ```bash
   RESULT=$(python3 -m trusClamAV scan --targets /tmp --out scan1 --format json)
   INFECTED_COUNT=$(jq -r '.infected_count' scan1.json)

   if [ "$INFECTED_COUNT" -gt 0 ]; then
     jq -r '.infected_files[].path' scan1.json | while read FILE; do
       echo "Quarantine: $FILE"
     done
   fi
   ```

---

**For additional support, contact:** volodymyr.dubetskyy@upct.es
