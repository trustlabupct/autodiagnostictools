# trustMITRE Usage Guide

Complete reference for using trustMITRE v1.0.0 — High-performance CAR analytics engine for adversary behavior detection.

**Author:** Volodymyr Dubetskyy
**Organization:** TRUST Lab UPCT
**© 2025 TRUST Lab UPCT**

---

## Overview

trustMITRE is a high-performance CAR (Cyber Analytics Repository) analytics engine that detects adversary behaviors in security logs. It processes Sysmon events, Windows Event Logs, and other telemetry sources through MITRE CAR analytics to produce actionable detections.

**Key Capabilities:**
- Normalize logs from multiple sources (Sysmon, Windows Events, JSON, CSV)
- Execute parallel detection analytics based on MITRE CAR framework
- Generate structured detection reports in CSV and JSONL formats
- Support live Windows Sysmon collection and offline EVTX processing
- High-performance parallel processing with configurable workers and batch sizes

---

## System Requirements

### Python Version

- Python 3.11 or newer (required)

### Operating Systems

- Windows 10, Windows 11, Windows Server 2016+
- Linux: Ubuntu 20.04+, RHEL 8+, Debian 11+
- macOS: Tested on recent versions

### Permissions

- Standard user permissions for file-based log processing
- Administrator/root access required for live Windows Sysmon collection

### Optional Dependencies

- **Windows live Sysmon**: Install with `pip install ".[windows]"` (requires pywin32)
- **Offline EVTX processing**: Install with `pip install ".[offline_evtx]"` (requires python-evtx)

---

## Installation

### Linux Installation

```bash
cd trusMITRE

# Create virtual environment
python3.11 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install trustMITRE
pip install -e .

# Verify installation
trustmitre --help
```

### Windows Installation

```powershell
cd trusMITRE

# Create virtual environment
py -3.11 -m venv .venv

# Activate virtual environment
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Install trustMITRE
pip install -e .

# Verify installation
trustmitre --help
```

### Installing Optional Extras

```bash
# Windows live Sysmon and offline EVTX support
pip install -e ".[windows,offline_evtx]"

# Only Windows live Sysmon
pip install -e ".[windows]"

# Only offline EVTX processing
pip install -e ".[offline_evtx]"
```

---

## Commands Reference

### quickstart

Run the complete analytics pipeline with default settings.

#### Syntax

```bash
trustmitre quickstart [OPTIONS]
```

#### Options

- `--config FILE` - Path to configuration file

#### Behavior

Executes the following pipeline automatically:
1. Compile analytics from YAML sources
2. Ingest sample logs
3. Run detection analytics
4. Generate reports

#### Examples

```bash
# Run with defaults
trustmitre quickstart

# Use custom configuration
trustmitre quickstart --config /path/to/config.json
```

#### Output

Creates three files in the output directory:
- `detections.jsonl` - Full detection records with evidence
- `report.csv` - CSV summary for analysis
- `summary.json` - Aggregated statistics

---

### download

Fetch CAR analytics from remote repository.

#### Syntax

```bash
trustmitre download [OPTIONS]
```

#### Options

- `--force` - Force re-download even if analytics exist
- `--url URL` - Custom download URL
- `--config FILE` - Path to configuration file

#### Behavior

Downloads CAR analytics YAML files to the configured analytics directory.

#### Examples

```bash
# Download analytics
trustmitre download

# Force re-download
trustmitre download --force

# Use custom source
trustmitre download --url https://example.com/analytics.zip
```

---

### compile

Compile YAML analytics into executable analyzers.

#### Syntax

```bash
trustmitre compile [OPTIONS]
```

#### Options

- `--config FILE` - Path to configuration file
- `--analytics-dir DIR` - Source analytics directory
- `--output-dir DIR` - Compiled output directory
- `--validate` - Validate compiled analytics
- `--strict` - Fail on any compilation errors

#### Behavior

Reads YAML analytics from the analytics directory and compiles them into Python modules in the compiled directory. Required before running analytics.

#### Examples

```bash
# Compile with defaults
trustmitre compile

# Compile with custom paths
trustmitre compile --analytics-dir ./custom_analytics --output-dir ./compiled

# Compile with validation
trustmitre compile --validate --strict
```

#### Output

Creates compiled Python modules in `.compiled/` directory (default).

---

### ingest

Normalize and prepare logs for analysis.

#### Syntax

```bash
trustmitre ingest [SOURCE...] [OPTIONS]
```

#### Required Arguments

- `SOURCE` - One or more input files or directories (JSON, JSONL, CSV, EVTX)

#### Options

- `--output FILE` - Output normalized JSONL file (required)
- `--live` - Collect live Windows Sysmon events (requires Administrator)
- `--evtx FILE` - Process offline EVTX file(s)
- `--format FORMAT` - Input format hint (json, jsonl, csv, evtx)
- `--batch-size N` - Processing batch size (default: 500)
- `--workers N` - Parallel processing threads
- `--timezone TZ` - Timezone for timestamp normalization
- `--config FILE` - Configuration file path

#### Behavior

Reads logs from various sources, normalizes them to a standard JSONL format, and writes to the output file. Supports multiple input files and formats simultaneously.

#### Examples

```bash
# Ingest sample logs
trustmitre ingest samples/golden_events.jsonl --output logs/normalized.jsonl

# Ingest multiple files
trustmitre ingest file1.json file2.jsonl file3.csv --output logs/all.jsonl

# Process directory of logs
trustmitre ingest logs/raw/*.jsonl --output logs/normalized.jsonl

# Live Windows Sysmon collection (requires Administrator)
trustmitre ingest --live --output logs/live_sysmon.jsonl

# Process offline EVTX file
trustmitre ingest --evtx SecurityEvents.evtx --output logs/converted.jsonl

# Custom batch size and workers
trustmitre ingest large_file.jsonl --output normalized.jsonl --batch-size 1000 --workers 4
```

#### Input Formats

**Supported formats:**
- JSON (single object or array)
- JSONL (line-delimited JSON)
- CSV (with headers)
- EVTX (Windows Event Log, requires `offline_evtx` extra)
- Live Sysmon (Windows only, requires `windows` extra)

---

### run

Execute detection analytics on normalized logs.

#### Syntax

```bash
trustmitre run INPUT_FILE [OPTIONS]
```

#### Required Arguments

- `INPUT_FILE` - Path to normalized JSONL log file

#### Options

- `--workers N` - Number of parallel workers (default: CPU count - 1)
- `--batch-size N` - Events per processing batch (default: 500)
- `--output-dir DIR` - Directory for detection output
- `--include ANALYTIC_ID` - Include specific analytic(s) only (repeatable)
- `--exclude ANALYTIC_ID` - Exclude specific analytic(s) (repeatable)
- `--memory-limit MB` - Maximum memory usage per worker
- `--timeout SECONDS` - Maximum execution time
- `--config FILE` - Configuration file path

#### Behavior

Loads compiled analytics and executes them against normalized log files in parallel. Produces detection records for matching events.

#### Examples

```bash
# Run with defaults
trustmitre run logs/normalized.jsonl

# Custom workers and batch size
trustmitre run logs/normalized.jsonl --workers 8 --batch-size 1000

# Include specific analytics only
trustmitre run logs/normalized.jsonl --include CAR-2021-01-001 --include CAR-2021-01-002

# Exclude specific analytics
trustmitre run logs/normalized.jsonl --exclude CAR-2020-11-008

# Combine filters
trustmitre run logs/normalized.jsonl --workers 4 --include CAR-2021-01-001 --exclude CAR-2020-11-008

# Custom output directory
trustmitre run logs/normalized.jsonl --output-dir /data/detections

# With memory and timeout limits
trustmitre run logs/normalized.jsonl --memory-limit 2048 --timeout 3600
```

#### Output

Creates `detections.jsonl` in the output directory containing all detection records.

#### Performance Tuning

**Workers:**
- More workers = faster processing but higher CPU usage
- Default: CPU count - 1
- Recommended: 2-8 depending on system resources
- For low-memory systems: Use 2-4 workers

**Batch Size:**
- Larger batches = more memory but better throughput
- Default: 500 events per batch
- High-memory systems: 1000-2000
- Low-memory systems: 100-200

---

### report

Generate summary reports from detection results.

#### Syntax

```bash
trustmitre report [OPTIONS]
```

#### Options

- `--config FILE` - Configuration file path
- `--detections-file FILE` - Input detections JSONL file
- `--output-dir DIR` - Report output directory
- `--format FORMAT` - Report format: csv, json, html (default: csv,json)
- `--include-stats` - Include statistical summary
- `--group-by FIELD` - Group detections by field (host, analytic_id, severity)

#### Behavior

Reads detection records and generates formatted reports with summaries and statistics.

#### Examples

```bash
# Generate default reports (CSV + JSON)
trustmitre report

# Custom detections file
trustmitre report --detections-file /data/detections.jsonl

# Specific format
trustmitre report --format csv

# Multiple formats
trustmitre report --format csv,json,html

# With statistics and grouping
trustmitre report --include-stats --group-by analytic_id
```

#### Output Files

- `report.csv` - CSV summary with one row per detection
- `summary.json` - Aggregated statistics and counts
- `report.html` - Interactive HTML report (if requested)

---

### validate-config

Validate and display resolved configuration.

#### Syntax

```bash
trustmitre validate-config [OPTIONS]
```

#### Options

- `--config FILE` - Configuration file to validate

#### Behavior

Reads configuration from all sources (file, environment, defaults), resolves values, and displays the final configuration. Validates for errors and conflicts.

#### Examples

```bash
# Validate default configuration
trustmitre validate-config

# Validate custom configuration
trustmitre validate-config --config /path/to/config.json
```

#### Output

Displays resolved configuration as JSON with validation status.

---

### schema

Display detection record schema.

#### Syntax

```bash
trustmitre schema
```

#### Behavior

Prints the JSON schema for detection records, showing required fields, data types, and structure.

#### Example

```bash
trustmitre schema
```

---

### clean

Remove generated artifacts and temporary files.

#### Syntax

```bash
trustmitre clean [OPTIONS]
```

#### Options

- `--config FILE` - Configuration file path
- `--all` - Remove all generated files including downloads
- `--compiled` - Remove compiled analytics only
- `--output` - Remove output files only
- `--logs` - Remove normalized logs only
- `--dry-run` - Show what would be deleted without deleting

#### Behavior

Removes generated files to clean up workspace. Use with caution.

#### Examples

```bash
# Remove all generated files
trustmitre clean --all

# Remove compiled analytics only
trustmitre clean --compiled

# Remove output files only
trustmitre clean --output

# Preview deletions
trustmitre clean --all --dry-run
```

---

### list-analytics

List available analytics.

#### Syntax

```bash
trustmitre list-analytics [OPTIONS]
```

#### Options

- `--config FILE` - Configuration file path
- `--verbose` - Show detailed information
- `--filter PATTERN` - Filter by ID pattern

#### Examples

```bash
# List all analytics
trustmitre list-analytics

# Detailed listing
trustmitre list-analytics --verbose

# Filter by pattern
trustmitre list-analytics --filter "CAR-2021*"
```

---

## Configuration

### Configuration File Locations

trustMITRE checks for configuration in the following order:

1. Command-line `--config` argument
2. Environment variable `TRUSTMITRE_CONFIG`
3. Platform-specific default locations:
   - **Linux/macOS**: `~/.config/trustmitre/config.json`
   - **Windows**: `%PROGRAMDATA%\trustmitre\config.json`
4. Project directory: `./config.json`

### Configuration File Format

Configuration files use JSON or YAML format.

#### JSON Example

```json
{
  "analytics_dir": "./analytics",
  "compiled_dir": "./.compiled",
  "logs_dir": "./logs",
  "output_dir": "./output",
  "download_url": null,
  "workers": 4,
  "batch_size": 500,
  "timezone": null,
  "memory_limit_mb": 2048,
  "timeout_seconds": 3600
}
```

#### YAML Example

```yaml
analytics_dir: ./analytics
compiled_dir: ./.compiled
logs_dir: ./logs
output_dir: ./output
download_url: null
workers: 4
batch_size: 500
timezone: null
memory_limit_mb: 2048
timeout_seconds: 3600
```

### Configuration Fields

#### analytics_dir
- **Type:** String (path)
- **Default:** `./analytics`
- **Description:** Directory containing YAML analytics definitions

#### compiled_dir
- **Type:** String (path)
- **Default:** `./.compiled`
- **Description:** Directory for compiled analytics modules

#### logs_dir
- **Type:** String (path)
- **Default:** `./logs`
- **Description:** Directory for normalized log files

#### output_dir
- **Type:** String (path)
- **Default:** `./output`
- **Description:** Directory for detection results and reports

#### download_url
- **Type:** String (URL) or null
- **Default:** null
- **Description:** Custom URL for downloading analytics

#### workers
- **Type:** Integer
- **Default:** CPU count - 1
- **Description:** Number of parallel processing workers

#### batch_size
- **Type:** Integer
- **Default:** 500
- **Description:** Number of events per processing batch

#### timezone
- **Type:** String or null
- **Default:** null
- **Description:** Timezone for timestamp normalization (e.g., "UTC", "America/New_York")

#### memory_limit_mb
- **Type:** Integer or null
- **Default:** null
- **Description:** Maximum memory per worker in megabytes

#### timeout_seconds
- **Type:** Integer or null
- **Default:** null
- **Description:** Maximum execution time for analytics

---

### Environment Variables

Override any configuration value using environment variables with the `TRUSTMITRE_` prefix.

**Format:** `TRUSTMITRE_<FIELD_NAME>`

**Examples:**

```bash
# Set workers
export TRUSTMITRE_WORKERS=8

# Set batch size
export TRUSTMITRE_BATCH_SIZE=1000

# Set output directory
export TRUSTMITRE_OUTPUT_DIR=/data/detections

# Set timezone
export TRUSTMITRE_TIMEZONE=UTC

# Set configuration file
export TRUSTMITRE_CONFIG=/etc/trustmitre/config.json
```

### Configuration Precedence

Configuration values are resolved in the following order (highest priority first):

1. Command-line arguments
2. Environment variables
3. Configuration file
4. Built-in defaults

---

## Detection Record Schema

Detection records are written in JSONL format with the following structure:

### Fields

#### analytic_id
- **Type:** String
- **Required:** Yes
- **Description:** CAR analytic identifier (e.g., "CAR-2013-02-003")

#### title
- **Type:** String
- **Required:** Yes
- **Description:** Human-readable detection title

#### log_type
- **Type:** String
- **Required:** Yes
- **Description:** Type of log that triggered detection (e.g., "process", "network", "file")

#### time_generated
- **Type:** String (ISO 8601)
- **Required:** Yes
- **Description:** Timestamp when the event occurred

#### host
- **Type:** String
- **Required:** Yes
- **Description:** Host where the event occurred

#### details
- **Type:** Object
- **Required:** Yes
- **Description:** Original event subset that triggered detection

#### evidence
- **Type:** Object
- **Required:** Yes
- **Description:** Fields used in detection logic

#### severity
- **Type:** String
- **Required:** Yes
- **Description:** Severity level: low, medium, high, critical

#### version
- **Type:** String
- **Required:** Yes
- **Description:** Schema version

### Example Detection Record

```json
{
  "analytic_id": "CAR-2013-02-003",
  "title": "Processes Spawning cmd.exe",
  "log_type": "process",
  "time_generated": "2025-10-15T10:00:00+00:00",
  "host": "lab-host",
  "details": {
    "original_subset": {
      "time_generated": "2025-10-15T10:00:00+00:00",
      "host": "lab-host",
      "log_type": "process",
      "event_type": "Process:Create",
      "exe": "C:\\Windows\\System32\\cmd.exe",
      "command_line": "cmd.exe /c whoami",
      "parent_exe": "C:\\Windows\\explorer.exe",
      "severity": "medium"
    }
  },
  "evidence": {
    "fields_used": [
      "command_line",
      "event_type",
      "exe",
      "host",
      "log_type",
      "severity",
      "time_generated"
    ]
  },
  "severity": "medium",
  "version": "1.0"
}
```

---

## Common Workflows

### Complete Pipeline from Scratch

```bash
# 1. Compile analytics
trustmitre compile

# 2. Ingest sample logs
trustmitre ingest samples/golden_events.jsonl --output logs/normalized.jsonl

# 3. Run detections
trustmitre run logs/normalized.jsonl --workers 2 --batch-size 200

# 4. Generate report
trustmitre report

# 5. View results
ls -la output/
cat output/report.csv
```

---

### Windows Live Sysmon Monitoring

Requires Administrator privileges and Windows extras installed.

```powershell
# Ensure running as Administrator
# Collect live events for 60 seconds
trustmitre ingest --live --output logs/live_sysmon.jsonl

# Run analytics
trustmitre run logs/live_sysmon.jsonl --workers 4

# Generate report
trustmitre report

# View detections
type output\report.csv
```

---

### Processing Historical Windows Event Logs

Requires offline_evtx extras installed.

```bash
# Export EVTX from Windows system first
# Then process the EVTX file
trustmitre ingest --evtx SecurityEvents.evtx --output logs/converted.jsonl

# Run analytics
trustmitre run logs/converted.jsonl

# Generate report
trustmitre report
```

---

### Batch Processing Multiple Log Sources

```bash
# Ingest multiple files at once
trustmitre ingest \
  logs/source1/*.jsonl \
  logs/source2/*.json \
  logs/source3/*.csv \
  --output logs/all_normalized.jsonl \
  --batch-size 1000

# Run with optimized settings
trustmitre run logs/all_normalized.jsonl \
  --workers 8 \
  --batch-size 1000

# Generate report
trustmitre report
```

---

### Targeted Detection with Filters

```bash
# Run only specific analytics
trustmitre run logs/normalized.jsonl \
  --include CAR-2021-01-001 \
  --include CAR-2021-01-002 \
  --include CAR-2021-01-003

# Exclude problematic analytics
trustmitre run logs/normalized.jsonl \
  --exclude CAR-2020-11-008 \
  --exclude CAR-2019-07-002

# Combine inclusion and exclusion
trustmitre run logs/normalized.jsonl \
  --include CAR-2021* \
  --exclude CAR-2021-01-005
```

---

### Continuous Monitoring Setup

```bash
#!/bin/bash
# monitor.sh - Continuous monitoring script

while true; do
  # Collect logs
  trustmitre ingest /var/log/security/*.jsonl \
    --output logs/current_$(date +%Y%m%d_%H%M%S).jsonl

  # Run analytics
  trustmitre run logs/current_*.jsonl --workers 4

  # Generate report
  trustmitre report

  # Archive old detections
  mv output/detections.jsonl archive/detections_$(date +%Y%m%d_%H%M%S).jsonl

  # Wait before next cycle
  sleep 300
done
```

---

## Performance Optimization

### Worker Configuration

**Low-end systems (2-4 cores):**
```bash
trustmitre run logs/normalized.jsonl --workers 2 --batch-size 200
```

**Mid-range systems (4-8 cores):**
```bash
trustmitre run logs/normalized.jsonl --workers 4 --batch-size 500
```

**High-end systems (8+ cores):**
```bash
trustmitre run logs/normalized.jsonl --workers 8 --batch-size 1000
```

**Server-class systems (16+ cores):**
```bash
trustmitre run logs/normalized.jsonl --workers 16 --batch-size 2000
```

---

### Memory Optimization

**Low memory (4GB or less):**
```bash
trustmitre run logs/normalized.jsonl \
  --workers 2 \
  --batch-size 100 \
  --memory-limit 512
```

**Standard memory (8GB):**
```bash
trustmitre run logs/normalized.jsonl \
  --workers 4 \
  --batch-size 500 \
  --memory-limit 1024
```

**High memory (16GB+):**
```bash
trustmitre run logs/normalized.jsonl \
  --workers 8 \
  --batch-size 2000 \
  --memory-limit 2048
```

---

### Processing Large Log Files

For log files larger than 1GB:

```bash
# Split into chunks first
split -l 100000 large_file.jsonl chunk_

# Process chunks in parallel
for chunk in chunk_*; do
  trustmitre run "$chunk" --workers 4 --batch-size 1000 &
done
wait

# Combine results
cat output/detections_*.jsonl > output/all_detections.jsonl
```

---

## Troubleshooting

### Installation Issues

#### Command Not Found

**Issue:** `trustmitre: command not found`

**Solution:**
```bash
# Reactivate virtual environment
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\Activate.ps1  # Windows
```

---

#### Missing Windows Dependencies

**Issue:** `ModuleNotFoundError: No module named 'win32evtlog'`

**Solution:**
```bash
pip install -e ".[windows]"
```

---

#### Missing EVTX Dependencies

**Issue:** `RuntimeError: python-evtx is required`

**Solution:**
```bash
pip install -e ".[offline_evtx]"
```

---

### Runtime Issues

#### No Compiled Analyzers

**Issue:** `No compiled analyzers found`

**Solution:**
```bash
# Compile analytics first
trustmitre compile

# Verify compilation
ls -la .compiled/
```

---

#### Empty Detection Output

**Issue:** Analytics run but no detections generated

**Possible Causes:**
1. Input logs don't match analytic criteria
2. Analytics not compiled
3. Filters excluding all analytics
4. Input file empty or malformed

**Solutions:**
```bash
# Verify input file has events
wc -l logs/normalized.jsonl

# Check compiled analytics exist
ls -la .compiled/

# List available analytics
trustmitre list-analytics

# Run without filters
trustmitre run logs/normalized.jsonl --workers 2

# Validate configuration
trustmitre validate-config
```

---

#### Access Denied on Windows

**Issue:** `Access denied` when collecting live Sysmon

**Solution:**
Run PowerShell as Administrator:
```powershell
# Right-click PowerShell > Run as Administrator
.venv\Scripts\Activate.ps1
trustmitre ingest --live --output logs/live.jsonl
```

---

#### High Memory Usage

**Issue:** Process consuming excessive memory

**Solutions:**
```bash
# Reduce batch size
trustmitre run logs/normalized.jsonl --batch-size 100

# Reduce workers
trustmitre run logs/normalized.jsonl --workers 2

# Set memory limit
trustmitre run logs/normalized.jsonl --memory-limit 1024

# Process in smaller chunks
split -l 50000 large_file.jsonl chunk_
```

---

#### Slow Performance

**Issue:** Processing takes too long

**Solutions:**
```bash
# Increase workers (if CPU allows)
trustmitre run logs/normalized.jsonl --workers 8

# Increase batch size (if memory allows)
trustmitre run logs/normalized.jsonl --batch-size 2000

# Use specific analytics only
trustmitre run logs/normalized.jsonl --include CAR-2021-01-001

# Check system resources
top  # Linux
Get-Process  # Windows
```

---

#### Non-Deterministic Results

**Issue:** Different detection counts on repeated runs

**Causes:**
- Different input files
- System timezone changes
- Parallel processing race conditions

**Solutions:**
```bash
# Ensure consistent timezone
export TRUSTMITRE_TIMEZONE=UTC

# Use single worker for determinism
trustmitre run logs/normalized.jsonl --workers 1

# Verify input file integrity
sha256sum logs/normalized.jsonl
```

---

### Data Issues

#### Invalid Log Format

**Issue:** Ingestion fails with format errors

**Solutions:**
```bash
# Specify format explicitly
trustmitre ingest file.log --format jsonl --output normalized.jsonl

# Validate JSON syntax
jq . file.json

# Check for malformed lines
grep -v '^{' file.jsonl
```

---

#### Missing Required Fields

**Issue:** Normalized logs missing required fields

**Solution:**
Check log schema and ensure source logs contain:
- timestamp
- host
- event_type
- log_type

---

#### Timezone Issues

**Issue:** Timestamp inconsistencies

**Solutions:**
```bash
# Set explicit timezone
export TRUSTMITRE_TIMEZONE=UTC
trustmitre ingest logs/file.jsonl --output normalized.jsonl

# Or in config file
{
  "timezone": "UTC"
}
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: trustMITRE Security Analytics

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 2 * * *'

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install trustMITRE
        run: |
          pip install -r trusMITRE/requirements.txt
          pip install -e trusMITRE/

      - name: Compile analytics
        run: trustmitre compile

      - name: Process logs
        run: |
          trustmitre ingest logs/*.jsonl --output normalized.jsonl
          trustmitre run normalized.jsonl --workers 2
          trustmitre report

      - name: Upload results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: detection-results
          path: output/

      - name: Check for critical detections
        run: |
          if grep -q '"severity": "critical"' output/detections.jsonl; then
            echo "Critical detections found!"
            exit 1
          fi
```

---

### GitLab CI

```yaml
stages:
  - analyze

variables:
  TRUSTMITRE_WORKERS: "2"
  TRUSTMITRE_BATCH_SIZE: "500"

security_analytics:
  stage: analyze
  image: python:3.11
  before_script:
    - pip install -r trusMITRE/requirements.txt
    - pip install -e trusMITRE/
  script:
    - trustmitre compile
    - trustmitre ingest logs/*.jsonl --output normalized.jsonl
    - trustmitre run normalized.jsonl
    - trustmitre report
  artifacts:
    when: always
    paths:
      - output/
    expire_in: 30 days
  allow_failure: false
```

---

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    environment {
        TRUSTMITRE_WORKERS = '4'
        TRUSTMITRE_BATCH_SIZE = '1000'
    }

    stages {
        stage('Setup') {
            steps {
                sh '''
                    python3.11 -m venv .venv
                    . .venv/bin/activate
                    pip install -r trusMITRE/requirements.txt
                    pip install -e trusMITRE/
                '''
            }
        }

        stage('Compile Analytics') {
            steps {
                sh '''
                    . .venv/bin/activate
                    trustmitre compile
                '''
            }
        }

        stage('Process Logs') {
            steps {
                sh '''
                    . .venv/bin/activate
                    trustmitre ingest logs/*.jsonl --output normalized.jsonl
                    trustmitre run normalized.jsonl
                    trustmitre report
                '''
            }
        }

        stage('Archive Results') {
            steps {
                archiveArtifacts artifacts: 'output/**/*', allowEmptyArchive: false
            }
        }
    }

    post {
        always {
            publishHTML([
                reportDir: 'output',
                reportFiles: 'report.html',
                reportName: 'Detection Report'
            ])
        }
    }
}
```

---

## Security Best Practices

### Authorization

**Always obtain proper authorization before:**
- Collecting logs from production systems
- Processing sensitive security data
- Running analytics on organizational infrastructure
- Exporting or sharing detection results

**Documentation requirements:**
- Written authorization from system owners
- Defined scope and objectives
- Data handling procedures
- Incident response procedures

---

### Data Handling

**Protect sensitive information:**
- Store logs and detections securely
- Encrypt data at rest and in transit
- Implement access controls
- Follow data retention policies
- Sanitize logs before sharing
- Remove PII where possible

**Example sanitization:**
```bash
# Remove sensitive fields before sharing
jq 'del(.username, .email, .ip_address)' output/detections.jsonl > sanitized.jsonl
```

---

### Operational Security

**Production considerations:**
1. Run on dedicated analysis systems
2. Isolate from production networks
3. Use read-only access to log sources
4. Monitor resource usage
5. Implement rate limiting
6. Log all analytics operations
7. Regular backup of detection results

---

### Incident Response

**If critical detections are found:**
1. Document findings thoroughly
2. Preserve evidence (logs, detections)
3. Follow incident response procedures
4. Notify appropriate stakeholders
5. Coordinate remediation efforts
6. Conduct post-incident review

---

## Legal Notice

**YOU ARE RESPONSIBLE FOR OBTAINING PROPER AUTHORIZATION.**

Unauthorized access to computer systems and security monitoring is illegal in many jurisdictions. By using trustMITRE, you agree that:

1. You will only process logs from systems you own or have explicit written permission to analyze
2. You understand that detection results may contain sensitive information
3. You will handle all data in accordance with applicable laws and regulations
4. You accept all responsibility and liability for your actions
5. The authors and TRUST Lab UPCT are not liable for any misuse of this tool

Relevant laws include but are not limited to:
- United States: Computer Fraud and Abuse Act (CFAA), HIPAA, SOX
- European Union: GDPR, NIS Directive
- Other jurisdictions: Various data protection and cybersecurity laws

---

## Support and Resources

### Documentation

- Architecture and Design: `README.md`
- Quick Start Guide: `QUICKSTART.md`
- CAR Analytics: https://car.mitre.org

### Contact

For questions, issues, or contributions:
- Email: volodymyr.dubetskyy@upct.es
- Organization: TRUST Lab UPCT

---

Version: 1.0.0
Date: 2025
© 2025 TRUST Lab UPCT
