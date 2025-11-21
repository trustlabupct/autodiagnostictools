# PYMEs Unified UI Usage Guide

Complete reference for using PYMEs Unified UI v1.0.0 — Centralized interface for TrusLAN, trusClamAV, and trustMITRE security tools.

**Organization:** TRUST Lab UPCT
**© 2025 TRUST Lab UPCT**

---

## Overview

PYMEs Unified UI provides a centralized graphical interface for running three security tools:
- **TrusLAN** - Network discovery and vulnerability scanning
- **trusClamAV** - Malware detection and scanning
- **trustMITRE** - Security analytics and threat detection

---

## Prerequisites

### System Requirements

- Python 3.9 or higher
- tkinter library for GUI support
- Operating systems: Linux, macOS, Windows

### Verify Installation

```bash
# Check Python version
python3 --version

# Verify tkinter availability
python3 -c "import tkinter; print('tkinter OK')"
```

### Installing tkinter

If tkinter is not installed:

**Ubuntu/Debian:**
```bash
sudo apt-get install python3-tk
```

**Fedora/RHEL:**
```bash
sudo dnf install python3-tkinter
```

**Windows:**
Reinstall Python with "tcl/tk and IDLE" option checked.

---

## Installation

### Step 1: Install Tool Dependencies

Navigate to the PYMEs project root directory and install dependencies for each tool:

```bash
cd /path/to/PYMEs

# Install TrusLAN dependencies
cd truslan
pip install -r requirements.txt
cd ..

# Install trusClamAV dependencies
cd trusClamAV
pip install -r requirements.txt
cd ..

# Install trustMITRE dependencies
cd trusMITRE
source .venv/bin/activate  # Linux/macOS
# OR: .venv\Scripts\activate  # Windows
pip install -r requirements.txt
pip install -e .
deactivate
cd ..
```

### Step 2: Verify Installation

The UI will automatically detect tool availability on startup.

---

## Launching the Application

### Linux / macOS

```bash
cd pymes_ui
./launch.sh
```

### Windows

```powershell
cd pymes_ui
launch.bat
```

### Direct Python Launch

```bash
cd pymes_ui
python3 main.py
```

---

## Interface Overview

The application window consists of:

1. **Tab Bar** - Switch between TrusLAN, trusClamAV, trustMITRE, and About
2. **Command Selector** - Radio buttons tailored to each tool's available commands
3. **Options Panel** - Dynamic form for command-specific parameters
4. **Action Buttons** - Run Command, Clear Output, and (where available) Open Output Folder
5. **Output Console** - Real-time command output and results
6. **Status Bar** - Current operation status and progress

---

## TrusLAN Commands

### Discover Networks

Automatically discover local network CIDRs.

**Options:** None — the UI prints discovered networks directly to the console.

**Usage:**
1. Select "Discover Networks"
2. Click "Run Command"
3. Read the list of discovered CIDRs in the output console

**Example Output:**
```
Discovered Networks:
  - 192.168.1.0/24
  - 10.0.0.0/24
```

---

### Scan Networks

Scan specified networks with profile-based settings.

**Required Options:**
- CIDR - Network range to scan (e.g., `192.168.1.0/24`)

**Optional Options:**
- Profile - Scan intensity: safe (default), standard, aggressive
- Port Mode - Port selection strategy: top (default), ports
- Top Ports - Number of most common ports (for top mode)
- Ports - Specific port list (for ports mode)
- Enable UDP - Scan top ports over UDP (requires root/admin)
- Timing Template - Nmap timing: T0 (slowest) to T5 (fastest)
- Trust Discovery - Apply `-Pn` to the scanning phase
- Save XML - Save raw nmap XML output
- I Am Authorized - Required flag for aggressive profile
- Output Directory - Directory for results

**Usage:**
```
1. Select "Scan Networks" command
2. Enter target CIDR (e.g., "192.168.1.0/24")
3. Select profile (safe/standard/aggressive)
4. Configure additional options as needed
5. Click Run Command
6. Monitor progress in console
7. View results in output directory
```

**Output Files:**
- `scan.json` - Complete structured results
- `report.html` - Interactive HTML report
- `findings.csv` - Machine-readable findings

---

### Generate Report

Create reports from existing scan JSON files.

**Options:**
- JSON File - Path to an existing `scan.json`
- Output Directory - Directory where the UI will write `report.html` and `findings.csv`

**Usage:**
```
1. Select "Generate Report" command
2. Browse to existing scan.json file
3. Set an output directory (defaults to `./output`)
4. Click Run Command
```

---

### All-in-One

Combined workflow: discover, scan, and report.

**Options:**
- Auto-discover CIDR - Automatically find local networks
- Manual CIDR(s) - Specify networks if not auto-discovering
- Plus all options from "Scan Networks" command

**Usage:**
```
1. Select "All-in-One" command
2. Check "Auto-discover CIDR" OR enter manual CIDR(s)
3. Configure scan options
4. Click Run Command
5. Wait for complete pipeline
6. Check output directory for all results
```

---

### List NSE Scripts

Display available Nmap NSE scripts grouped by prefix.

**Options:** None — the UI prints the grouped list using TrusLAN defaults.

**Usage:**
```
1. Select "List NSE Scripts" command
2. Click Run Command
3. View available scripts in console
```

---

## trusClamAV Commands

### Doctor (Diagnostics)

Check ClamAV installation and configuration status.

**Options:**
- JSON output - Format output as JSON for parsing

**Usage:**
```
1. Select "Doctor (Diagnostics)" command
2. Check "JSON output" for structured data
3. Click Run Command
4. Review installation status in console
```

**What It Reports:**
- ClamAV installation status
- Binary locations and versions
- Database status and freshness
- Daemon availability
- Configuration issues
- Recommended actions

---

### Install ClamAV

Install or verify ClamAV installation.

**Options:** None — the command runs with trusClamAV defaults.

**Usage:**
```
1. Select "Install ClamAV" command
2. Click Run Command
3. Follow platform-specific installation steps
```

**Note:** May require elevated privileges (sudo/admin).

---

### Update Database

Update ClamAV virus signature database.

**Options:**
- Retries - Number of retry attempts

**Usage:**
```
1. Select "Update Database" command
2. Set retry count (default: 3)
3. Click Run Command
4. Wait for database download and update
```

**Recommended:** Run before first scan and schedule regular updates.

---

### Scan Files

Scan files and directories for malware.

**Required Options:**
- Target paths - Files or directories to scan (space-separated)

**Optional Options:**
- Exclude patterns - Glob patterns to skip
- Output prefix - Base path for result files
- Use ClamAV daemon - Use clamd for faster scanning
- Timeout & Log level - Shared settings applied to every command

**Usage:**
```
1. Select "Scan Files" command
2. Browse to target directory or enter paths
3. Add exclude patterns if needed (e.g., "*.log *.tmp")
4. Set output prefix (e.g., "./scan_results")
5. Click Run Command
6. Monitor scan progress
7. Review results in output files
```

**Output Files:**
- `<prefix>.json` - Structured scan results
- `<prefix>.txt` - Human-readable summary
- `<prefix>.csv` - Tabular findings

**Exit Codes:**
- 0: Clean (no threats found)
- 1: Infected files detected
- 2: Scan errors occurred

---

### Cleanup

Clean up old scan results and logs.

**Options:** None — the cleanup routine runs with trusClamAV defaults.

**Usage:**
```
1. Select "Cleanup" command
2. Click Run Command
3. Review cleaned files in console
```

---

## trustMITRE Commands

### Quickstart

Most trustMITRE commands also accept an optional configuration file at the top of the tab. Leave it blank to use the default settings shipped with `trusMITRE`.

### Quickstart

Run the end-to-end pipeline with a single command.

**Options:**
- Input file (optional) - JSONL log file; the UI falls back to `trusMITRE/logs/test.jsonl` when left blank

**Usage:**
```
1. Select "Quickstart" command
2. Optionally browse to a JSONL log file
3. Click Run Command
4. Wait for compile → ingest → analytics → report stages to finish
5. Open the output folder to review generated artefacts
```

*Note:* The upstream trustMITRE quickstart has known reliability issues. If it fails, run the following commands individually.

---

### Download Analytics

Fetch the latest CAR analytics bundle defined in the trustMITRE configuration.

**Options:** None (uses the optional config file if provided).

**Usage:**
```
1. Select "Download Analytics"
2. Click Run Command
3. Monitor the console for download progress
```

---

### Compile Analytics

Compile downloaded analytics into runnable analyzers.

**Options:** None (relies on trustMITRE defaults or the selected config file).

**Usage:**
```
1. Select "Compile Analytics"
2. Click Run Command
3. Wait for compilation to finish
```

---

### Ingest Logs

Normalize raw telemetry before running analytics.

**Options:**
- Live collection - Toggle real-time Sysmon ingestion (requires elevated privileges)
- EVTX file - Optional Windows Event Log input for offline ingestion
- Output file - Destination JSONL file (recommended to set explicitly)

**Usage:**
```
1. Select "Ingest Logs"
2. Either enable live collection or browse to an EVTX file
3. Provide an output file path (e.g., ./normalized.jsonl)
4. Click Run Command
5. Review the console for ingestion status
```

---

### Run Analytics

Execute compiled analytics against normalized logs.

**Required Options:**
- Input log file - Normalized JSONL file from the ingest step

**Optional Options:**
- Workers - Parallel processing workers
- Batch size - Events processed per batch
- Include analytics - Space-separated CAR analytic IDs to include
- Exclude analytics - Space-separated CAR analytic IDs to skip

**Usage:**
```
1. Select "Run Analytics"
2. Browse to the normalized log file
3. Set workers and batch size as needed
4. Optionally specify analytics to include or exclude
5. Click Run Command and monitor progress
```

---

### Generate Report

Produce summary reports from the most recent analytics results.

**Options:** None — trustMITRE writes reports to `trusMITRE/output/` using its configured defaults.

**Usage:**
```
1. Select "Generate Report"
2. Click Run Command
3. Open the output folder to review CSV/JSON summaries
```

---

### Validate Config

Check that the active trustMITRE configuration is valid.

**Options:** None.

**Usage:**
```
1. Select "Validate Config"
2. Click Run Command
3. Review validation feedback in the console
```

---

### Clean

Remove compiled analyzers and temporary trustMITRE artefacts.

**Options:** None.

**Usage:**
```
1. Select "Clean"
2. Click Run Command
3. Confirm in the console that build output was removed
```

---

## Common Workflows

### Complete Network Security Assessment

```
1. TrusLAN Tab:
   - Command: "All-in-One"
   - Check "Auto-discover CIDR"
   - Profile: "Standard"
   - Output Directory: ./network_assessment
   - Run Command

2. Wait for completion

3. Review results:
   - Open output folder
   - Check report.html for findings
   - Review scan.json for details
```

---

### Malware Scanning Pipeline

```
1. trusClamAV Tab:
   - Command: "Doctor (Diagnostics)"
   - Check "JSON output"
   - Run Command
   - Verify ClamAV is ready

2. If database needs update:
   - Command: "Update Database"
   - Max retries: 3
   - Run Command

3. Scan target:
   - Command: "Scan Files"
   - Targets: /path/to/scan
   - Exclude patterns: "*.log *.tmp"
   - (Optional) Enable "Use ClamAV daemon" for repeated scans
   - Run Command

4. Review results in output files
```

---

### Security Log Analysis

```
1. trustMITRE Tab:
   - Command: "Download Analytics"
   - Run Command

2. Command: "Compile Analytics"
   - Run Command

3. Command: "Ingest Logs"
   - EVTX file (or leave blank for samples)
   - Output file: ./normalized.jsonl
   - Run Command

4. Command: "Run Analytics"
   - Input log file: ./normalized.jsonl
   - Workers: 2
   - Batch size: 500
   - Run Command

5. Command: "Generate Report"
   - Run Command

6. Open output folder to view results
```

---

## Output Management

### Opening Output Folders

On the TrusLAN and trustMITRE tabs you can click "Open Output Folder" to launch the tool's results directory in your file manager.

**Default Output Locations:**
- **TrusLAN:** `<Output Directory>` field (defaults to `./output`)
- **trusClamAV:** Files created from the selected output prefix (no dedicated button)
- **trustMITRE:** `trusMITRE/output/`

---

### Clearing Console Output

Click "Clear Output" button to clear the console window. This does not delete saved files.

---

### Stopping Running Commands

The current UI does not expose a stop button. Allow commands to finish or close the application if you need to terminate a long-running process (this may leave partial results).

---

## Configuration

### Tool Configuration Files

Each tool can use its own configuration file. Refer to individual tool documentation:
- TrusLAN: `truslan/USAGE.md`
- trusClamAV: `trusClamAV/USAGE.md`
- trustMITRE: `trusMITRE/README.md`

---

## Performance Considerations

### TrusLAN Performance

**Safe Profile:**
- Scan time: 1-5 minutes for /24 network
- Network impact: Minimal
- Use for: Regular inventory

**Standard Profile:**
- Scan time: 5-15 minutes for /24 network
- Network impact: Moderate
- Use for: Monthly audits

**Aggressive Profile:**
- Scan time: 15-60+ minutes for /24 network
- Network impact: High (may trigger IDS/IPS)
- Use for: Penetration testing only

---

### trusClamAV Performance

**First Scan:**
- Loads signature database (slower startup)
- Subsequent scans are faster

**Optimization Tips:**
- Enable "Use ClamAV daemon" for repeated scans
- Add exclude patterns to skip unnecessary files
- Break large scans into smaller directories to avoid long-running jobs

---

### trustMITRE Performance

**Worker Configuration:**
- More workers = faster processing but higher CPU usage
- Start with 2 workers, increase if CPU allows
- 4-8 workers optimal for modern systems

**Batch Size:**
- Larger batches = more memory but better throughput
- Start with 500, increase for high-memory systems
- Reduce if experiencing memory issues

---

## Troubleshooting

### UI Won't Launch

**Issue:** Python or tkinter not available

**Solution:**
```bash
# Verify Python
python3 --version

# Install tkinter
sudo apt-get install python3-tk  # Ubuntu/Debian
sudo dnf install python3-tkinter  # Fedora/RHEL
```

---

### Tool Not Detected

**Issue:** Tool shows as unavailable in UI

**Solution:**
1. Verify tool dependencies are installed
2. Check tool directory structure
3. Ensure tool executables are accessible
4. Review console for specific errors

---

### Command Fails to Execute

**Issue:** Command starts but fails immediately

**Solution:**
1. Check console output for error messages
2. Verify all required options are provided
3. Ensure file paths are correct and accessible
4. Check tool-specific requirements (e.g., root for UDP scanning)

---

### Output Not Generated

**Issue:** Command completes but no output files

**Solution:**
1. Verify output directory exists and is writable
2. Check console for write permission errors
3. Ensure output prefix/path is valid
4. Review tool-specific output requirements

---

### Process Hangs

**Issue:** Command runs indefinitely without progress

**Solution:**
1. Allow the command extra time; some scans can take several minutes
2. Review timeout settings
3. Reduce scan scope or batch size
4. Check network connectivity for update commands
5. As a last resort, close the UI window to terminate the background process

---

## Security Best Practices

### Authorization

**Always obtain proper authorization before:**
- Scanning any network you don't own
- Testing systems in production environments
- Running aggressive scans

**Document:**
- Scan objectives and scope
- Authorization approvals
- Timestamps and results
- Any incidents or alerts

---

### Network Impact

**Be aware that:**
- Aggressive scans may trigger IDS/IPS alerts
- Network scans generate significant traffic
- Some operations require elevated privileges
- Scans may impact system performance

**Recommendations:**
- Start with safe/minimal settings
- Schedule scans during maintenance windows
- Monitor for alerts during testing
- Use test environments when possible

---

### Data Security

**Protect scan results:**
- Results contain sensitive network information
- Store in secure locations with access controls
- Encrypt sensitive findings
- Follow data retention policies
- Properly dispose of old results

---

### Responsible Disclosure

**If vulnerabilities are found:**
1. Document findings thoroughly
2. Follow responsible disclosure timelines
3. Notify appropriate stakeholders
4. Allow time for remediation
5. Coordinate public disclosure

---

## Legal Notice

**YOU ARE RESPONSIBLE FOR OBTAINING PROPER AUTHORIZATION.**

Unauthorized security testing is illegal in many jurisdictions. By using PYMEs Unified UI and its integrated tools, you agree that:

1. You will only test systems you own or have explicit written permission to test
2. You understand that scans may trigger security alerts and monitoring systems
3. You accept all responsibility and liability for your actions
4. The authors and TRUST Lab UPCT are not liable for any misuse of these tools

Relevant laws include but are not limited to:
- United States: Computer Fraud and Abuse Act (CFAA)
- European Union: GDPR and national cybercrime laws
- Other jurisdictions: Various computer crime and privacy laws

---

## Support and Resources

### Documentation

- TrusLAN: `/truslan/USAGE.md`
- trusClamAV: `/trusClamAV/USAGE.md`
- trustMITRE: `/trusMITRE/README.md`

### Additional Resources

For questions, issues, or contributions, contact TRUST Lab UPCT.

---

Version: 1.0.0
Date: 2025
© 2025 TRUST Lab UPCT
