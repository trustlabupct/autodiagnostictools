# PYMEs Unified Security Toolkit - Unified UI

**Version:** 1.0.0
**Author:** Volodymyr Dubetskyy
**Contact:** volodymyr.dubetskyy@upct.es
**Organization:** TRUST Lab UPCT
**© 2025 TRUST Lab UPCT**

---

## Overview

The **PYMEs Unified Security Toolkit** provides a single, intuitive graphical user interface (GUI) to interact with three powerful security tools developed by TRUST Lab UPCT:

- **TrusLAN** - LAN Exposure Scanner
- **trusClamAV** - Cross-platform ClamAV Companion
- **trustMITRE** - CAR Analytics Engine

This unified interface eliminates the need to remember complex command-line options and provides a consistent experience across all three tools, while maintaining full access to their underlying capabilities.

---

## Features

### User-Friendly Interface
- **Tabbed Layout**: Each tool has its own dedicated tab with organized options
- **Dynamic Forms**: Options adjust automatically based on selected commands
- **Real-time Output**: Live command output displayed in scrollable text areas
- **Status Indicators**: Progress bars and status messages for running operations

### Full Tool Integration
- **TrusLAN**: Network discovery, scanning, reporting, and NSE script management
- **trusClamAV**: Diagnostics, installation, database updates, and malware scanning
- **trustMITRE**: Complete pipeline from analytics compilation to detection reporting

### Cross-Platform Support
- **Linux**: Primary development target (verified on Ubuntu-based systems)
- **Windows**: Expected to run with Python + tkinter; some system commands (e.g., `xdg-open`) are Linux-specific
- **macOS**: Should run with the built-in tkinter stack, though it has not been formally tested

### Ease of Use
- **File Browsing**: Built-in file and directory pickers
- **Command Building**: Automatic command construction from GUI inputs
- **Output Management**: Output folder button is available on tabs where the target tool exposes a fixed results directory
- **Async Execution**: Commands run in background threads without freezing the UI

---

## Prerequisites

### Required
- **Python 3.9 or higher** (3.11+ recommended)
- **tkinter** (usually bundled with Python)

### Tool-Specific Requirements
Each integrated tool has its own dependencies. When launching commands the UI looks for a tool-specific `.venv` first, then falls back to `trusMITRE/.venv`, and finally to the system Python interpreter.

#### TrusLAN
- Python 3.9+
- nmap
- Dependencies: `jinja2`, `tqdm`

#### trusClamAV
- Python 3.8+
- ClamAV (can be installed via the UI)
- Dependencies: `pyyaml`

#### trustMITRE
- Python 3.11+
- Dependencies: Various (see `trusMITRE/requirements.txt`)

---

## Installation

### Quick Installation (Recommended)

The PYMEs Unified Security Toolkit provides automated installation scripts for both Linux and Windows.

#### Linux / macOS

```bash
cd pymes_ui
chmod +x install.sh
./install.sh
```

**Install specific modules only:**
```bash
./install.sh truslan              # Install TrusLAN only
./install.sh trusclamav           # Install trusClamAV only
./install.sh trustmitre           # Install trustMITRE only
./install.sh truslan trusclamav   # Install multiple modules
./install.sh all                  # Install all modules (default)
```

#### Windows (PowerShell)

```powershell
cd pymes_ui
powershell -ExecutionPolicy Bypass -File install.ps1
```

**Install specific modules only:**
```powershell
.\install.ps1 -TrusLAN              # Install TrusLAN only
.\install.ps1 -TrusClamAV           # Install trusClamAV only
.\install.ps1 -TrustMITRE           # Install trustMITRE only
.\install.ps1 -All                  # Install all modules (default)
```

**Or use the batch file:**
```cmd
cd pymes_ui
install.bat
```

**Note:** If you encounter execution policy errors, run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Installing External Dependencies

#### nmap (for TrusLAN)

**Linux:**
```bash
sudo apt-get install nmap        # Ubuntu/Debian
sudo dnf install nmap            # Fedora/RHEL
brew install nmap                # macOS
```

**Windows:**
Download from https://nmap.org/download.html and check "Add to PATH" during installation.

#### ClamAV (for trusClamAV)

**Linux:**
```bash
sudo apt-get install clamav clamav-daemon  # Ubuntu/Debian
sudo dnf install clamav                    # Fedora/RHEL
brew install clamav                        # macOS
```

**Windows:**
Download from https://www.clamav.net/downloads or use the "Doctor" command in the UI.

---

### Manual Installation (Optional)

If you prefer manual installation or need to customize the setup:

#### Step 1: Clone or Navigate to PYMEs Directory

```bash
cd /path/to/PYMEs
```

#### Step 2: Verify Directory Structure

The unified UI expects the three tools to be in the parent directory:

```
PYMEs/
├── pymes_ui/     # This unified interface
├── truslan/              # TrusLAN tool
├── trusClamAV/           # trusClamAV tool
└── trusMITRE/      # trustMITRE tool
```

#### Step 3: Install Tool Dependencies

**TrusLAN:**
```bash
cd truslan
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# OR: .venv\Scripts\activate.bat  # Windows
pip install -r requirements.txt
deactivate
cd ..
```

**trusClamAV:**
```bash
cd trusClamAV
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# OR: .venv\Scripts\activate.bat  # Windows
pip install -r requirements.txt
deactivate
cd ..
```

**trustMITRE:**
```bash
cd trusMITRE
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# OR: .venv\Scripts\activate.bat  # Windows
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .
deactivate
cd ..
```

#### Step 4: Verify tkinter Installation

**Linux:**
```bash
python3 -c "import tkinter; print('tkinter OK')"
```

If tkinter is missing:
- Ubuntu/Debian: `sudo apt-get install python3-tk`
- Fedora/RHEL: `sudo dnf install python3-tkinter`

**Windows:**
Tkinter is usually included with Python. If missing, reinstall Python with "tcl/tk and IDLE" option checked.

### No Additional Installation for UI

The unified UI uses only Python's built-in `tkinter` library, so no additional packages are required!

---

## Windows Executable Builds

The GUI detects standalone binaries for each tool. You can ship a Windows bundle without requiring a Python install by packaging every component with PyInstaller:

1. **Build the tool executables** (run inside each tool directory after creating its virtual environment)
   ```powershell
   cd ..\truslan
   .\.venv\Scripts\activate
   pip install pyinstaller
   pyinstaller --onefile --name truslan -m truslan

   cd ..\trusClamAV
   .\.venv\Scripts\activate
   pip install pyinstaller
   pyinstaller --onefile --name trusClamAV -m trusClamAV

   cd ..\trusMITRE
   .\.venv\Scripts\activate
   pip install pyinstaller
   pyinstaller --onefile --name trustmitre -m trustmitre
   ```

2. **Build the unified UI executable**
   ```powershell
   cd ..\pymes_ui
   pip install pyinstaller
   pyinstaller --onefile --noconsole --name PYMEsUI main.py
   ```

3. **Assemble the distribution directory**
   - Place `PYMEsUI.exe` next to `truslan.exe`, `trusClamAV.exe`, and `trustmitre.exe`.
   - Copy any required resources (`analytics/`, config files, sample data) for each tool.
   - Install or ship the bundle in a writable location (e.g., `%USERPROFILE%\PYMEs`) so generated reports can be saved.

4. **Optional overrides**
   - If executables live elsewhere, set environment variables before launch:
     ```
     set PYMES_TRUSLAN_EXECUTABLE=C:\Tools\truslan.exe
     set PYMES_TRUSCLAMAV_EXECUTABLE=C:\Tools\trusClamAV.exe
     set PYMES_TRUSTMITRE_EXECUTABLE=C:\Tools\trustmitre.exe
     ```

If no executable is found the UI falls back to running the Python modules, which requires a local interpreter. Bundled releases should keep the generated `.exe` files together to avoid that fallback.

---

## Running the Application

### Using Launch Scripts (Recommended)

**Linux / macOS:**
```bash
cd pymes_ui
./launch.sh
```

**Windows:**
```cmd
cd pymes_ui
launch.bat
```

### Direct Python Launch

**Linux / macOS:**
```bash
cd pymes_ui
python3 main.py
```

**Windows:**
```cmd
cd pymes_ui
python main.py
```

### Alternative: Make Executable (Linux/macOS)

```bash
chmod +x main.py
./main.py
```

---

## Usage Guide

### Application Layout

The application consists of:
1. **Header**: Displays the application title and branding
2. **Tabbed Interface**: Four tabs (TrusLAN, trusClamAV, trustMITRE, About)
3. **Status Bar**: Shows command status and progress indicator

### General Workflow

1. **Select a Tab** for the tool you want to use
2. **Choose a Command** using the radio buttons
3. **Configure Options** in the dynamic options panel
4. **Click "Run Command"** to execute
5. **Monitor Output** in the scrollable text area
6. **Access Results** via the output folder button (available on TrusLAN and trustMITRE tabs) or by opening the paths printed in the console

---

## Tab-by-Tab Guide

### TrusLAN Tab

**Available Commands:**
- **Discover Networks**: Automatically detect local network CIDRs
- **Scan Network**: Perform security scanning on specified networks
- **Generate Report**: Create HTML/CSV reports from existing scan results
- **All-in-One**: Run discovery, scanning, and reporting in sequence
- **List NSE Scripts**: Show available nmap NSE scripts

**Key Options:**
- **CIDR**: Target network (e.g., `192.168.1.0/24`)
- **Auto-discover CIDR**: Available for the all-in-one workflow
- **Profile**: Safe, Standard, or Aggressive scanning intensity
- **Port Mode**: Scan top N ports or specific ports
- **Top Ports / Ports**: Configure the values used by the selected port mode
- **Timing**: Nmap timing template (T0-T5)
- **UDP / Trust discovery / Save XML**: Toggle optional nmap behaviours
- **I am authorized**: Required by TrusLAN when running the aggressive profile
- **Output Directory**: Where to save results

**Example Use Case:**
1. Select "All-in-One"
2. Check "Auto-discover CIDR"
3. Set Profile to "Standard"
4. Set Output Directory to `./truslan_results`
5. Click "Run Command"

### trusClamAV Tab

**Available Commands:**
- **Doctor (Diagnostics)**: Check ClamAV installation and environment
- **Install ClamAV**: Automatically install ClamAV using system package manager
- **Update Database**: Update virus signature database
- **Scan Files**: Scan directories or files for malware
- **Cleanup**: Remove logs and temporary files

**Key Options:**
- **Targets**: Paths to scan (space-separated)
- **Exclude patterns**: Files/folders to skip (e.g., `*.log *.cache`)
- **Output prefix**: Base name for result files
- **Use ClamAV daemon**: Enable for faster repeated scans
- **Timeout & Log level**: Common settings applied to every command
- **Retries**: Number of attempts when updating the database

**Example Use Case:**
1. Select "Scan Files"
2. Click "Browse" next to Targets and select `/home/user/Downloads`
3. Set Exclude patterns to `*.log *.tmp`
4. Set Output prefix to `./scan_results/download_scan`
5. Click "Run Command"

### trustMITRE Tab

**Available Commands:**
- **Quickstart**: Run complete pipeline (download → compile → ingest → run → report)
- **Download Analytics**: Fetch latest CAR analytics
- **Compile Analytics**: Build executable analyzers from analytics
- **Ingest Logs**: Normalize logs to JSONL format
- **Run Analytics**: Execute detection analytics on normalized logs
- **Generate Report**: Create CSV/JSON reports from detections
- **Validate Config**: Check configuration settings
- **Clean**: Remove compiled artifacts and temporary files

**Key Options:**
- **Config file**: Optional custom configuration JSON recognised by trustMITRE
- **Quickstart input**: Optional path to a JSONL log file (falls back to the bundled sample)
- **Ingest settings**: Toggle live collection or provide EVTX input and an output path
- **Run settings**: Input log file, worker count, batch size, and analytics include/exclude filters

**Example Use Case:**
1. Select "Quickstart"
2. Browse to select an input file (or leave blank for samples)
3. Optionally specify a config file
4. Click "Run Command"
5. Wait for complete pipeline execution
6. Click "Open Output Folder" to view results
- *Note:* The upstream `trustMITRE` quickstart command is known to be brittle; if it fails, run the individual commands in sequence.

### About Tab

Displays:
- Application information and version
- Author and organization details
- Integrated tools descriptions
- Platform and Python version information
- License information

---

## Configuration

### Python Executable Selection

The application automatically selects the Python executable in this order:
1. Tool-specific `.venv` inside `truslan/`, `trusClamAV/`, or `trusMITRE/` (if present)
2. **Virtual environment** from `trusMITRE/.venv`
3. **System Python** (fallback)

This ensures compatibility with tool dependencies, especially for trustMITRE which requires specific packages.

### Working Directories

Each tool command executes in its respective directory:
- TrusLAN: `/path/to/PYMEs/truslan`
- trusClamAV: `/path/to/PYMEs/trusClamAV`
- trustMITRE: `/path/to/PYMEs/trusMITRE`

### Output Files

Default output locations:
- **TrusLAN**: `<Output Directory>` (defaults to `./output`)
- **trusClamAV**: Files generated from the selected output prefix (default `./scan_result`)
- **trustMITRE**: `trusMITRE/output/` (opened by the "Open Output Folder" button)

---

## Tips and Best Practices

### Performance Optimization

1. **TrusLAN**: Use "Safe" profile for quick scans, "Standard" for audits, "Aggressive" only when authorized
2. **trusClamAV**: Enable "Use ClamAV daemon" for faster repeated scans
3. **trustMITRE**: Adjust worker count based on CPU cores; use batch size 500-1000 for large files

### Error Handling

- **Command Fails**: Check the output console for detailed error messages
- **Permission Errors**: Run with elevated privileges (sudo/Administrator) when needed
- **Path Issues**: Use the Browse buttons to ensure correct file/directory paths
- **Tool Not Found**: Verify tools are installed in the correct directory structure

### Output Management

- Use the **"Open Output Folder"** button to quickly access results (available on TrusLAN and trustMITRE tabs)
- **Clear Output** before running new commands for cleaner logs
- Save important output to files before closing the application

---

## Support

### Documentation
- **Usage Guide**: See `USAGE.md` for detailed command reference and troubleshooting
- **TrusLAN**: See `truslan/USAGE.md`
- **trusClamAV**: See `trusClamAV/USAGE.md`
- **trustMITRE**: See `trusMITRE/USAGE.md`

### Getting Help
1. Check individual tool documentation
2. Review command output in the UI console
3. Verify tool installation and dependencies
4. Contact the development team

---

## License

**PYMEs Unified Security Toolkit**
Copyright © 2025 Volodymyr Dubetskyy, Universidad Politécnica de Cartagena

This unified interface is provided as-is for educational and professional use. Each integrated tool maintains its own license and usage terms.

For specific license information, refer to:
- `truslan/LICENSE` (if available)
- `trusClamAV/LICENSE`
- `trusMITRE/LICENSE`

---

## Acknowledgments

- **TRUST Lab UPCT** - For supporting the development of these security tools
- **Universidad Politécnica de Cartagena** - For institutional resources
- **Open Source Community** - For the underlying tools and libraries

---

**Built with care for security professionals and SMBs**

*Last updated: January 2025 • Version 1.0.0*
