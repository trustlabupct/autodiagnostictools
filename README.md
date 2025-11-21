# TrustPYMEs - Unified Security Toolkit

**TrustPYMEs** is a comprehensive security suite designed by **TRUST Lab UPCT**. It integrates three powerful security modules into a single, user-friendly graphical interface, providing a unified platform for network scanning, malware detection, and threat analytics.

## Modules

### 1. TrustLAN
**Network Discovery & Vulnerability Scanning**
- Discovers devices on the local network.
- Performs port scanning and service enumeration.
- Identifies potential vulnerabilities.

### 2. TrustClamAV
**Antivirus Management**
- Graphical interface for the ClamAV antivirus engine.
- Supports on-demand scanning of files and directories.
- Manages virus database updates.
- **Note**: Automatically installs Chocolatey and ClamAV if run as Administrator on Windows.

### 3. TrustMITRE
**Threat Analytics Pipeline**
- Implements a full threat detection pipeline based on MITRE ATT&CK.
- Compiles and executes analytics from the Cyber Analytics Repository (CAR).
- Ingests logs (Sysmon, EVTX) and generates detection reports.

## Compilation

To build the standalone executable `TrustPYMEs.exe`, ensure you have Python 3.10+ and the required dependencies installed.

### Build Command
Run the following command from the project root:

```powershell
pyinstaller --clean --noconfirm pymes.spec
```

### Output
The compiled executable will be located at:
`dist/TrustPYMEs.exe`

## Usage

1.  Run `TrustPYMEs.exe`.
2.  Navigate through the tabs to access each tool.
3.  Use the **Dashboard** for a quick overview and history.
4.  **TrustMITRE**: Use the "Quickstart" command to run a full analysis pipeline.

## License
(c) 2025 TRUST Lab UPCT
