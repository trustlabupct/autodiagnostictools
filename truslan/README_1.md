# TrusLAN v1.3.0

**TrusLAN — LAN Exposure Scanner (SMB/RDP/HTTP/TLS/SSH/UDP)**

A professional, safe-by-default network security scanner designed for LANs and small business networks. Identifies common security vulnerabilities across multiple protocols and provides actionable remediation advice.

**Author:** Volodymyr Dubetskyy
**Organization:** TRUST Lab UPCT
**© 2025 TRUST Lab UPCT**

## Why TrusLAN?

Originally developed with a focus on **SMB/Windows file sharing exposure** (ports 445/139) and **RDP** vulnerabilities—hence the original "smbscan" name—the tool has evolved significantly. Today's scope includes **HTTP/TLS/SSH/UDP** scanning, aggressive profiling modes, and comprehensive reporting capabilities. The name **TrusLAN** better reflects this broader mission: comprehensive **LAN Exposure Scanning** for the protocols that matter most in local network security.

## Features

- **Three Scan Profiles**: Safe (default), Standard, and Aggressive with profile-aware remediation
- **Multi-Protocol Support**: SMB, RDP, HTTP, TLS/SSH, UDP, and more
- **Cross-Platform Discovery**: Automatic network detection on Windows, Linux, and macOS
- **Windows-Friendly Discovery**: Automatically falls back to parsing localized `ipconfig` output when PowerShell reports no networks, so multilingual Windows installs are fully supported
- **Privilege-Aware**: Automatically adapts to available permissions
- **Two-Phase Scanning**: Discovery phase finds live hosts, scan phase targets them in batches
- **Trust Discovery Mode**: Optional `-Pn` in Phase 2 to align scan counts with discovery
- **Actionable Findings**: Security issues mapped to business-friendly remediation steps
- **Multiple Report Formats**: JSON, HTML (with embedded CSS), and CSV outputs
- **NSE Script Management**: Auto-detection and filtering of available NSE scripts
- **Minimal Dependencies**: Python 3.9+, nmap, jinja2, tqdm

## Installation

### Prerequisites

1. **Python 3.9 or higher**
2. **Nmap** - Install from your package manager:
   - Ubuntu/Debian: `sudo apt-get install nmap`
   - macOS: `brew install nmap`
   - Windows: Download from https://nmap.org/download.html

### Install TrusLAN

```bash
# Navigate to the module directory
cd truslan

# Install dependencies
pip install -r requirements.txt

# Or use a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Quick Start

### 1. Discover Local Networks

```bash
python -m truslan discover
```

### 2. Run a Safe Scan

```bash
python -m truslan scan --cidr "192.168.1.0/24" --out out/
```

### 3. Generate Reports

Reports are auto-generated during scan, or create from existing JSON:

```bash
python -m truslan report --from-json out/scan.json \
    --out-html out/report.html \
    --out-csv out/findings.csv
```

### 4. All-in-One Command

```bash
python -m truslan all --auto-cidr --profile standard --out out/
```

For aggressive scanning with all protocols:

```bash
python3 -m truslan all --auto-cidr --profile aggressive --mode top --top 1000 --out out/ --i-am-authorized
```

## Commands

- `discover` - Discover local network CIDRs
- `scan` - Scan specified networks
- `report` - Generate reports from scan JSON
- `all` - Run discover, scan, and report in one command
- `list-scripts` - List available NSE scripts grouped by prefix

## Scan Profiles

### SAFE (default)
- Business ports (SSH, HTTP, HTTPS, SMB, RDP, databases, mail, printing)
- Minimal network impact
- Basic service detection
- Safe NSE scripts only

**Use case:** Regular inventory, production environments

### STANDARD
- Top 1000 ports
- Safe vulnerability detection
- OS detection (if root)
- Moderate network impact

**Use case:** Monthly security audits, compliance checks

### AGGRESSIVE
- Top 2000 ports (or custom)
- Full vulnerability detection
- Version scanning and OS detection
- All applicable NSE scripts (including intrusive)
- Higher network impact

**Use case:** Penetration testing, deep security audits

**Requires explicit authorization:** `--i-am-authorized`

## Protocol Coverage

TrusLAN comprehensively scans for exposures across:

- **SMB/NetBIOS** (445, 139) - File sharing vulnerabilities
- **RDP** (3389) - Remote desktop exposure
- **HTTP/HTTPS** (80, 443, 8080, 8443) - Web service security
- **SSH** (22) - Secure shell configuration
- **TLS/SSL** - Certificate validation and cipher strength
- **UDP Services** - DNS, SNMP, NTP, and more
- **Databases** - MySQL, PostgreSQL, MSSQL, MongoDB, Redis
- **Mail Services** - SMTP, POP3, IMAP
- **Industrial/IoT** - Modbus, BACnet, MQTT

## CLI Examples

### Basic Scans

```bash
# Discover and scan local network
truslan all --auto-cidr

# Scan specific network with standard profile
truslan scan --cidr "192.168.1.0/24" --profile standard

# Scan multiple networks
truslan scan --cidr "192.168.1.0/24 10.0.0.0/24" --profile safe
```

### Advanced Scans

```bash
# Aggressive scan with UDP
truslan scan --cidr "10.0.0.0/16" \
    --profile aggressive \
    --mode top --top 2000 \
    --udp --udp-ports "53,161,123" \
    --i-am-authorized

# Custom port scan
truslan scan --cidr "192.168.1.0/24" \
    --mode ports \
    --ports "22,80,443,445,3389"

# Fast timing with specific timeout
truslan scan --cidr "192.168.1.0/24" \
    --timing T4 \
    --host-timeout 60s \
    --max-retries 2
```

### Reporting

```bash
# Generate both HTML and CSV
truslan report --from-json scan.json \
    --out-html report.html \
    --out-csv findings.csv

# JSON output for integration
truslan scan --cidr "192.168.1.0/24" \
    --out out/ \
    --save-xml
```

## Configuration

TrusLAN supports configuration through:

1. **Environment Variables**:
   - `TRUSLAN_PROFILE` - Default scan profile
   - `TRUSLAN_TIMING` - Default timing template
   - `TRUSLAN_OUTPUT_DIR` - Default output directory

2. **Config Files** (in order of precedence):
   - `./truslan.json` - Project-specific config
   - `~/.config/truslan/config.json` - User config
   - `/etc/truslan/config.json` - System config

Example config:
```json
{
  "default_profile": "standard",
  "default_timing": "T3",
  "default_top_ports": 1000,
  "auto_save_xml": true
}
```

## Output Files

Each scan generates:

- `scan.json` - Complete scan results with findings
- `report.html` - Interactive HTML report
- `findings.csv` - CSV export of all findings
- `raw/*.xml` - Raw nmap XML (if `--save-xml`)

## Security Considerations

1. **Authorization Required**: Only scan networks you own or have explicit permission to test
2. **Legal Compliance**: Unauthorized scanning may violate laws (CFAA, GDPR, etc.)
3. **Network Impact**: Aggressive scans can impact network performance
4. **Credential Safety**: Never hardcode credentials in scripts

## Finding Severity Levels

- **CRITICAL**: Immediate action required (exposed services, known exploits)
- **HIGH**: Significant risk requiring prompt attention
- **MEDIUM**: Notable issues to address in maintenance windows
- **LOW**: Best practice improvements
- **INFO**: Informational findings for awareness

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=truslan --cov-report=html

# Run specific test file
pytest tests/test_cli.py -v
```

### Project Structure

```
truslan/
├── __init__.py          # Package metadata and exports
├── __main__.py          # Entry point for -m truslan
├── cli.py               # Command-line interface
├── core/
│   ├── checks.py        # Security checks and findings
│   ├── discovery.py     # Network discovery
│   ├── models.py        # Data models
│   ├── nse.py          # NSE script management
│   ├── scanners.py     # Scan orchestration
│   └── utils.py        # Utilities and helpers
├── reports/
│   ├── csv.py          # CSV report generation
│   ├── html.py         # HTML report generation
│   └── templates/      # Report templates
└── tests/              # Test suite
```

## Changelog

### v1.3.0 (2025-10-08)
- **Breaking Change**: Hard rename from `smbscan_module` to `truslan`
- CLI executable now `truslan` (lowercase)
- Updated branding to reflect expanded protocol support (SMB/RDP/HTTP/TLS/SSH/UDP)
- Documentation updated to explain SMB/RDP origins and current broader scope
- All references and imports updated to new namespace

### v1.2.6
- Enhanced NSE script resolution and filtering
- Improved profile-based remediation advice
- Better handling of privilege requirements

## Support

For issues, feature requests, or contributions, please contact TRUST Lab UPCT.

## License

[Specify License Here]

---

*TrusLAN is developed and maintained by TRUST Lab UPCT*
