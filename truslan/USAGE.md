# TrusLAN Usage Guide

Complete reference for using TrusLAN v1.3.0 — LAN Exposure Scanner.

**Author:** Volodymyr Dubetskyy
**Organization:** TRUST Lab UPCT
**© 2025 TRUST Lab UPCT**

---

## Commands

### discover
Discover local network CIDRs automatically.

```bash
python -m truslan discover
# Or with installed CLI:
truslan discover
```

**Output:**
```
Discovered Networks:
  - 192.168.1.0/24
  - 10.0.0.0/24
```

**Options:**
- `--out FILE` - Save discovered CIDRs to file

**Windows note:** If PowerShell discovery returns no interfaces, TrusLAN automatically falls back to parsing `ipconfig` output—including localized strings such as `Dirección IPv4` and `Máscara de subred`—so multilingual Windows editions are detected correctly.

---

### scan
Scan specified networks with profile-based settings.

```bash
python -m truslan scan --cidr "192.168.1.0/24" --profile safe --out out/
```

**Required:**
- `--cidr CIDR` - Network(s) to scan (space or comma-separated)

**Options:**
- `--profile PROFILE` - Scan profile: safe (default), standard, aggressive
- `--mode MODE` - Port selection: top (default), ports
- `--top N` - Number of top ports (requires --mode top)
- `--ports LIST` - Specific ports (requires --mode ports, e.g., "22,80,443")
- `--udp` - Enable UDP scanning (requires root)
- `--udp-ports LIST` - UDP ports to scan
- `--timing T0-T5` - Nmap timing template (default: T3)
- `--host-timeout TIME` - Host timeout (default: 30s)
- `--max-retries N` - Maximum retries per host
- `--script-timeout TIME` - NSE script timeout (default: 30s)
- `--trust-discovery` - Apply -Pn to Phase 2; trust Phase 1 discovery results
- `--allow-intrusive` - Allow intrusive NSE scripts (aggressive only)
- `--batch-size N` - Hosts per scan batch (default: 64)
- `--fail-on-errors` - Abort on batch failure (default: continue)
- `--save-xml` - Save raw nmap XML output
- `--nse-strict` - Abort if NSE scripts unavailable
- `--nmap-path PATH` - Path to nmap binary
- `--i-am-authorized` - Required for aggressive profile
- `--out DIR` - Output directory for results

---

### report
Generate reports from existing scan JSON.

```bash
python -m truslan report --from-json out/scan.json --out-html out/report.html --out-csv out/findings.csv
```

**Required:**
- `--from-json FILE` - Input scan JSON file

**Options:**
- `--out-html FILE` - Generate HTML report
- `--out-csv FILE` - Generate CSV findings export

---

### all
All-in-one command: discover, scan, and report.

```bash
python -m truslan all --auto-cidr --profile standard --mode top --top 1000 --out out/
```

**Options:**
- `--auto-cidr` - Auto-discover local networks
- `--cidr CIDR` - Manual CIDR specification (if not using --auto-cidr)
- Plus all options from `scan` command

---

### list-scripts
List available NSE scripts grouped by prefix.

```bash
python -m truslan list-scripts
```

**Options:**
- `--nmap-path PATH` - Path to nmap binary (default: nmap)
- `--grep NAME` - Check if specific script is available
- `--explain NAME` - Explain availability and installation for script

---

## Scan Profiles

### SAFE (default)
- **Ports:** Business-critical services (SSH, HTTP/S, SMB, RDP, databases, mail, printing)
- **Impact:** Minimal
- **Scripts:** Safe scripts only
- **Use case:** Regular inventory, production environments

### STANDARD
- **Ports:** Top 1000 most common ports
- **Impact:** Moderate
- **Scripts:** Safe vulnerability detection
- **Use case:** Monthly security audits, compliance checks

### AGGRESSIVE
- **Ports:** Top 2000 ports (or custom)
- **Impact:** High (may trigger IDS/IPS)
- **Scripts:** All applicable including intrusive
- **Requirements:** `--i-am-authorized` flag
- **Use case:** Penetration testing, deep security assessments

---

## Protocol Coverage

TrusLAN comprehensively scans across multiple protocols:

- **SMB/NetBIOS** (445, 139) - File sharing vulnerabilities
- **RDP** (3389) - Remote desktop exposure
- **HTTP/HTTPS** (80, 443, 8080, 8443) - Web service security
- **SSH** (22) - Secure shell configuration
- **TLS/SSL** - Certificate validation and cipher strength
- **UDP Services** - DNS, SNMP, NTP, and more
- **Databases** - MySQL, PostgreSQL, MSSQL, MongoDB, Redis
- **Mail Services** - SMTP, POP3, IMAP
- **Industrial/IoT** - Modbus, BACnet, MQTT

---

## Examples

### Basic Examples

```bash
# Quick safe scan of local network
truslan scan --cidr "192.168.1.0/24"

# Discover and scan automatically
truslan all --auto-cidr

# Standard scan with specific output directory
truslan scan --cidr "10.0.0.0/16" --profile standard --out results/
```

### Advanced Examples

```bash
# Aggressive scan with all protocols (requires authorization)
python3 -m truslan all --auto-cidr --profile aggressive --mode top --top 1000 --out out/ --i-am-authorized

# Multiple networks with custom ports
truslan scan --cidr "192.168.1.0/24 10.0.0.0/24" \
    --mode ports --ports "22,80,443,445,3389,8080,8443"

# UDP scanning with specific ports
sudo truslan scan --cidr "192.168.1.0/24" \
    --udp --udp-ports "53,67,68,123,161,5353"

# Fast timing for quick inventory
truslan scan --cidr "192.168.1.0/24" \
    --timing T4 --host-timeout 15s --max-retries 1

# Trust discovery mode for filtered networks
truslan scan --cidr "10.0.0.0/16" \
    --trust-discovery --profile standard
```

### Reporting Examples

```bash
# Generate both HTML and CSV reports
truslan report --from-json scan.json \
    --out-html report.html --out-csv findings.csv

# Save all outputs including raw XML
truslan scan --cidr "192.168.1.0/24" \
    --out output/ --save-xml

# Custom batch size for large networks
truslan scan --cidr "10.0.0.0/8" \
    --batch-size 128 --timing T3
```

---

## Configuration

### Environment Variables

- `TRUSLAN_PROFILE` - Default scan profile (safe/standard/aggressive)
- `TRUSLAN_MODE` - Default port mode (top/ports)
- `TRUSLAN_TOP` - Default top ports count
- `TRUSLAN_TIMING` - Default timing template (T0-T5)
- `TRUSLAN_BATCH_SIZE` - Default batch size
- `TRUSLAN_OUTPUT_DIR` - Default output directory

### Configuration Files

TrusLAN checks for configuration in order:

1. `./truslan.json` - Project-specific config
2. `~/.config/truslan/config.json` - User config
3. `/etc/truslan/config.json` - System config

Example `truslan.json`:
```json
{
  "default_profile": "standard",
  "default_timing": "T3",
  "default_top_ports": 1000,
  "default_batch_size": 64,
  "auto_save_xml": true,
  "nmap_path": "/usr/bin/nmap"
}
```

---

## Output Files

### scan.json
Complete structured scan results including:
- Scan metadata and configuration
- Discovered hosts and services
- Security findings with severity levels
- Summary statistics

### report.html
Interactive single-file HTML report with:
- Executive summary dashboard
- Top quick fixes and recommendations
- Per-host service details
- Consolidated findings table
- Profile-aware remediation advice

### findings.csv
Machine-readable CSV export containing:
- Finding ID, severity, and type
- Affected host and port
- Description and remediation
- CVSS scores (when available)

### raw/*.xml
Raw nmap XML output (when --save-xml is used) for:
- Third-party tool integration
- Manual analysis
- Debugging and verification

---

## Troubleshooting

### Common Issues

#### "Discovered X hosts but only Y marked up"
This is normal behavior. Some devices respond to ARP/ICMP (Phase 1) but block TCP probes (Phase 2).

**Solution:** Use `--trust-discovery` to force Phase 2 to scan all discovered targets with `-Pn`.

#### "nmap is not installed or not in PATH"
Install nmap for your platform:
- Ubuntu/Debian: `sudo apt-get install nmap`
- macOS: `brew install nmap`
- Windows: Download from https://nmap.org/download.html

#### "UDP scanning requires root/admin privileges"
Run with elevated privileges:
- Linux/macOS: `sudo truslan scan --udp ...`
- Windows: Run as Administrator

#### "Aggressive profile requires explicit authorization"
Add the `--i-am-authorized` flag to confirm you have permission to perform aggressive scans.

#### "No local networks discovered"
TrusLAN now automatically retries discovery on Windows by parsing `ipconfig`, including localized output (for example, Spanish `Dirección IPv4`). If the message persists, double-check that the interfaces are up, run the terminal as Administrator, or provide the target range explicitly with `--cidr`.

#### "Scan taking too long"
Speed optimizations:
- Reduce batch size: `--batch-size 32`
- Increase timing: `--timing T4` or `T5`
- Reduce timeout: `--host-timeout 15s`
- Scan fewer ports: `--mode ports --ports "22,80,443"`
- Skip UDP: Remove `--udp` flag

---

## Security Best Practices

1. **Always obtain authorization** before scanning any network
2. **Start with safe profile** and escalate only if needed
3. **Document scan activities** for compliance and audit trails
4. **Be aware of network impact**, especially with aggressive profiles
5. **Secure output files** as they contain sensitive network information
6. **Use read-only accounts** when possible for authenticated scans
7. **Monitor for IDS/IPS alerts** during and after scanning
8. **Follow responsible disclosure** for any vulnerabilities found

---

## Legal Notice

**YOU ARE RESPONSIBLE FOR OBTAINING PROPER AUTHORIZATION.**

Unauthorized network scanning is illegal in many jurisdictions, including but not limited to:
- United States: Computer Fraud and Abuse Act (CFAA)
- European Union: GDPR and national cybercrime laws
- Other countries: Various computer crime and privacy laws

By using TrusLAN, you agree that:
1. You will only scan networks you own or have explicit written permission to test
2. You understand that scans may trigger security alerts and monitoring systems
3. You accept all responsibility and liability for your actions
4. The authors and TRUST Lab UPCT are not liable for any misuse of this tool

---

## Support

For questions, issues, or contributions, contact TRUST Lab UPCT.

Version: 1.3.0
Date: 2025-10-08
© 2025 TRUST Lab UPCT
