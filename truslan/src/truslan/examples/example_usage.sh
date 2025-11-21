#!/bin/bash
# TrusLAN v1.3.0 - Example Usage
# TrusLAN — LAN Exposure Scanner (SMB/RDP/HTTP/TLS/SSH/UDP)
# Author: Volodymyr Dubetskyy
# Organization: Trust Lab UPCT
# © 2025 Trust Lab UPCT

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=================================================="
echo "  TrusLAN v1.3.0 - Example Usage"
echo "  LAN Exposure Scanner (SMB/RDP/HTTP/TLS/SSH/UDP)"
echo "=================================================="
echo ""

# Example 1: Discover local networks
echo -e "${BLUE}Example 1: Discover Local Networks${NC}"
echo "Command: python -m truslan discover"
echo ""
python -m truslan discover
echo ""

# Example 2: Quick safe scan (default profile)
echo -e "${BLUE}Example 2: Quick Safe Scan${NC}"
echo "Command: python -m truslan scan --cidr \"192.168.1.0/24\" --out out/safe"
echo "Profile: SAFE (business ports, minimal impact)"
echo "Protocols: SMB/RDP/HTTP/TLS/SSH/UDP"
echo ""
# python -m truslan scan --cidr "192.168.1.0/24" --out out/safe
echo -e "${YELLOW}(Commented out - replace with your network)${NC}"
echo ""

# Example 3: Standard scan with top 1000 ports
echo -e "${BLUE}Example 3: Standard Scan with Top 1000 Ports${NC}"
echo "Command: python -m truslan scan --cidr \"192.168.1.0/24\" --profile standard --mode top --top 1000 --out out/standard"
echo "Profile: STANDARD (comprehensive audit)"
echo ""
# python -m truslan scan --cidr "192.168.1.0/24" --profile standard --mode top --top 1000 --out out/standard
echo -e "${YELLOW}(Commented out - replace with your network)${NC}"
echo ""

# Example 4: Trust discovery mode (for filtered networks)
echo -e "${BLUE}Example 4: Trust Discovery Mode${NC}"
echo "Command: python -m truslan scan --cidr \"192.168.1.0/24\" --trust-discovery --profile standard --out out/trust"
echo "Purpose: Force Phase 2 to scan all Phase 1 discovered hosts with -Pn"
echo "Use case: Networks with aggressive firewalls blocking TCP probes"
echo ""
# python -m truslan scan --cidr "192.168.1.0/24" --trust-discovery --profile standard --out out/trust
echo -e "${YELLOW}(Commented out - replace with your network)${NC}"
echo ""

# Example 5: Custom ports with UDP
echo -e "${BLUE}Example 5: Custom Ports with UDP${NC}"
echo "Command: sudo python -m truslan scan --cidr \"192.168.1.0/24\" --mode ports --ports \"22,80,443,3389\" --udp --udp-ports \"53,161,5353\" --out out/custom"
echo "Note: UDP scanning requires root/admin privileges"
echo ""
# sudo python -m truslan scan --cidr "192.168.1.0/24" --mode ports --ports "22,80,443,3389" --udp --udp-ports "53,161,5353" --out out/custom
echo -e "${YELLOW}(Commented out - requires root, replace with your network)${NC}"
echo ""

# Example 6: Aggressive scan (requires authorization)
echo -e "${BLUE}Example 6: Aggressive Scan (Authorized Only)${NC}"
echo "Command: python -m truslan scan --cidr \"192.168.1.0/24\" --profile aggressive --i-am-authorized --out out/aggressive"
echo "Warning: High network impact, may trigger IDS/IPS alerts"
echo "Requires: --i-am-authorized flag (explicit consent)"
echo ""
# python -m truslan scan --cidr "192.168.1.0/24" --profile aggressive --i-am-authorized --out out/aggressive
echo -e "${YELLOW}(Commented out - only use on authorized networks)${NC}"
echo ""

# Example 7: Multiple networks
echo -e "${BLUE}Example 7: Scan Multiple Networks${NC}"
echo "Command: python -m truslan scan --cidr \"192.168.1.0/24 10.0.0.0/24\" --profile standard --out out/multi"
echo ""
# python -m truslan scan --cidr "192.168.1.0/24 10.0.0.0/24" --profile standard --out out/multi
echo -e "${YELLOW}(Commented out - replace with your networks)${NC}"
echo ""

# Example 8: All-in-one command (discover + scan + report)
echo -e "${BLUE}Example 8: All-in-One Command${NC}"
echo "Command: python -m truslan all --auto-cidr --profile standard --out out/all"
echo "Purpose: Discover, scan, and generate reports in one command"
echo ""
# python -m truslan all --auto-cidr --profile standard --out out/all
echo -e "${YELLOW}(Commented out - will scan all discovered networks)${NC}"
echo ""

# Example 9: Generate reports from existing scan
echo -e "${BLUE}Example 9: Generate Reports from Existing Scan${NC}"
echo "Command: python -m truslan report --from-json out/scan.json --out-html report.html --out-csv findings.csv"
echo ""
# python -m truslan report --from-json out/scan.json --out-html report.html --out-csv findings.csv
echo -e "${YELLOW}(Commented out - requires existing scan.json)${NC}"
echo ""

# Example 10: Full aggressive scan with all protocols
echo -e "${BLUE}Example 10: Full Protocol Coverage - Aggressive Mode${NC}"
echo "Command: python3 -m truslan all --auto-cidr --profile aggressive --mode top --top 1000 --out out/ --i-am-authorized"
echo "Purpose: Comprehensive LAN exposure scanning across SMB/RDP/HTTP/TLS/SSH/UDP"
echo ""
# python3 -m truslan all --auto-cidr --profile aggressive --mode top --top 1000 --out out/ --i-am-authorized
echo -e "${YELLOW}(Commented out - requires explicit authorization)${NC}"
echo ""

# Example 11: List available NSE scripts
echo -e "${BLUE}Example 11: List Available NSE Scripts${NC}"
echo "Command: python -m truslan list-scripts"
echo ""
python -m truslan list-scripts | head -n 50
echo "..."
echo -e "${YELLOW}(Output truncated - run command to see all scripts)${NC}"
echo ""

# Example 12: Custom batch size for large networks
echo -e "${BLUE}Example 12: Large Network with Custom Batch Size${NC}"
echo "Command: python -m truslan scan --cidr \"10.0.0.0/16\" --batch-size 128 --timing T4 --out out/large"
echo "Purpose: Optimize scanning for large networks"
echo ""
# python -m truslan scan --cidr "10.0.0.0/16" --batch-size 128 --timing T4 --out out/large
echo -e "${YELLOW}(Commented out - large network scan)${NC}"
echo ""

# Example 13: Strict NSE mode
echo -e "${BLUE}Example 13: Strict NSE Mode${NC}"
echo "Command: python -m truslan scan --cidr \"192.168.1.0/24\" --nse-strict --out out/strict"
echo "Purpose: Abort if any requested NSE script is unavailable"
echo ""
# python -m truslan scan --cidr "192.168.1.0/24" --nse-strict --out out/strict
echo -e "${YELLOW}(Commented out - replace with your network)${NC}"
echo ""

# Example 14: Save raw XML output
echo -e "${BLUE}Example 14: Save Raw XML Output${NC}"
echo "Command: python -m truslan scan --cidr \"192.168.1.0/24\" --save-xml --out out/withxml"
echo "Purpose: Save raw nmap XML files for advanced analysis"
echo "Output: out/withxml/raw/*.xml"
echo ""
# python -m truslan scan --cidr "192.168.1.0/24" --save-xml --out out/withxml
echo -e "${YELLOW}(Commented out - replace with your network)${NC}"
echo ""

# Example 15: Using the truslan CLI directly
echo -e "${BLUE}Example 15: Using the truslan CLI Executable${NC}"
echo "Command: truslan scan --cidr \"192.168.1.0/24\" --profile standard"
echo "Note: Requires installation with pip install -e . or equivalent"
echo ""
# truslan scan --cidr "192.168.1.0/24" --profile standard
echo -e "${YELLOW}(Commented out - requires CLI installation)${NC}"
echo ""

echo "=================================================="
echo -e "${GREEN}Examples complete!${NC}"
echo "=================================================="
echo ""
echo "About TrusLAN:"
echo "  Originally focused on SMB/Windows file sharing exposure (ports 445/139)"
echo "  and RDP vulnerabilities, TrusLAN has evolved to include HTTP/TLS/SSH/UDP"
echo "  scanning with aggressive profiling modes and comprehensive reporting."
echo ""
echo "Notes:"
echo "  - All scan commands are commented out by default"
echo "  - Replace \"192.168.1.0/24\" with your actual network CIDR"
echo "  - Ensure you have authorization before scanning any network"
echo "  - Use --verbose for detailed logging"
echo "  - Use --help on any command for more options"
echo ""
echo "Quick Reference:"
echo "  discover      - Find local networks"
echo "  scan          - Scan specified networks"
echo "  report        - Generate reports from scan JSON"
echo "  all           - Discover, scan, and report in one command"
echo "  list-scripts  - Show available NSE scripts"
echo ""
echo "Documentation:"
echo "  README.md     - Overview and quick start"
echo "  USAGE.md      - Complete command reference and troubleshooting"
echo ""
echo "Key Options:"
echo "  --trust-discovery    - Apply -Pn to Phase 2 (trust Phase 1 discovery)"
echo "  --profile PROF       - safe (default), standard, or aggressive"
echo "  --mode MODE          - top (default) or ports"
echo "  --top N              - Number of top ports (requires --mode top)"
echo "  --ports LIST         - Specific ports (requires --mode ports)"
echo "  --udp                - Enable UDP scanning (requires root)"
echo "  --timing T0-T5       - Nmap timing template (default: T3)"
echo "  --batch-size N       - Hosts per batch (default: 64)"
echo "  --save-xml           - Save raw nmap XML output"
echo "  --nse-strict         - Abort if NSE scripts unavailable"
echo "  --i-am-authorized    - Required for aggressive profile"
echo ""
echo "Protocol Coverage:"
echo "  - SMB/NetBIOS (445, 139)"
echo "  - RDP (3389)"
echo "  - HTTP/HTTPS (80, 443, 8080, 8443)"
echo "  - SSH (22)"
echo "  - TLS/SSL certificate validation"
echo "  - UDP services (DNS, SNMP, NTP, etc.)"
echo "  - Databases (MySQL, PostgreSQL, MSSQL, MongoDB, Redis)"
echo "  - Mail services (SMTP, POP3, IMAP)"
echo ""
echo "Legal Notice:"
echo "  Only scan networks you own or have explicit written permission to test."
echo "  Unauthorized scanning may be illegal in your jurisdiction."
echo ""
echo "© 2025 Trust Lab UPCT"
echo ""
