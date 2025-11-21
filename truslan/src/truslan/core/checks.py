"""
Security checks and findings engine for truslan.

Implements heuristic rules to map scan evidence to actionable findings.
No exploitation - only detection and advisory.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from .models import (
    Host, Service, Finding, FindingSeverity, PortState, ScanProfile, ScanResult
)

logger = logging.getLogger("truslan")


# Known vulnerable service versions (simple heuristic table)
OUTDATED_VERSIONS = {
    "openssh": {"threshold": "7.0", "severity": FindingSeverity.MEDIUM},
    "apache": {"threshold": "2.4.0", "severity": FindingSeverity.MEDIUM},
    "nginx": {"threshold": "1.18.0", "severity": FindingSeverity.LOW},
    "mysql": {"threshold": "5.7.0", "severity": FindingSeverity.MEDIUM},
    "postgresql": {"threshold": "10.0", "severity": FindingSeverity.MEDIUM},
}


def _get_no_tcp_remediation(profile: ScanProfile, mode: str, top_ports: Optional[int]) -> str:
    """
    Generate profile-aware remediation text for NO_TCP_OPEN_IN_PROFILE finding.

    Args:
        profile: Current scan profile
        mode: Scan mode ("top" or "ports")
        top_ports: Number of top ports if mode is "top"

    Returns:
        Profile-appropriate remediation text
    """
    profile_value = profile.value if hasattr(profile, 'value') else profile

    if profile_value == "safe":
        return (
            "No action needed; this host exposes no TCP ports within the safe profile. "
            "To discover additional services, consider escalating to --profile standard (top 100 ports + common SMB/HTTP checks) "
            "or --profile aggressive (top 1000 ports + comprehensive NSE scripts)."
        )

    elif profile_value == "standard":
        return (
            "No TCP ports found in standard profile scan. To increase coverage: "
            "(1) Switch to ports mode with curated business ports: --mode ports -p 21,22,23,25,80,110,135,139,143,443,445,1433,3306,3389,5432,5900,8080,8443; "
            "(2) Increase top ports: --mode top --top-ports 2000; "
            "(3) Enable UDP scanning: --udp --udp-ports 53,67,68,69,123,137,138,161,500,514,520; "
            "(4) Verify host firewalls are not blocking scans."
        )

    elif profile_value == "aggressive":
        return (
            "No TCP ports found even in aggressive profile scan. Recommendations: "
            "(1) Switch to explicit ports mode targeting your environment's business services: "
            "--mode ports -p <custom-port-list> (built-in business ports: 21,22,23,25,80,110,135,139,143,443,445,1433,3306,3389,5432,5900,8080,8443); "
            "(2) Increase beyond --top-ports 1000 (e.g., --top-ports 3000 or --top-ports 5000); "
            "(3) Enable UDP scanning: --udp --udp-ports <udp-list>; "
            "(4) Check for host-based firewalls, IPS/IDS systems, or network ACLs that may be dropping inbound probes; "
            "(5) Verify the host is genuinely reachable and not a false positive from discovery."
        )

    else:
        # Fallback for unknown profile
        return (
            "No action needed; this host exposes no TCP ports within current profile. "
            "Consider deeper scanning with different profiles or port ranges if needed."
        )


def analyze_scan_results(result: ScanResult) -> ScanResult:
    """
    Analyze scan results and generate findings.

    Args:
        result: ScanResult with hosts and services

    Returns:
        Updated ScanResult with findings added to each host
    """
    logger.info("Running security analysis on scan results")

    total_findings = 0

    for host in result.hosts:
        host.findings = []

        # Check if host has any open TCP ports
        open_tcp_ports = [s for s in host.services if s.state == PortState.OPEN and s.protocol == "tcp"]

        # Run all checks
        findings = []

        # If no open TCP ports found, add informational finding
        if not open_tcp_ports and host.state == "up":
            # Generate profile-aware remediation
            mode = result.meta.options.mode if hasattr(result.meta.options, 'mode') else "top"
            top_ports = result.meta.options.top_ports if hasattr(result.meta.options, 'top_ports') else None
            remediation = _get_no_tcp_remediation(result.meta.profile, mode, top_ports)

            findings.append(Finding(
                finding_id="NO_TCP_OPEN_IN_PROFILE",
                severity=FindingSeverity.INFO,
                title="No TCP services found in selected profile",
                description=f"Host {host.ip} is up but has no TCP ports open within the current scan profile. This could mean the host uses non-standard ports or requires deeper scanning.",
                remediation=remediation,
                host=host.ip
            ))
        else:
            # Only run security checks if there are open ports
            findings.extend(_check_dangerous_ports(host))
            findings.extend(_check_unencrypted_protocols(host))
            findings.extend(_check_weak_tls(host))
            findings.extend(_check_smb_security(host))
            findings.extend(_check_ssh_security(host))
            findings.extend(_check_http_security(host))
            findings.extend(_check_outdated_versions(host))

            # Profile-specific checks
            if result.meta.profile in [ScanProfile.STANDARD, ScanProfile.AGGRESSIVE]:
                findings.extend(_check_advanced_vulnerabilities(host))

        host.findings = findings
        total_findings += len(findings)

    # Update summary
    result.summary["findings_total"] = total_findings
    result.summary["findings_by_severity"] = _count_by_severity(result)

    logger.info(f"Analysis complete: {total_findings} findings across {len(result.hosts)} hosts")

    return result


def _check_dangerous_ports(host: Host) -> List[Finding]:
    """Check for commonly exploited open ports."""
    findings = []

    for service in host.services:
        if service.state != PortState.OPEN:
            continue

        finding = None

        # RDP (Remote Desktop Protocol)
        if service.port == 3389:
            finding = Finding(
                finding_id="RDP-EXPOSED",
                severity=FindingSeverity.HIGH,
                title="Remote Desktop Protocol (RDP) Exposed",
                description=f"RDP is accessible on port {service.port}. RDP is frequently targeted by attackers for brute-force attacks and exploitation.",
                remediation="1. Enable Network Level Authentication (NLA). 2. Restrict access via firewall to specific IP addresses or VPN only. 3. Use strong passwords and account lockout policies. 4. Consider disabling RDP if not actively used. 5. Monitor RDP logs for failed login attempts.",
                host=host.ip,
                port=service.port,
                protocol=service.protocol,
                service="rdp"
            )

        # SMB (Server Message Block)
        elif service.port in [445, 139]:
            finding = Finding(
                finding_id="SMB-EXPOSED",
                severity=FindingSeverity.HIGH,
                title="SMB File Sharing Exposed",
                description=f"SMB is accessible on port {service.port}. SMB has been exploited by ransomware (WannaCry, NotPetya) and other attacks.",
                remediation="1. Disable SMBv1 protocol (legacy and insecure). 2. Enable SMB signing (prevents man-in-the-middle attacks). 3. Restrict SMB access via firewall to trusted networks only. 4. Keep Windows fully patched. 5. Use complex passwords for shared folders.",
                host=host.ip,
                port=service.port,
                protocol=service.protocol,
                service="smb"
            )

        # Telnet
        elif service.port == 23:
            finding = Finding(
                finding_id="TELNET-EXPOSED",
                severity=FindingSeverity.HIGH,
                title="Telnet Service Exposed (Unencrypted)",
                description=f"Telnet is accessible on port {service.port}. Telnet transmits all data including passwords in cleartext.",
                remediation="1. DISABLE Telnet immediately. 2. Migrate to SSH for secure remote access. 3. If Telnet is required for legacy equipment, isolate it on a separate VLAN with strict firewall rules.",
                host=host.ip,
                port=service.port,
                protocol=service.protocol,
                service="telnet"
            )

        # FTP
        elif service.port == 21:
            finding = Finding(
                finding_id="FTP-EXPOSED",
                severity=FindingSeverity.MEDIUM,
                title="FTP Service Exposed",
                description=f"FTP is accessible on port {service.port}. Standard FTP transmits credentials in cleartext.",
                remediation="1. Disable anonymous FTP access. 2. Migrate to SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS). 3. If FTP must be used, restrict access to internal networks only via firewall. 4. Use strong passwords and monitor logs.",
                host=host.ip,
                port=service.port,
                protocol=service.protocol,
                service="ftp"
            )

        # VNC
        elif service.port in [5900, 5901, 5902]:
            finding = Finding(
                finding_id="VNC-EXPOSED",
                severity=FindingSeverity.HIGH,
                title="VNC Remote Access Exposed",
                description=f"VNC is accessible on port {service.port}. VNC is often poorly secured and targeted by attackers.",
                remediation="1. Use strong VNC passwords (not the default). 2. Enable VNC encryption or tunnel through SSH/VPN. 3. Restrict access via firewall to specific IP addresses. 4. Consider using more secure alternatives like RDP with NLA or SSH tunneling.",
                host=host.ip,
                port=service.port,
                protocol=service.protocol,
                service="vnc"
            )

        # MySQL
        elif service.port == 3306:
            finding = Finding(
                finding_id="MYSQL-EXPOSED",
                severity=FindingSeverity.MEDIUM,
                title="MySQL Database Exposed to Network",
                description=f"MySQL is accessible on port {service.port}. Databases should not be directly accessible from untrusted networks.",
                remediation="1. Bind MySQL to localhost (127.0.0.1) if only local access is needed. 2. Use firewall rules to restrict access to application servers only. 3. Disable remote root login. 4. Use strong passwords and keep MySQL updated. 5. Enable SSL/TLS for MySQL connections.",
                host=host.ip,
                port=service.port,
                protocol=service.protocol,
                service="mysql"
            )

        # PostgreSQL
        elif service.port == 5432:
            finding = Finding(
                finding_id="POSTGRES-EXPOSED",
                severity=FindingSeverity.MEDIUM,
                title="PostgreSQL Database Exposed to Network",
                description=f"PostgreSQL is accessible on port {service.port}. Databases should not be directly accessible from untrusted networks.",
                remediation="1. Configure pg_hba.conf to restrict access to trusted hosts only. 2. Use firewall rules to limit access to application servers. 3. Enable SSL/TLS for PostgreSQL connections. 4. Use strong passwords and keep PostgreSQL updated. 5. Disable access for default postgres user from remote hosts.",
                host=host.ip,
                port=service.port,
                protocol=service.protocol,
                service="postgresql"
            )

        # MongoDB
        elif service.port == 27017:
            finding = Finding(
                finding_id="MONGODB-EXPOSED",
                severity=FindingSeverity.HIGH,
                title="MongoDB Database Exposed to Network",
                description=f"MongoDB is accessible on port {service.port}. MongoDB instances have been frequently targeted for data theft and ransomware.",
                remediation="1. Enable MongoDB authentication (--auth flag). 2. Bind to localhost or specific IPs only. 3. Use firewall rules to restrict access. 4. Keep MongoDB updated. 5. Enable SSL/TLS. 6. Do NOT expose MongoDB to the internet.",
                host=host.ip,
                port=service.port,
                protocol=service.protocol,
                service="mongodb"
            )

        # Redis
        elif service.port == 6379:
            finding = Finding(
                finding_id="REDIS-EXPOSED",
                severity=FindingSeverity.HIGH,
                title="Redis Database Exposed to Network",
                description=f"Redis is accessible on port {service.port}. Redis has no authentication by default and has been exploited for cryptomining and data theft.",
                remediation="1. Enable Redis authentication (requirepass in redis.conf). 2. Bind to localhost only if possible. 3. Use firewall rules to restrict access. 4. Disable dangerous commands (CONFIG, FLUSHALL, etc.) using rename-command. 5. Keep Redis updated.",
                host=host.ip,
                port=service.port,
                protocol=service.protocol,
                service="redis"
            )

        # SNMP
        elif service.port == 161 and service.protocol == "udp":
            finding = Finding(
                finding_id="SNMP-EXPOSED",
                severity=FindingSeverity.MEDIUM,
                title="SNMP Service Exposed",
                description=f"SNMP is accessible on UDP port {service.port}. SNMP can leak sensitive network information if misconfigured.",
                remediation="1. Change default SNMP community strings (not 'public' or 'private'). 2. Use SNMPv3 with encryption instead of SNMPv1/v2c. 3. Restrict SNMP access via firewall to management stations only. 4. Use read-only community strings where possible.",
                host=host.ip,
                port=service.port,
                protocol=service.protocol,
                service="snmp"
            )

        if finding:
            findings.append(finding)

    return findings


def _check_unencrypted_protocols(host: Host) -> List[Finding]:
    """Check for protocols that should use encryption."""
    findings = []

    has_http = False
    has_https = False

    for service in host.services:
        if service.state != PortState.OPEN:
            continue

        # HTTP without HTTPS
        if service.port == 80:
            has_http = True
        elif service.port == 443:
            has_https = True

    # If HTTP is open but HTTPS is also present, suggest redirect
    if has_http and has_https:
        findings.append(Finding(
            finding_id="HTTP-NO-REDIRECT",
            severity=FindingSeverity.LOW,
            title="HTTP Available Alongside HTTPS",
            description="Port 80 (HTTP) is open alongside port 443 (HTTPS). HTTP traffic should be redirected to HTTPS.",
            remediation="1. Configure web server to redirect all HTTP requests to HTTPS (301 or 302 redirect). 2. Implement HSTS (HTTP Strict Transport Security) headers to force browsers to use HTTPS. 3. Consider closing port 80 entirely if all clients support HTTPS.",
            host=host.ip,
            port=80,
            protocol="tcp",
            service="http"
        ))
    elif has_http and not has_https:
        findings.append(Finding(
            finding_id="HTTP-ONLY",
            severity=FindingSeverity.MEDIUM,
            title="HTTP Service Without HTTPS",
            description="Only HTTP (port 80) is available without HTTPS encryption. All web traffic is transmitted in cleartext.",
            remediation="1. Obtain and install an SSL/TLS certificate (free options: Let's Encrypt). 2. Configure HTTPS on port 443. 3. Redirect HTTP to HTTPS. 4. Implement HSTS headers.",
            host=host.ip,
            port=80,
            protocol="tcp",
            service="http"
        ))

    return findings


def _check_weak_tls(host: Host) -> List[Finding]:
    """Check for weak TLS configurations from NSE script output."""
    findings = []

    for service in host.services:
        if service.state != PortState.OPEN:
            continue

        # Check ssl-enum-ciphers script output
        if "ssl-enum-ciphers" in service.scripts:
            script_output = service.scripts["ssl-enum-ciphers"]

            # Simple heuristic checks
            weak_indicators = [
                ("SSLv2", "SSLv2 protocol detected", FindingSeverity.CRITICAL),
                ("SSLv3", "SSLv3 protocol detected", FindingSeverity.HIGH),
                ("TLSv1.0", "TLS 1.0 detected (deprecated)", FindingSeverity.MEDIUM),
                ("NULL", "NULL cipher detected", FindingSeverity.CRITICAL),
                ("EXPORT", "EXPORT cipher detected", FindingSeverity.HIGH),
                ("RC4", "RC4 cipher detected", FindingSeverity.HIGH),
                ("3DES", "3DES cipher detected (weak)", FindingSeverity.MEDIUM),
                ("DES", "DES cipher detected", FindingSeverity.CRITICAL),
            ]

            for indicator, description, severity in weak_indicators:
                if indicator in script_output:
                    findings.append(Finding(
                        finding_id=f"WEAK-TLS-{indicator.upper().replace('.', '')}",
                        severity=severity,
                        title=f"Weak TLS Configuration: {description}",
                        description=f"The service on port {service.port} supports weak cryptographic protocols or ciphers. {description}.",
                        remediation="1. Disable SSLv2, SSLv3, and TLS 1.0/1.1. 2. Only enable TLS 1.2 and TLS 1.3. 3. Disable weak ciphers (NULL, EXPORT, RC4, DES, 3DES). 4. Configure strong cipher suites only (AES-GCM, ChaCha20-Poly1305). 5. Test configuration with SSL Labs or similar tools.",
                        host=host.ip,
                        port=service.port,
                        protocol=service.protocol,
                        service=service.service,
                        evidence=indicator
                    ))

        # Check for SSLv2 specifically
        if "sslv2-drown" in service.scripts or "sslv2" in service.scripts:
            findings.append(Finding(
                finding_id="SSLV2-VULNERABLE",
                severity=FindingSeverity.CRITICAL,
                title="SSLv2 Enabled (DROWN Vulnerability)",
                description=f"SSLv2 is enabled on port {service.port}. This is vulnerable to the DROWN attack (CVE-2016-0800) which can decrypt TLS sessions.",
                remediation="1. IMMEDIATELY disable SSLv2 on all services. 2. Ensure only TLS 1.2+ is enabled. 3. Restart affected services after configuration changes. 4. Verify with vulnerability scanners.",
                host=host.ip,
                port=service.port,
                protocol=service.protocol,
                service=service.service
            ))

    return findings


def _check_smb_security(host: Host) -> List[Finding]:
    """Check SMB-specific security issues from NSE scripts."""
    findings = []

    for service in host.services:
        if service.state != PortState.OPEN:
            continue

        if service.port not in [139, 445]:
            continue

        # Check SMB signing
        if "smb2-security-mode" in service.scripts or "smb-security-mode" in service.scripts:
            script_name = "smb2-security-mode" if "smb2-security-mode" in service.scripts else "smb-security-mode"
            script_output = service.scripts[script_name]

            if "signing" in script_output.lower():
                if "disabled" in script_output.lower() or "not required" in script_output.lower():
                    findings.append(Finding(
                        finding_id="SMB-SIGNING-DISABLED",
                        severity=FindingSeverity.HIGH,
                        title="SMB Signing Not Required",
                        description=f"SMB signing is not required on port {service.port}. This allows man-in-the-middle attacks and SMB relay attacks.",
                        remediation="1. Enable 'Require SMB Signing' in Windows Group Policy or samba configuration. 2. This prevents relay attacks and ensures message integrity. 3. Note: May have minor performance impact on very high-traffic file servers.",
                        host=host.ip,
                        port=service.port,
                        protocol=service.protocol,
                        service="smb",
                        evidence="SMB signing disabled or not required"
                    ))

        # Check for SMBv1
        if "smb2-enabled" in service.scripts:
            script_output = service.scripts["smb2-enabled"]
            if "false" in script_output.lower() or "smb1" in script_output.lower():
                findings.append(Finding(
                    finding_id="SMBV1-ENABLED",
                    severity=FindingSeverity.HIGH,
                    title="SMBv1 Protocol Enabled",
                    description=f"SMBv1 is enabled on port {service.port}. SMBv1 is outdated and was exploited by WannaCry ransomware (EternalBlue vulnerability).",
                    remediation="1. DISABLE SMBv1 immediately (Windows: Uninstall via Windows Features, or PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol). 2. Ensure SMBv2/v3 is enabled. 3. Verify no legacy systems depend on SMBv1. 4. Apply all Windows security updates.",
                    host=host.ip,
                    port=service.port,
                    protocol=service.protocol,
                    service="smb",
                    evidence="SMBv1 detected"
                ))

    return findings


def _check_ssh_security(host: Host) -> List[Finding]:
    """Check SSH security from NSE scripts."""
    findings = []

    for service in host.services:
        if service.state != PortState.OPEN:
            continue

        if service.port != 22 or service.service != "ssh":
            continue

        # Check SSH algorithms
        if "ssh2-enum-algos" in service.scripts:
            script_output = service.scripts["ssh2-enum-algos"]

            # Check for weak MACs
            weak_macs = ["md5", "sha1", "96"]
            for weak_mac in weak_macs:
                if weak_mac in script_output.lower():
                    findings.append(Finding(
                        finding_id="SSH-WEAK-MAC",
                        severity=FindingSeverity.MEDIUM,
                        title="SSH Weak MAC Algorithms Enabled",
                        description=f"SSH service on port {service.port} supports weak MAC (Message Authentication Code) algorithms.",
                        remediation="1. Edit /etc/ssh/sshd_config and set MACs to strong algorithms only (e.g., hmac-sha2-256, hmac-sha2-512). 2. Remove MD5 and SHA1-based MACs. 3. Restart SSH service. 4. Test with 'ssh -vv' to verify configuration.",
                        host=host.ip,
                        port=service.port,
                        protocol=service.protocol,
                        service="ssh",
                        evidence=f"Weak MAC algorithm: {weak_mac}"
                    ))
                    break

            # Check for weak key exchange
            weak_kex = ["diffie-hellman-group1", "diffie-hellman-group14-sha1"]
            for weak in weak_kex:
                if weak in script_output.lower():
                    findings.append(Finding(
                        finding_id="SSH-WEAK-KEX",
                        severity=FindingSeverity.MEDIUM,
                        title="SSH Weak Key Exchange Algorithm",
                        description=f"SSH service on port {service.port} supports weak key exchange algorithms.",
                        remediation="1. Edit /etc/ssh/sshd_config and set KexAlgorithms to strong options (e.g., curve25519-sha256, diffie-hellman-group-exchange-sha256). 2. Remove group1 and SHA1-based key exchange. 3. Restart SSH service.",
                        host=host.ip,
                        port=service.port,
                        protocol=service.protocol,
                        service="ssh",
                        evidence=f"Weak key exchange: {weak}"
                    ))
                    break

    return findings


def _check_http_security(host: Host) -> List[Finding]:
    """Check HTTP security headers from NSE scripts."""
    findings = []

    for service in host.services:
        if service.state != PortState.OPEN:
            continue

        if service.port not in [80, 443, 8080, 8443]:
            continue

        # Check security headers
        if "http-security-headers" in service.scripts or "http-headers" in service.scripts:
            script_name = "http-security-headers" if "http-security-headers" in service.scripts else "http-headers"
            script_output = service.scripts[script_name]

            missing_headers = []

            if "strict-transport-security" not in script_output.lower() and service.port == 443:
                missing_headers.append("Strict-Transport-Security (HSTS)")

            if "x-frame-options" not in script_output.lower():
                missing_headers.append("X-Frame-Options")

            if "x-content-type-options" not in script_output.lower():
                missing_headers.append("X-Content-Type-Options")

            if missing_headers:
                findings.append(Finding(
                    finding_id="HTTP-MISSING-SECURITY-HEADERS",
                    severity=FindingSeverity.LOW,
                    title="Missing HTTP Security Headers",
                    description=f"Web service on port {service.port} is missing important security headers: {', '.join(missing_headers)}",
                    remediation="1. Add Strict-Transport-Security header (HSTS) to force HTTPS. 2. Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking. 3. Add X-Content-Type-Options: nosniff to prevent MIME sniffing. 4. Consider adding Content-Security-Policy (CSP) for additional protection.",
                    host=host.ip,
                    port=service.port,
                    protocol=service.protocol,
                    service=service.service or "http",
                    evidence=f"Missing: {', '.join(missing_headers)}"
                ))

    return findings


def _check_outdated_versions(host: Host) -> List[Finding]:
    """Check for outdated service versions (simple heuristic)."""
    findings = []

    for service in host.services:
        if service.state != PortState.OPEN:
            continue

        if not service.product or not service.version:
            continue

        product_lower = service.product.lower()
        version = service.version

        # Check against known thresholds
        for product_key, info in OUTDATED_VERSIONS.items():
            if product_key in product_lower:
                threshold = info["threshold"]
                severity = info["severity"]

                # Simple version comparison (naive, but good enough for heuristic)
                if _version_less_than(version, threshold):
                    findings.append(Finding(
                        finding_id=f"OUTDATED-{product_key.upper()}",
                        severity=severity,
                        title=f"Potentially Outdated {service.product} Version",
                        description=f"{service.product} version {version} on port {service.port} may be outdated (threshold: {threshold}). Outdated software may contain known vulnerabilities.",
                        remediation=f"1. Check vendor security bulletins for {service.product} version {version}. 2. Update to the latest stable version. 3. Implement a regular patching schedule. 4. Subscribe to security mailing lists for {service.product}. NOTE: This is a heuristic check - verify actual vulnerability status.",
                        host=host.ip,
                        port=service.port,
                        protocol=service.protocol,
                        service=service.service,
                        evidence=f"{service.product} {version} < {threshold} (heuristic)"
                    ))
                    break

    return findings


def _check_advanced_vulnerabilities(host: Host) -> List[Finding]:
    """Additional vulnerability checks for standard/aggressive profiles."""
    findings = []

    # Check for vulners script output
    for service in host.services:
        if service.state != PortState.OPEN:
            continue

        if "vulners" in service.scripts:
            script_output = service.scripts["vulners"]

            # Look for CVE mentions
            if "CVE-" in script_output:
                findings.append(Finding(
                    finding_id="VULNERS-CVE-DETECTED",
                    severity=FindingSeverity.HIGH,
                    title="Potential CVE Vulnerabilities Detected",
                    description=f"The vulners NSE script detected potential CVE vulnerabilities on port {service.port}. Review the evidence for details.",
                    remediation="1. Review the specific CVEs identified in the evidence. 2. Check vendor advisories for patches. 3. Apply security updates immediately for critical vulnerabilities. 4. Consider workarounds or firewall rules if patches are not available. 5. Verify exploitability in your environment.",
                    host=host.ip,
                    port=service.port,
                    protocol=service.protocol,
                    service=service.service,
                    evidence=script_output[:500]  # Truncate for brevity
                ))

    return findings


def _version_less_than(version: str, threshold: str) -> bool:
    """
    Simple version comparison (naive implementation).

    Args:
        version: Version string to check
        threshold: Threshold version

    Returns:
        True if version appears to be less than threshold
    """
    try:
        # Extract numeric parts
        v_parts = [int(x) for x in version.split('.')[:3] if x.isdigit()]
        t_parts = [int(x) for x in threshold.split('.')[:3] if x.isdigit()]

        # Pad to same length
        while len(v_parts) < 3:
            v_parts.append(0)
        while len(t_parts) < 3:
            t_parts.append(0)

        # Compare
        return v_parts < t_parts

    except Exception:
        # If parsing fails, don't flag
        return False


def _count_by_severity(result: ScanResult) -> Dict[str, int]:
    """Count findings by severity across all hosts."""
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for host in result.hosts:
        for finding in host.findings:
            severity_key = finding.severity.value if isinstance(finding.severity, FindingSeverity) else finding.severity
            if severity_key in counts:
                counts[severity_key] += 1

    return counts


def get_top_quick_fixes(result: ScanResult, limit: int = 5) -> List[Dict[str, Any]]:
    """
    Get top quick fixes based on severity and frequency.

    Args:
        result: Scan result
        limit: Maximum number of fixes to return

    Returns:
        List of quick fix recommendations
    """
    # Count findings by ID
    finding_counts: Dict[str, Dict[str, Any]] = {}

    for host in result.hosts:
        for finding in host.findings:
            if finding.finding_id not in finding_counts:
                finding_counts[finding.finding_id] = {
                    "id": finding.finding_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "remediation": finding.remediation,
                    "count": 0,
                    "hosts": []
                }
            finding_counts[finding.finding_id]["count"] += 1
            finding_counts[finding.finding_id]["hosts"].append(host.ip)

    # Sort by severity then count
    severity_order = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 3,
        FindingSeverity.INFO: 4
    }

    sorted_findings = sorted(
        finding_counts.values(),
        key=lambda x: (
            severity_order.get(x["severity"], 99),
            -x["count"]
        )
    )

    return sorted_findings[:limit]
