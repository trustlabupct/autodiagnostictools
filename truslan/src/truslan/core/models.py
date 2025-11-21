"""
Data models for truslan.

All data structures use dataclasses for type safety and validation.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class ScanProfile(str, Enum):
    """Scan profile levels."""
    SAFE = "safe"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


class FindingSeverity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PortState(str, Enum):
    """Port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"


@dataclass
class Service:
    """Service detected on a port."""
    port: int
    protocol: str  # tcp or udp
    state: PortState
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    cpe: List[str] = field(default_factory=list)
    scripts: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state.value if isinstance(self.state, PortState) else self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "cpe": self.cpe,
            "scripts": self.scripts
        }


@dataclass
class OSMatch:
    """Operating system detection match."""
    name: str
    accuracy: int
    osclass: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "accuracy": self.accuracy,
            "osclass": self.osclass
        }


@dataclass
class Finding:
    """Security finding."""
    finding_id: str
    severity: FindingSeverity
    title: str
    description: str
    remediation: str
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "severity": self.severity.value if isinstance(self.severity, FindingSeverity) else self.severity,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "evidence": self.evidence
        }


@dataclass
class Host:
    """Scanned host with services and findings."""
    ip: str
    hostname: Optional[str] = None
    state: str = "unknown"
    os_matches: List[OSMatch] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "os_matches": [osm.to_dict() for osm in self.os_matches],
            "services": [svc.to_dict() for svc in self.services],
            "findings": [f.to_dict() for f in self.findings],
            "mac_address": self.mac_address,
            "mac_vendor": self.mac_vendor
        }


@dataclass
class ScanOptions:
    """Scan execution options."""
    profile: ScanProfile
    cidr_list: List[str]
    mode: str  # "top" or "ports"
    top_ports: Optional[int] = None
    port_list: Optional[str] = None
    udp: bool = False
    udp_ports: Optional[str] = None
    timing: str = "T3"
    host_timeout: str = "30s"
    max_retries: Optional[int] = None
    script_timeout: str = "30s"
    allow_intrusive: bool = False
    authorized: bool = False
    nse_strict: bool = False
    fail_on_errors: bool = False
    trust_discovery: bool = False
    prefer_vulners: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "profile": self.profile.value if isinstance(self.profile, ScanProfile) else self.profile,
            "cidr_list": self.cidr_list,
            "mode": self.mode,
            "top_ports": self.top_ports,
            "port_list": self.port_list,
            "udp": self.udp,
            "udp_ports": self.udp_ports,
            "timing": self.timing,
            "host_timeout": self.host_timeout,
            "max_retries": self.max_retries,
            "prefer_vulners": self.prefer_vulners,
            "script_timeout": self.script_timeout,
            "allow_intrusive": self.allow_intrusive,
            "authorized": self.authorized,
            "nse_strict": self.nse_strict,
            "fail_on_errors": self.fail_on_errors,
            "trust_discovery": self.trust_discovery
        }


@dataclass
class ScanMeta:
    """Scan metadata."""
    profile: ScanProfile
    options: ScanOptions
    started_at: datetime
    finished_at: Optional[datetime] = None
    nmap_commands: List[str] = field(default_factory=list)
    nmap_version: Optional[str] = None
    platform: Optional[str] = None
    scanner_version: str = "1.3.0"
    batches_total: int = 0
    batches_failed: int = 0
    batches_retried: int = 0
    batch_errors: List[Dict[str, Any]] = field(default_factory=list)
    scripts_requested: int = 0
    scripts_skipped_missing: List[str] = field(default_factory=list)
    scripts_skipped_runtime: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "profile": self.profile.value if isinstance(self.profile, ScanProfile) else self.profile,
            "options": self.options.to_dict() if hasattr(self.options, 'to_dict') else self.options,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "nmap_commands": self.nmap_commands,
            "nmap_version": self.nmap_version,
            "platform": self.platform,
            "scanner_version": self.scanner_version,
            "batches_total": self.batches_total,
            "batches_failed": self.batches_failed,
            "batches_retried": self.batches_retried,
            "batch_errors": self.batch_errors,
            "scripts_requested": self.scripts_requested,
            "scripts_skipped_missing": self.scripts_skipped_missing,
            "scripts_skipped_runtime": self.scripts_skipped_runtime
        }


@dataclass
class ScanResult:
    """Complete scan result."""
    meta: ScanMeta
    hosts: List[Host] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    partial_failure: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "meta": self.meta.to_dict(),
            "hosts": [h.to_dict() for h in self.hosts],
            "summary": self.summary,
            "partial_failure": self.partial_failure
        }


@dataclass
class NmapInvocation:
    """Single nmap command invocation plan."""
    targets: List[str]
    arguments: List[str]
    description: str

    def to_command(self) -> List[str]:
        """Build command list for subprocess."""
        cmd = ["nmap"] + self.arguments + self.targets
        return cmd

    def to_string(self) -> str:
        """Build command string for logging."""
        return " ".join(self.to_command())
