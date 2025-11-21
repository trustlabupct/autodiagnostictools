"""
Nmap scanner orchestration for truslan.

Centralized profile-to-options mapping with privilege-aware execution.
Two-phase scanning: discovery first, then targeted scanning of live hosts.
"""

import subprocess
import json
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime
from pathlib import Path
import tempfile

from .models import (
    ScanProfile, ScanOptions, NmapInvocation, Host, Service,
    PortState, OSMatch, ScanResult, ScanMeta
)
from .utils import is_root, run_command, check_nmap_installed, ProgressTracker
from .nse import (
    NSEResolver, NSEScriptSet, SAFE_SCRIPTS_EXPLICIT, STANDARD_SCRIPTS_EXPLICIT,
    AGGRESSIVE_SCRIPTS_EXPLICIT, is_nse_init_error, parse_nse_init_error
)

logger = logging.getLogger("truslan")



# NSE Script Categories
# Note: Explicit script lists moved to nse.py module (v1.2.3)
SAFE_NSE_CATEGORIES = ["default", "safe"]
STANDARD_NSE_CATEGORIES = ["default", "safe"]
AGGRESSIVE_NSE_CATEGORIES = ["default", "safe"]

# Business ports - common services in SMB environments
BUSINESS_PORTS = "22,80,443,445,139,3389,3306,5432,5900,8080,8000-8100,25,110,143,993,995,515,631,9100"

# Default UDP port lists by profile
UDP_PORTS_SAFE = "53,123,161,5353"
UDP_PORTS_STANDARD = "53,67,68,69,123,135,137,138,139,161,500,5353"
UDP_PORTS_AGGRESSIVE = "53,67,68,69,123,135,137,138,139,161,162,500,514,520,1900,4500,5353"

# Configuration
DEFAULT_PORT_PROFILE = "business"  # or "top1000"
BATCH_SIZE = 64  # Number of hosts per scan batch


def build_scan_plan(
    options: ScanOptions,
    nmap_path: str = "nmap",
    batch_size: int = BATCH_SIZE
) -> List[NmapInvocation]:
    """
    Build nmap invocation plan from scan options.

    Implements two-phase scanning:
    1. Discovery phase: find live hosts
    2. Scan phase: scan live hosts in batches

    Centralizes all profile-to-nmap-args mapping logic.

    Args:
        options: Validated scan options
        nmap_path: Path to nmap binary
        batch_size: Number of hosts per batch

    Returns:
        List of NmapInvocation objects (discovery + scan batches)
    """
    logger.info(f"Building scan plan for profile: {options.profile.value}")

    invocations = []

    # Phase 1: Discovery scan to find live hosts
    discovery_inv = _build_discovery_scan(options, nmap_path)
    invocations.append(discovery_inv)

    # Phase 2 will be built after discovery completes
    # (see execute_scan for dynamic batch building)

    return invocations


def _build_discovery_scan(options: ScanOptions, nmap_path: str = "nmap") -> NmapInvocation:
    """Build discovery scan to find live hosts."""
    args = ["-sn", "-n"]  # Ping scan, no DNS

    description = f"Finding live hosts in {', '.join(options.cidr_list)}"

    return NmapInvocation(
        targets=options.cidr_list,
        arguments=args,
        description=description
    )


def _build_tcp_scan(
    options: ScanOptions,
    targets: List[str],
    nmap_path: str = "nmap",
    nse_script_set: Optional[NSEScriptSet] = None
) -> NmapInvocation:
    """
    Build TCP scan invocation based on profile.

    Args:
        options: Scan options
        targets: List of IP addresses to scan
        nmap_path: Path to nmap binary
        nse_script_set: Resolved NSE script set (optional, will resolve if not provided)
    """
    args = []

    # Trust discovery: skip host discovery in Phase 2 if requested
    if options.trust_discovery:
        args.append("-Pn")  # Treat all hosts as online

    # Privilege-aware scan type
    if is_root():
        args.append("-sS")  # SYN scan
        scan_type = "SYN"
    else:
        args.append("-sT")  # TCP Connect scan
        scan_type = "Connect"
        logger.warning("Running without root/admin privileges. Using TCP Connect scan (-sT) instead of SYN scan (-sS).")

    # Port specification - check for business ports mode
    if options.mode == "top":
        top_count = options.top_ports or _get_default_top_ports(options.profile)

        # Check if we should use business ports instead
        if (options.profile == ScanProfile.SAFE and
            top_count == 200 and
            DEFAULT_PORT_PROFILE == "business"):
            args.append("-p")
            args.append(BUSINESS_PORTS)
            port_desc = f"business ports ({BUSINESS_PORTS[:40]}...)"
        else:
            args.append(f"--top-ports")
            args.append(str(top_count))
            port_desc = f"top {top_count} ports"
    elif options.mode == "ports":
        if not options.port_list:
            raise ValueError("Port list required when mode=ports")
        args.append("-p")
        args.append(options.port_list)
        port_desc = f"ports {options.port_list}"
    else:
        raise ValueError(f"Unknown mode: {options.mode}")

    # Service version detection
    args.append("-sV")
    if options.profile == ScanProfile.SAFE:
        args.append("--version-light")
        version_intensity = "light"
    elif options.profile == ScanProfile.STANDARD:
        args.append("--version-light")
        version_intensity = "light"
    elif options.profile == ScanProfile.AGGRESSIVE:
        args.append("--version-all")
        version_intensity = "all"
    else:
        version_intensity = "default"

    # OS detection (if privileged and profile allows)
    if options.profile in [ScanProfile.STANDARD, ScanProfile.AGGRESSIVE]:
        if is_root():
            args.append("-O")
            if options.profile == ScanProfile.AGGRESSIVE:
                args.append("--osscan-limit")
                args.append("--osscan-guess")
            os_detect = "enabled"
        else:
            os_detect = "skipped (requires root)"
            logger.info("OS detection requires root privileges, skipping")
    else:
        os_detect = "disabled"

    # NSE scripts
    if nse_script_set:
        # Use pre-resolved script set
        if not nse_script_set.is_empty():
            args.append("--script")
            args.append(nse_script_set.to_nmap_arg())
        nse_categories = nse_script_set.categories
        nse_scripts = nse_script_set.explicit_scripts
    else:
        # Fallback to old method (no filtering)
        nse_categories, nse_scripts_set = _get_nse_scripts(options)
        nse_scripts = list(nse_scripts_set)
        all_scripts = nse_categories + nse_scripts
        if all_scripts:
            args.append("--script")
            args.append(",".join(all_scripts))

    # Script timeout
    args.append("--script-timeout")
    args.append(options.script_timeout)

    # Timing
    args.append(f"-{options.timing}")

    # Host timeout
    args.append("--host-timeout")
    args.append(options.host_timeout)

    # Max retries
    if options.max_retries is not None:
        args.append("--max-retries")
        args.append(str(options.max_retries))

    # Output format
    args.append("-oX")
    args.append("-")  # Output to stdout

    # Disable DNS resolution for speed
    args.append("-n")

    # Build description with correct script breakdown
    if nse_script_set and not nse_script_set.is_empty():
        if nse_script_set.categories and nse_script_set.explicit_scripts:
            script_desc = f"categories=[{','.join(nse_script_set.categories)}], explicit=[{','.join(nse_script_set.explicit_scripts)}]"
        elif nse_script_set.categories:
            script_desc = f"categories=[{','.join(nse_script_set.categories)}]"
        elif nse_script_set.explicit_scripts:
            script_desc = f"explicit=[{','.join(nse_script_set.explicit_scripts)}]"
        else:
            script_desc = "none"
    else:
        script_desc = "none"

    trust_note = " (trust-discovery: -Pn)" if options.trust_discovery else ""

    description = (
        f"TCP {scan_type} scan: {port_desc}, "
        f"version detection ({version_intensity}), "
        f"OS detection ({os_detect}), "
        f"NSE scripts ({script_desc}), "
        f"timing {options.timing}{trust_note}"
    )

    return NmapInvocation(
        targets=targets,
        arguments=args,
        description=description
    )


def _build_udp_scan(
    options: ScanOptions,
    targets: List[str],
    nmap_path: str = "nmap",
    nse_script_set: Optional[NSEScriptSet] = None
) -> NmapInvocation:
    """
    Build UDP scan invocation based on profile.

    Args:
        options: Scan options
        targets: List of IP addresses to scan
        nmap_path: Path to nmap binary
        nse_script_set: Resolved NSE script set (optional)
    """
    args = []

    # Trust discovery: skip host discovery in Phase 2 if requested
    if options.trust_discovery:
        args.append("-Pn")  # Treat all hosts as online

    # UDP scan (requires root)
    if not is_root():
        logger.warning("UDP scan requires root privileges, skipping")
        raise ValueError("UDP scan requires root/admin privileges")

    args.append("-sU")

    # Port specification
    if options.udp_ports:
        udp_ports = options.udp_ports
    else:
        udp_ports = _get_default_udp_ports(options.profile)

    args.append("-p")
    args.append(udp_ports)

    # Service version detection (lighter for UDP)
    args.append("-sV")
    args.append("--version-intensity")
    args.append("2")

    # Timing (usually slower for UDP)
    timing = options.timing
    if timing in ["T4", "T5"]:
        timing = "T3"  # Slow down for UDP
        logger.info("Reducing timing to T3 for UDP scan")
    args.append(f"-{timing}")

    # Host timeout (longer for UDP)
    udp_timeout = _increase_timeout(options.host_timeout)
    args.append("--host-timeout")
    args.append(udp_timeout)

    # Output format
    args.append("-oX")
    args.append("-")

    args.append("-n")

    description = f"UDP scan: ports {udp_ports}, timing {timing}"

    return NmapInvocation(
        targets=targets,
        arguments=args,
        description=description
    )


def _get_default_top_ports(profile: ScanProfile) -> int:
    """Get default top ports count for profile."""
    if profile == ScanProfile.SAFE:
        return 200
    elif profile == ScanProfile.STANDARD:
        return 1000
    elif profile == ScanProfile.AGGRESSIVE:
        return 2000
    else:
        return 1000


def _get_default_udp_ports(profile: ScanProfile) -> str:
    """Get default UDP ports for profile."""
    if profile == ScanProfile.SAFE:
        return UDP_PORTS_SAFE
    elif profile == ScanProfile.STANDARD:
        return UDP_PORTS_STANDARD
    elif profile == ScanProfile.AGGRESSIVE:
        return UDP_PORTS_AGGRESSIVE
    else:
        return UDP_PORTS_STANDARD


def _get_nse_scripts(options: ScanOptions) -> Tuple[List[str], Set[str]]:
    """
    Get NSE script categories and explicit scripts for profile.

    Returns:
        Tuple of (categories, explicit_scripts_set)
    """
    if options.profile == ScanProfile.SAFE:
        return (SAFE_NSE_CATEGORIES.copy(), SAFE_SCRIPTS_EXPLICIT.copy())
    elif options.profile == ScanProfile.STANDARD:
        return (STANDARD_NSE_CATEGORIES.copy(), STANDARD_SCRIPTS_EXPLICIT.copy())
    elif options.profile == ScanProfile.AGGRESSIVE:
        categories = AGGRESSIVE_NSE_CATEGORIES.copy()
        scripts = AGGRESSIVE_SCRIPTS_EXPLICIT.copy()
        if options.allow_intrusive:
            logger.warning("Including intrusive NSE scripts - use with caution!")
            categories.append("intrusive")
        return (categories, scripts)
    else:
        return (["default", "safe"], set())


def _increase_timeout(timeout: str) -> str:
    """Increase timeout value for UDP scans."""
    # Parse timeout (e.g., "30s", "1m")
    import re
    match = re.match(r'(\d+)([smh])', timeout)
    if match:
        value, unit = match.groups()
        value = int(value)
        if unit == 's':
            value = min(value * 2, 300)  # Cap at 5 minutes
        return f"{value}{unit}"
    return timeout


def execute_scan(
    invocations: List[NmapInvocation],
    options: ScanOptions,
    nmap_path: str = "nmap",
    save_xml_dir: Optional[Path] = None,
    batch_size: int = BATCH_SIZE,
    disable_progress: bool = False,
    nse_resolver: Optional[NSEResolver] = None
) -> ScanResult:
    """
    Execute scan plan with two-phase approach and parse results.

    Phase 1: Discovery to find live hosts
    Phase 2: Targeted scanning of live hosts in batches

    Args:
        invocations: Initial list of nmap invocations (discovery)
        options: Scan options
        nmap_path: Path to nmap binary
        save_xml_dir: Directory to save raw XML files (optional)
        batch_size: Number of hosts per batch
        disable_progress: Disable progress bars

    Returns:
        ScanResult with parsed data
    """
    started_at = datetime.now()
    all_hosts: Dict[str, Host] = {}
    nmap_commands = []
    batch_errors = []
    batches_failed_count = 0
    batches_retried_count = 0
    scripts_skipped_runtime = []

    # Check nmap is installed
    nmap_installed, nmap_version = check_nmap_installed()
    if not nmap_installed:
        raise RuntimeError("nmap is not installed or not in PATH")

    logger.info(f"Using nmap version: {nmap_version}")

    # Initialize NSE resolver if not provided
    if nse_resolver is None:
        nse_resolver = NSEResolver(nmap_path=nmap_path, strict=options.nse_strict)

    # Resolve NSE scripts once for all batches
    nse_categories, nse_scripts_set = _get_nse_scripts(options)
    try:
        nse_script_set = nse_resolver.resolve_scripts(nse_categories, nse_scripts_set)
        logger.debug(f"Resolved NSE scripts: categories={nse_categories}, explicit={len(nse_script_set.explicit_scripts)} of {nse_script_set.scripts_requested}")

        # Warn if prefer_vulners is set but vulners is missing
        if options.prefer_vulners and "vulners" in nse_script_set.scripts_skipped_missing:
            logger.warning("The 'vulners' NSE script is not available in your Nmap installation.")
            logger.warning("For installation instructions, run: truslan list-scripts --explain vulners")

    except ValueError as e:
        logger.error(f"NSE script resolution failed: {e}")
        raise

    # Phase 1: Discovery
    logger.info("Phase 1 - Discovery")
    live_hosts = _execute_discovery(
        invocations[0],
        nmap_commands,
        save_xml_dir,
        disable_progress
    )

    hosts_discovered = len(live_hosts)

    if not live_hosts:
        logger.warning("No live hosts found during discovery")
        finished_at = datetime.now()
        meta = _build_scan_meta(
            options, started_at, finished_at, nmap_commands, nmap_version
        )
        meta.scripts_requested = nse_script_set.scripts_requested
        meta.scripts_skipped_missing = nse_script_set.scripts_skipped_missing
        return ScanResult(
            meta=meta,
            hosts=[],
            summary={
                "hosts_total": 0,
                "hosts_up": 0,
                "services_total": 0,
                "services_open": 0,
                "duration_seconds": (finished_at - started_at).total_seconds()
            },
            partial_failure=False
        )

    logger.info(f"Discovery complete: {len(live_hosts)} live hosts found")

    # Phase 2: Scan live hosts in batches
    logger.info(f"Phase 2 - Scanning")

    # Split hosts into batches
    host_batches = [
        list(live_hosts)[i:i + batch_size]
        for i in range(0, len(live_hosts), batch_size)
    ]

    logger.info(f"Scanning {len(live_hosts)} hosts in {len(host_batches)} batches")

    # Execute TCP scans
    with ProgressTracker(
        total=len(host_batches),
        desc="Scanning batches",
        disable=disable_progress or not live_hosts
    ) as progress:
        for batch_idx, host_batch in enumerate(host_batches, 1):
            logger.info(f"Batch {batch_idx}/{len(host_batches)}: scanning {len(host_batch)} hosts")

            # Build TCP scan for this batch with resolved NSE scripts
            tcp_inv = _build_tcp_scan(options, host_batch, nmap_path, nse_script_set)

            # Execute scan with retry on NSE init error
            batch_success, hosts, batch_error = _execute_batch_with_retry(
                tcp_inv,
                nmap_commands,
                save_xml_dir,
                batch_idx,
                "tcp",
                options,
                nmap_path,
                nse_resolver,
                nse_script_set
            )

            if not batch_success:
                batches_failed_count += 1
                if batch_error:
                    batch_errors.append(batch_error)
                    if batch_error.get('retried'):
                        batches_retried_count += 1
                    if batch_error.get('scripts_skipped'):
                        scripts_skipped_runtime.extend(batch_error['scripts_skipped'])

                if options.fail_on_errors:
                    logger.error(f"Batch {batch_idx} failed and --fail-on-errors is set, aborting")
                    break

            # Merge hosts
            for host in hosts:
                if host.ip in all_hosts:
                    _merge_host_data(all_hosts[host.ip], host)
                else:
                    all_hosts[host.ip] = host

            progress.update(1)

    # Execute UDP scans if requested
    if options.udp and is_root():
        logger.info("Phase 3 - UDP Scanning")
        with ProgressTracker(
            total=len(host_batches),
            desc="UDP scanning",
            disable=disable_progress
        ) as progress:
            for batch_idx, host_batch in enumerate(host_batches, 1):
                try:
                    udp_inv = _build_udp_scan(options, host_batch, nmap_path, nse_script_set)
                    returncode, stderr, hosts = _execute_single_scan(
                        udp_inv,
                        nmap_commands,
                        save_xml_dir,
                        batch_idx,
                        "udp"
                    )

                    for host in hosts:
                        if host.ip in all_hosts:
                            _merge_host_data(all_hosts[host.ip], host)
                        else:
                            all_hosts[host.ip] = host

                    progress.update(1)
                except Exception as e:
                    logger.warning(f"UDP scan batch {batch_idx} failed: {e}")
                    batches_failed_count += 1
                    progress.update(1)

    finished_at = datetime.now()

    # Build metadata with batch tracking
    meta = _build_scan_meta(
        options, started_at, finished_at, nmap_commands, nmap_version
    )
    meta.batches_total = len(host_batches)
    meta.batches_failed = batches_failed_count
    meta.batches_retried = batches_retried_count
    meta.batch_errors = batch_errors
    meta.scripts_requested = nse_script_set.scripts_requested
    meta.scripts_skipped_missing = nse_script_set.scripts_skipped_missing
    meta.scripts_skipped_runtime = list(set(scripts_skipped_runtime))  # Deduplicate

    # Build summary from parsed services
    hosts_list = list(all_hosts.values())
    total_services = sum(len(h.services) for h in hosts_list)
    open_services = sum(
        len([s for s in h.services if s.state == PortState.OPEN])
        for h in hosts_list
    )

    hosts_marked_up = len([h for h in hosts_list if h.state == "up"])
    hosts_scanned_targets = len(live_hosts) if live_hosts else 0
    hosts_unresponsive = max(0, hosts_scanned_targets - hosts_marked_up)

    summary = {
        "hosts_total": hosts_discovered,  # Use discovery count, not scanned count
        "hosts_discovered": hosts_discovered,  # Track discovered count separately (Phase 1)
        "hosts_scanned_targets": hosts_scanned_targets,  # Number of hosts sent to Phase 2
        "hosts_marked_up_by_scanner": hosts_marked_up,  # Hosts Nmap marked as up in Phase 2
        "hosts_unresponsive_after_discovery": hosts_unresponsive,  # Discovered but not marked up
        "hosts_up": hosts_marked_up,  # For backward compatibility
        "services_total": total_services,
        "services_open": open_services,
        "duration_seconds": (finished_at - started_at).total_seconds()
    }

    partial_failure = batches_failed_count > 0

    result = ScanResult(
        meta=meta,
        hosts=hosts_list,
        summary=summary,
        partial_failure=partial_failure
    )

    # Log completion status
    if partial_failure:
        logger.warning(f"SCAN COMPLETED WITH WARNINGS")
        logger.warning(f"  Hosts discovered: {hosts_discovered}")
        logger.warning(f"  Hosts scanned: {summary['hosts_up']} of {hosts_discovered}")
        logger.warning(f"  Batches failed: {batches_failed_count} of {meta.batches_total}")
        if meta.scripts_skipped_missing:
            logger.warning(f"  Scripts missing: {', '.join(meta.scripts_skipped_missing)}")
        if meta.scripts_skipped_runtime:
            logger.warning(f"  Scripts failed at runtime: {', '.join(meta.scripts_skipped_runtime)}")
        logger.warning(f"  See scan JSON meta.batch_errors for details")
    else:
        logger.info(f"SCAN COMPLETE")
        logger.info(f"  Hosts: {summary['hosts_up']} up, {summary['services_open']} open ports")

    return result


def _build_scan_meta(
    options: ScanOptions,
    started_at: datetime,
    finished_at: datetime,
    nmap_commands: List[str],
    nmap_version: str
) -> ScanMeta:
    """Build scan metadata."""
    import platform as plat
    return ScanMeta(
        profile=options.profile,
        options=options,
        started_at=started_at,
        finished_at=finished_at,
        nmap_commands=nmap_commands,
        nmap_version=nmap_version,
        platform=plat.system()
    )


def _execute_discovery(
    discovery_inv: NmapInvocation,
    nmap_commands: List[str],
    save_xml_dir: Optional[Path],
    disable_progress: bool
) -> Set[str]:
    """
    Execute discovery scan and return set of live host IPs.

    Args:
        discovery_inv: Discovery invocation
        nmap_commands: List to append commands to
        save_xml_dir: Directory to save XML (optional)
        disable_progress: Whether to disable progress

    Returns:
        Set of live host IP addresses
    """
    logger.info(f"{discovery_inv.description}")
    logger.debug(f"Command: {discovery_inv.to_string()}")

    nmap_commands.append(discovery_inv.to_string())

    try:
        cmd = discovery_inv.to_command()
        cmd.extend(["-oX", "-"])  # XML output to stdout

        returncode, stdout, stderr = run_command(
            cmd,
            timeout=1800,  # 30 minutes for discovery
            check=False
        )

        if returncode != 0:
            logger.warning(f"Discovery returned non-zero exit code: {returncode}")
            if stderr:
                logger.warning(f"Discovery stderr: {stderr}")

        # Save XML if requested
        if save_xml_dir:
            xml_file = save_xml_dir / "discovery.xml"
            xml_file.write_text(stdout)
            logger.debug(f"Saved discovery XML to {xml_file}")

        # Parse for live hosts
        hosts = _parse_nmap_xml(stdout)
        live_ips = {h.ip for h in hosts if h.state == "up"}

        return live_ips

    except subprocess.TimeoutExpired:
        logger.error("Discovery timed out after 30 minutes")
        return set()
    except Exception as e:
        logger.error(f"Discovery failed: {e}")
        return set()


def _execute_batch_with_retry(
    invocation: NmapInvocation,
    nmap_commands: List[str],
    save_xml_dir: Optional[Path],
    batch_idx: int,
    scan_type: str,
    options: ScanOptions,
    nmap_path: str,
    nse_resolver: NSEResolver,
    nse_script_set: NSEScriptSet
) -> Tuple[bool, List[Host], Optional[Dict[str, Any]]]:
    """
    Execute a scan batch with automatic retry on NSE init errors.

    Args:
        invocation: Scan invocation
        nmap_commands: List to append commands to
        save_xml_dir: Directory to save XML (optional)
        batch_idx: Batch number for logging
        scan_type: Type of scan (tcp/udp) for logging
        options: Scan options
        nmap_path: Path to nmap binary
        nse_resolver: NSE resolver instance
        nse_script_set: Current NSE script set

    Returns:
        Tuple of (success, hosts, error_dict)
    """
    # First attempt
    returncode, stderr, hosts = _execute_single_scan(
        invocation,
        nmap_commands,
        save_xml_dir,
        batch_idx,
        scan_type
    )

    # Check if this is an NSE initialization error
    if returncode != 0 and is_nse_init_error(returncode, stderr):
        logger.warning(f"Batch {batch_idx}: NSE initialization error detected")

        # Parse offending scripts
        offending_scripts = parse_nse_init_error(stderr)

        if offending_scripts:
            logger.warning(f"Batch {batch_idx}: retrying without scripts: {', '.join(offending_scripts)}")

            # Build new script set excluding offending scripts
            nse_categories, nse_scripts_set = _get_nse_scripts(options)
            retry_script_set = nse_resolver.resolve_scripts(
                nse_categories,
                nse_scripts_set,
                exclude_scripts=set(offending_scripts)
            )

            # Rebuild invocation with new script set
            retry_inv = _build_tcp_scan(options, invocation.targets, nmap_path, retry_script_set)

            # Retry once
            returncode_retry, stderr_retry, hosts_retry = _execute_single_scan(
                retry_inv,
                nmap_commands,
                save_xml_dir,
                batch_idx,
                scan_type + "-retry"
            )

            # Build error dict
            error_dict = {
                "batch": batch_idx,
                "scan_type": scan_type,
                "first_returncode": returncode,
                "first_stderr": stderr[:500],  # Truncate
                "retry_returncode": returncode_retry,
                "retry_stderr": stderr_retry[:500] if stderr_retry else "",
                "scripts_skipped": offending_scripts,
                "retried": True
            }

            if returncode_retry == 0:
                logger.info(f"Batch {batch_idx}: retry succeeded")
                return (True, hosts_retry, error_dict)
            else:
                logger.error(f"Batch {batch_idx}: retry failed with code {returncode_retry}")
                return (False, hosts_retry, error_dict)
        else:
            # NSE error but couldn't parse scripts
            error_dict = {
                "batch": batch_idx,
                "scan_type": scan_type,
                "returncode": returncode,
                "stderr": stderr[:500],
                "scripts_skipped": [],
                "retried": False
            }
            return (False, hosts, error_dict)

    # No NSE error or successful on first try
    if returncode == 0:
        return (True, hosts, None)
    else:
        error_dict = {
            "batch": batch_idx,
            "scan_type": scan_type,
            "returncode": returncode,
            "stderr": stderr[:500],
            "scripts_skipped": [],
            "retried": False
        }
        return (False, hosts, error_dict)


def _execute_single_scan(
    invocation: NmapInvocation,
    nmap_commands: List[str],
    save_xml_dir: Optional[Path],
    batch_idx: int,
    scan_type: str
) -> Tuple[int, str, List[Host]]:
    """
    Execute a single scan invocation and return parsed hosts.

    Args:
        invocation: Scan invocation
        nmap_commands: List to append commands to
        save_xml_dir: Directory to save XML (optional)
        batch_idx: Batch number for logging
        scan_type: Type of scan (tcp/udp) for logging

    Returns:
        Tuple of (returncode, stderr, hosts)
    """
    logger.debug(f"Command: {invocation.to_string()}")
    nmap_commands.append(invocation.to_string())

    try:
        cmd = invocation.to_command()
        returncode, stdout, stderr = run_command(
            cmd,
            timeout=3600,
            check=False
        )

        if returncode != 0:
            logger.warning(f"Scan batch {batch_idx} ({scan_type}) returned code {returncode}")
            if stderr:
                logger.warning(f"Stderr: {stderr}")

        # Save XML if requested
        if save_xml_dir:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            xml_file = save_xml_dir / f"scan-{timestamp}-batch{batch_idx}-{scan_type}.xml"
            xml_file.write_text(stdout)
            logger.debug(f"Saved XML to {xml_file}")

        # Parse hosts
        hosts = _parse_nmap_xml(stdout)
        logger.debug(f"Batch {batch_idx} ({scan_type}): parsed {len(hosts)} hosts")

        return (returncode, stderr, hosts)

    except subprocess.TimeoutExpired:
        logger.error(f"Scan batch {batch_idx} ({scan_type}) timed out")
        return (1, "Timeout", [])
    except Exception as e:
        logger.error(f"Scan batch {batch_idx} ({scan_type}) failed: {e}")
        return (1, str(e), [])


def _merge_host_data(existing: Host, new: Host) -> None:
    """
    Merge new host data into existing host.

    Args:
        existing: Existing host to update
        new: New host data to merge
    """
    # Merge services (avoid duplicates)
    existing_ports = {(s.port, s.protocol) for s in existing.services}
    for service in new.services:
        if (service.port, service.protocol) not in existing_ports:
            existing.services.append(service)

    # Update OS matches if better
    if new.os_matches and not existing.os_matches:
        existing.os_matches = new.os_matches

    # Update MAC if available
    if new.mac_address and not existing.mac_address:
        existing.mac_address = new.mac_address
        existing.mac_vendor = new.mac_vendor


def _parse_nmap_xml(xml_output: str) -> List[Host]:
    """
    Parse nmap XML output into Host objects.

    Args:
        xml_output: XML string from nmap -oX

    Returns:
        List of Host objects
    """
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        logger.error(f"Failed to parse nmap XML: {e}")
        return []

    hosts = []

    for host_elem in root.findall('.//host'):
        # Parse host status
        status = host_elem.find('status')
        if status is None:
            continue

        state = status.get('state', 'unknown')

        # Parse address
        address_elem = host_elem.find('address[@addrtype="ipv4"]')
        if address_elem is None:
            address_elem = host_elem.find('address[@addrtype="ipv6"]')
        if address_elem is None:
            continue

        ip = address_elem.get('addr')

        # Parse hostname
        hostname = None
        hostnames = host_elem.find('hostnames')
        if hostnames is not None:
            hostname_elem = hostnames.find('hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name')

        # Parse MAC address
        mac_address = None
        mac_vendor = None
        mac_elem = host_elem.find('address[@addrtype="mac"]')
        if mac_elem is not None:
            mac_address = mac_elem.get('addr')
            mac_vendor = mac_elem.get('vendor')

        # Parse OS detection
        os_matches = []
        os_elem = host_elem.find('os')
        if os_elem is not None:
            for osmatch in os_elem.findall('osmatch'):
                name = osmatch.get('name', 'Unknown')
                accuracy = int(osmatch.get('accuracy', 0))

                osclass_list = []
                for osclass in osmatch.findall('osclass'):
                    osclass_list.append({
                        'type': osclass.get('type'),
                        'vendor': osclass.get('vendor'),
                        'osfamily': osclass.get('osfamily'),
                        'osgen': osclass.get('osgen'),
                        'accuracy': osclass.get('accuracy')
                    })

                os_matches.append(OSMatch(
                    name=name,
                    accuracy=accuracy,
                    osclass=osclass_list
                ))

        # Parse ports and services
        services = []
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port_elem in ports_elem.findall('port'):
                port = int(port_elem.get('portid'))
                protocol = port_elem.get('protocol', 'tcp')

                state_elem = port_elem.find('state')
                if state_elem is None:
                    continue

                port_state_str = state_elem.get('state', 'unknown')
                try:
                    port_state = PortState(port_state_str)
                except ValueError:
                    port_state = PortState.UNKNOWN

                # Only include open ports in services list
                if port_state != PortState.OPEN:
                    continue

                # Parse service info
                service_elem = port_elem.find('service')
                service_name = None
                product = None
                version = None
                extrainfo = None
                cpe_list = []

                if service_elem is not None:
                    service_name = service_elem.get('name')
                    product = service_elem.get('product')
                    version = service_elem.get('version')
                    extrainfo = service_elem.get('extrainfo')

                    for cpe_elem in service_elem.findall('cpe'):
                        if cpe_elem.text:
                            cpe_list.append(cpe_elem.text)

                # Parse script results
                scripts = {}
                for script_elem in port_elem.findall('script'):
                    script_id = script_elem.get('id')
                    script_output = script_elem.get('output')
                    if script_id and script_output:
                        scripts[script_id] = script_output

                service = Service(
                    port=port,
                    protocol=protocol,
                    state=port_state,
                    service=service_name,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                    cpe=cpe_list,
                    scripts=scripts
                )

                services.append(service)

        host = Host(
            ip=ip,
            hostname=hostname,
            state=state,
            os_matches=os_matches,
            services=services,
            mac_address=mac_address,
            mac_vendor=mac_vendor
        )

        hosts.append(host)

    return hosts
