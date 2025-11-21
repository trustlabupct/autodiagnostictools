"""
Command-line interface for truslan.

Provides discover, scan, report, and all commands with profile-based scanning.
"""

import sys
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, List

from .core.models import ScanProfile, ScanOptions
from .core.discovery import discover_local_networks
from .core.scanners import build_scan_plan, execute_scan
from .core.checks import analyze_scan_results
from .reports.html import generate_html_report
from .reports.csv import generate_csv_report
from .core.utils import (
    logger, setup_logging, show_safety_banner, check_nmap_installed,
    parse_cidr_list, parse_port_list, save_json_file, load_json_file,
    get_nmap_privileges_warning, format_duration, load_config_from_files,
    get_env_config
)

VERSION = "1.3.0"


def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    if args.verbose:
        setup_logging(logging.DEBUG)
    elif args.quiet:
        setup_logging(logging.ERROR)
    else:
        setup_logging(logging.INFO)

    # Show safety banner on first run
    show_safety_banner()

    # Check nmap is installed
    nmap_installed, nmap_version = check_nmap_installed()
    if not nmap_installed:
        logger.error("nmap is not installed or not in PATH")
        logger.error("Please install nmap:")
        logger.error("  Ubuntu/Debian: sudo apt-get install nmap")
        logger.error("  macOS: brew install nmap")
        logger.error("  Windows: Download from https://nmap.org/download.html")
        sys.exit(1)

    # Show privilege warning if applicable
    priv_warning = get_nmap_privileges_warning()
    if priv_warning:
        logger.warning(priv_warning)

    # Dispatch to command handler
    if args.command == "discover":
        handle_discover(args)
    elif args.command == "scan":
        handle_scan(args)
    elif args.command == "report":
        handle_report(args)
    elif args.command == "all":
        handle_all(args)
    elif args.command == "list-scripts":
        handle_list_scripts(args)
    else:
        parser.print_help()
        sys.exit(1)


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="truslan",
        description="TrusLAN — LAN Exposure Scanner (SMB/RDP/HTTP/TLS/SSH/UDP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover local networks
  truslan discover

  # Safe scan of a single network
  truslan scan --cidr "192.168.1.0/24"

  # Standard scan with top 1000 ports
  truslan scan --cidr "192.168.1.0/24 10.0.0.0/24" --profile standard --mode top --top 1000

  # Aggressive scan (requires consent)
  truslan scan --cidr "192.168.1.0/24" --profile aggressive --i-am-authorized

  # Generate reports from existing scan
  truslan report --from-json out/scan.json --out-html out/report.html --out-csv out/findings.csv

  # All-in-one: discover, scan, and report
  truslan all --auto-cidr --profile standard --mode top --top 1000 --out out/
"""
    )

    parser.add_argument("--version", action="version", version=f"truslan v{VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (errors only)")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Discover command
    discover_parser = subparsers.add_parser("discover", help="Discover local network CIDRs")
    discover_parser.add_argument("--out", type=str, help="Save discovered CIDRs to file")

    # List scripts command
    list_scripts_parser = subparsers.add_parser("list-scripts", help="List available NSE scripts")
    list_scripts_parser.add_argument(
        "--nmap-path",
        type=str,
        default="nmap",
        help="Path to nmap binary (default: nmap)"
    )
    list_scripts_parser.add_argument(
        "--grep",
        type=str,
        metavar="NAME",
        help="Check if specific script NAME is available (exit 0 if present, 2 if missing)"
    )
    list_scripts_parser.add_argument(
        "--explain",
        type=str,
        metavar="NAME",
        help="Explain availability and installation for script NAME"
    )

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan network(s)")
    scan_parser.add_argument(
        "--cidr",
        type=str,
        required=True,
        help='CIDR(s) to scan (space or comma-separated, e.g., "192.168.1.0/24 10.0.0.0/24")'
    )
    scan_parser.add_argument(
        "--profile",
        type=str,
        choices=["safe", "standard", "aggressive"],
        default="safe",
        help="Scan profile: safe (default), standard, or aggressive"
    )
    scan_parser.add_argument(
        "--mode",
        type=str,
        choices=["top", "ports"],
        default="top",
        help="Port selection mode: top (top-N ports) or ports (specific list)"
    )
    scan_parser.add_argument(
        "--top",
        type=int,
        help="Number of top ports to scan (requires --mode top)"
    )
    scan_parser.add_argument(
        "--ports",
        type=str,
        help='Specific ports to scan (requires --mode ports, e.g., "22,80,443,3389")'
    )
    scan_parser.add_argument(
        "--udp",
        action="store_true",
        help="Enable UDP scanning (requires root/admin)"
    )
    scan_parser.add_argument(
        "--udp-ports",
        type=str,
        help="UDP ports to scan (comma-separated)"
    )
    scan_parser.add_argument(
        "--timing",
        type=str,
        choices=["T0", "T1", "T2", "T3", "T4", "T5"],
        help="Nmap timing template (T0=slowest, T5=fastest)"
    )
    scan_parser.add_argument(
        "--host-timeout",
        type=str,
        help="Host timeout (e.g., 30s, 5m)"
    )
    scan_parser.add_argument(
        "--max-retries",
        type=int,
        help="Maximum retries per host"
    )
    scan_parser.add_argument(
        "--script-timeout",
        type=str,
        help="NSE script timeout (e.g., 30s)"
    )
    scan_parser.add_argument(
        "--allow-intrusive",
        action="store_true",
        help="Allow intrusive NSE scripts (aggressive profile only)"
    )
    scan_parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Required flag for aggressive profile (confirms authorization)"
    )
    scan_parser.add_argument(
        "--nmap-path",
        type=str,
        default="nmap",
        help="Path to nmap binary (default: nmap)"
    )
    scan_parser.add_argument(
        "--save-xml",
        action="store_true",
        help="Save raw XML output files"
    )
    scan_parser.add_argument(
        "--batch-size",
        type=int,
        default=64,
        help="Number of hosts per scan batch (default: 64)"
    )
    scan_parser.add_argument(
        "--nse-strict",
        action="store_true",
        help="Abort if any requested NSE script is unavailable"
    )
    scan_parser.add_argument(
        "--prefer-vulners",
        action="store_true",
        help="Warn (but don't abort) if 'vulners' NSE script is missing"
    )
    scan_parser.add_argument(
        "--fail-on-errors",
        action="store_true",
        help="Abort on first batch failure (default: continue)"
    )
    scan_parser.add_argument(
        "--trust-discovery",
        action="store_true",
        help="Trust Phase 1 discovery; apply -Pn to skip host discovery in Phase 2 (may increase scan time)"
    )
    scan_parser.add_argument(
        "--out",
        type=str,
        default="./out",
        help="Output directory for scan results (default: ./out)"
    )

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate reports from scan JSON")
    report_parser.add_argument(
        "--from-json",
        type=str,
        required=True,
        help="Path to scan JSON file"
    )
    report_parser.add_argument(
        "--out-html",
        type=str,
        help="Output path for HTML report"
    )
    report_parser.add_argument(
        "--out-csv",
        type=str,
        help="Output path for CSV report"
    )

    # All command
    all_parser = subparsers.add_parser("all", help="Run discover, scan, and report in one command")
    all_parser.add_argument(
        "--auto-cidr",
        action="store_true",
        help="Automatically discover local CIDRs"
    )
    all_parser.add_argument(
        "--cidr",
        type=str,
        help='CIDR(s) to scan (alternative to --auto-cidr)'
    )
    all_parser.add_argument(
        "--profile",
        type=str,
        choices=["safe", "standard", "aggressive"],
        default="safe",
        help="Scan profile"
    )
    all_parser.add_argument(
        "--mode",
        type=str,
        choices=["top", "ports"],
        default="top",
        help="Port selection mode"
    )
    all_parser.add_argument(
        "--top",
        type=int,
        help="Number of top ports"
    )
    all_parser.add_argument(
        "--ports",
        type=str,
        help="Specific ports"
    )
    all_parser.add_argument(
        "--udp",
        action="store_true",
        help="Enable UDP scanning"
    )
    all_parser.add_argument(
        "--udp-ports",
        type=str,
        help="UDP ports"
    )
    all_parser.add_argument(
        "--timing",
        type=str,
        choices=["T0", "T1", "T2", "T3", "T4", "T5"],
        help="Nmap timing template"
    )
    all_parser.add_argument(
        "--host-timeout",
        type=str,
        help="Host timeout"
    )
    all_parser.add_argument(
        "--max-retries",
        type=int,
        help="Maximum retries"
    )
    all_parser.add_argument(
        "--script-timeout",
        type=str,
        help="Script timeout"
    )
    all_parser.add_argument(
        "--allow-intrusive",
        action="store_true",
        help="Allow intrusive scripts"
    )
    all_parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Authorization flag for aggressive profile"
    )
    all_parser.add_argument(
        "--nmap-path",
        type=str,
        default="nmap",
        help="Path to nmap binary"
    )
    all_parser.add_argument(
        "--save-xml",
        action="store_true",
        help="Save raw XML output files"
    )
    all_parser.add_argument(
        "--batch-size",
        type=int,
        default=64,
        help="Number of hosts per scan batch"
    )
    all_parser.add_argument(
        "--nse-strict",
        action="store_true",
        help="Abort if any requested NSE script is unavailable"
    )
    all_parser.add_argument(
        "--fail-on-errors",
        action="store_true",
        help="Abort on first batch failure"
    )
    all_parser.add_argument(
        "--prefer-vulners",
        action="store_true",
        help="Warn (but don't abort) if 'vulners' NSE script is missing"
    )
    all_parser.add_argument(
        "--trust-discovery",
        action="store_true",
        help="Trust Phase 1 discovery; apply -Pn to skip host discovery in Phase 2 (may increase scan time)"
    )
    all_parser.add_argument(
        "--out",
        type=str,
        default="./out",
        help="Output directory"
    )

    return parser


def handle_list_scripts(args):
    """Handle list-scripts command."""
    from .core.nse import NSEResolver

    resolver = NSEResolver(nmap_path=args.nmap_path)

    # Handle --grep flag
    if args.grep:
        available = resolver.get_available_scripts()
        if args.grep in available:
            print(f"{args.grep}: available")
            sys.exit(0)
        else:
            print(f"{args.grep}: not available")
            sys.exit(2)

    # Handle --explain flag
    if args.explain:
        info = resolver.explain_script(args.explain)
        if info["present"]:
            print(f"Script '{args.explain}' is available")
        else:
            print(f"Script '{args.explain}' is NOT available")
            if info["hint"]:
                print(f"\n{info['hint']}")
        sys.exit(0)

    # Default: list all scripts
    logger.info("Detecting available NSE scripts...")

    grouped = resolver.list_available_scripts_grouped()

    if not grouped:
        logger.error("Could not detect NSE scripts")
        sys.exit(1)

    total = sum(len(scripts) for scripts in grouped.values())
    print(f"\nAvailable NSE Scripts ({total} total):\n")

    for prefix, scripts in sorted(grouped.items()):
        print(f"{prefix.upper()} ({len(scripts)} scripts):")
        for script in scripts[:20]:  # Limit display
            print(f"  - {script}")
        if len(scripts) > 20:
            print(f"  ... and {len(scripts) - 20} more")
        print()

    sys.exit(0)


def handle_discover(args):
    """Handle discover command."""
    logger.info("Discovering local networks...")

    try:
        cidrs = discover_local_networks()

        if not cidrs:
            logger.warning("No local networks discovered")
            sys.exit(1)

        print("\nDiscovered Networks:")
        for cidr in cidrs:
            print(f"  - {cidr}")

        if args.out:
            out_path = Path(args.out)
            with open(out_path, 'w') as f:
                for cidr in cidrs:
                    f.write(f"{cidr}\n")
            logger.info(f"Saved to {out_path}")

    except Exception as e:
        logger.error(f"Discovery failed: {e}")
        sys.exit(1)


def handle_scan(args):
    """Handle scan command."""
    # Parse profile
    try:
        profile = ScanProfile(args.profile)
    except ValueError:
        logger.error(f"Invalid profile: {args.profile}")
        sys.exit(1)

    # Check authorization for aggressive profile
    if profile == ScanProfile.AGGRESSIVE and not args.i_am_authorized:
        print("\n" + "="*80, file=sys.stderr)
        print("ERROR: Aggressive profile requires explicit authorization", file=sys.stderr)
        print("="*80, file=sys.stderr)
        print("\nScanning in aggressive mode requires explicit authorization.", file=sys.stderr)
        print("This mode uses more intrusive techniques and generates more network traffic.", file=sys.stderr)
        print("\nRe-run with --i-am-authorized to confirm you have permission to scan", file=sys.stderr)
        print("the target networks with aggressive techniques.", file=sys.stderr)
        print("="*80 + "\n", file=sys.stderr)
        sys.exit(1)

    # Warn if intrusive scripts requested
    if args.allow_intrusive and profile != ScanProfile.AGGRESSIVE:
        logger.warning("--allow-intrusive only applies to aggressive profile, ignoring")
        args.allow_intrusive = False

    if args.allow_intrusive and not args.i_am_authorized:
        logger.error("--allow-intrusive requires --i-am-authorized")
        sys.exit(1)

    # Parse CIDRs
    cidrs = parse_cidr_list(args.cidr)
    if not cidrs:
        logger.error("No valid CIDRs provided")
        sys.exit(1)

    # Validate mode and port specification
    if args.mode == "top":
        if args.ports:
            logger.error("Cannot use --ports with --mode top")
            sys.exit(1)
        top_ports = args.top  # May be None, will use profile default
    elif args.mode == "ports":
        if not args.ports:
            logger.error("--mode ports requires --ports")
            sys.exit(1)
        if args.top:
            logger.error("Cannot use --top with --mode ports")
            sys.exit(1)
        top_ports = None
        try:
            port_list = parse_port_list(args.ports)
        except ValueError as e:
            logger.error(f"Invalid port specification: {e}")
            sys.exit(1)
    else:
        logger.error(f"Invalid mode: {args.mode}")
        sys.exit(1)

    # Load config defaults
    file_config = load_config_from_files()
    env_config = get_env_config()

    # Build scan options
    options = ScanOptions(
        profile=profile,
        cidr_list=cidrs,
        mode=args.mode,
        top_ports=top_ports,
        port_list=args.ports if args.mode == "ports" else None,
        udp=args.udp,
        udp_ports=args.udp_ports,
        timing=args.timing or env_config.get('timing') or file_config.get('timing') or "T3",
        host_timeout=args.host_timeout or env_config.get('host_timeout') or file_config.get('host_timeout') or "30s",
        max_retries=args.max_retries,
        script_timeout=args.script_timeout if hasattr(args, 'script_timeout') and args.script_timeout else "30s",
        allow_intrusive=args.allow_intrusive,
        authorized=args.i_am_authorized,
        nse_strict=args.nse_strict if hasattr(args, 'nse_strict') else False,
        fail_on_errors=args.fail_on_errors if hasattr(args, 'fail_on_errors') else False,
        trust_discovery=args.trust_discovery if hasattr(args, 'trust_discovery') else False,
        prefer_vulners=args.prefer_vulners if hasattr(args, 'prefer_vulners') else False
    )

    # Show scan banner
    print("\n" + "="*80)
    print(f"TrusLAN — LAN Exposure Scanner v{VERSION}")
    print("="*80)
    print(f"Profile: {profile.value.upper()}")
    print(f"Targets: {', '.join(cidrs)}")
    print(f"Protocols: SMB/RDP/HTTP/TLS/SSH/UDP")
    print(f"Mode: {args.mode}" + (f" (top {options.top_ports or 'default'})" if args.mode == "top" else f" ({args.ports})"))
    if args.udp:
        print(f"UDP: Enabled ({options.udp_ports or 'default ports'})")
    print(f"Timing: {options.timing}")
    print("="*80 + "\n")

    try:
        # Prepare save_xml_dir if requested
        save_xml_dir = None
        if args.save_xml:
            save_xml_dir = Path(args.out) / "raw"
            save_xml_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Raw XML will be saved to {save_xml_dir}")

        # Build scan plan
        invocations = build_scan_plan(options, nmap_path=args.nmap_path, batch_size=args.batch_size)

        # Execute scan
        logger.info("Starting scan...")
        result = execute_scan(
            invocations,
            options,
            nmap_path=args.nmap_path,
            save_xml_dir=save_xml_dir,
            batch_size=args.batch_size,
            disable_progress=args.quiet
        )

        # Run security analysis
        logger.info("Analyzing results...")
        result = analyze_scan_results(result)

        # Save JSON output
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)

        json_path = out_dir / "scan.json"
        save_json_file(result.to_dict(), json_path)

        # Print summary
        print("\n" + "="*80)
        print("SCAN COMPLETE")
        print("="*80)
        print(f"Duration: {format_duration(result.summary.get('duration_seconds', 0))}")
        print(f"Hosts up: {result.summary.get('hosts_up', 0)}/{result.summary.get('hosts_total', 0)}")
        print(f"Open ports: {result.summary.get('services_open', 0)}")
        print(f"Findings: {result.summary.get('findings_total', 0)}")

        severity_counts = result.summary.get('findings_by_severity', {})
        if any(severity_counts.values()):
            print("\nFindings by severity:")
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    print(f"  {severity.upper()}: {count}")

        print(f"\nResults saved to: {json_path}")
        print("\nGenerate reports with:")
        print(f"  truslan report --from-json {json_path} --out-html {out_dir}/report.html --out-csv {out_dir}/findings.csv")
        print("="*80 + "\n")

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        sys.exit(1)


def handle_report(args):
    """Handle report command."""
    json_path = Path(args.from_json)

    if not json_path.exists():
        logger.error(f"JSON file not found: {json_path}")
        sys.exit(1)

    try:
        # Load scan results
        logger.info(f"Loading scan results from {json_path}")
        data = load_json_file(json_path)

        # Reconstruct ScanResult object (simplified - we'll work with dict)
        from .core.models import ScanResult, ScanMeta, Host, Service, Finding, OSMatch, ScanOptions

        # Build meta
        meta_dict = data.get('meta', {})
        options_dict = meta_dict.get('options', {})

        options = ScanOptions(
            profile=ScanProfile(options_dict.get('profile', 'safe')),
            cidr_list=options_dict.get('cidr_list', []),
            mode=options_dict.get('mode', 'top'),
            top_ports=options_dict.get('top_ports'),
            port_list=options_dict.get('port_list'),
            udp=options_dict.get('udp', False),
            udp_ports=options_dict.get('udp_ports'),
            timing=options_dict.get('timing', 'T3'),
            host_timeout=options_dict.get('host_timeout', '30s'),
            max_retries=options_dict.get('max_retries'),
            script_timeout=options_dict.get('script_timeout', '30s'),
            allow_intrusive=options_dict.get('allow_intrusive', False),
            authorized=options_dict.get('authorized', False)
        )

        meta = ScanMeta(
            profile=ScanProfile(meta_dict.get('profile', 'safe')),
            options=options,
            started_at=datetime.fromisoformat(meta_dict.get('started_at')) if meta_dict.get('started_at') else datetime.now(),
            finished_at=datetime.fromisoformat(meta_dict.get('finished_at')) if meta_dict.get('finished_at') else None,
            nmap_commands=meta_dict.get('nmap_commands', []),
            nmap_version=meta_dict.get('nmap_version'),
            platform=meta_dict.get('platform'),
            scanner_version=meta_dict.get('scanner_version', VERSION)
        )

        # Build hosts
        hosts = []
        for host_dict in data.get('hosts', []):
            services = []
            for svc_dict in host_dict.get('services', []):
                from .core.models import PortState
                services.append(Service(
                    port=svc_dict['port'],
                    protocol=svc_dict['protocol'],
                    state=PortState(svc_dict['state']),
                    service=svc_dict.get('service'),
                    product=svc_dict.get('product'),
                    version=svc_dict.get('version'),
                    extrainfo=svc_dict.get('extrainfo'),
                    cpe=svc_dict.get('cpe', []),
                    scripts=svc_dict.get('scripts', {})
                ))

            findings = []
            for find_dict in host_dict.get('findings', []):
                from .core.models import FindingSeverity
                findings.append(Finding(
                    finding_id=find_dict['finding_id'],
                    severity=FindingSeverity(find_dict['severity']),
                    title=find_dict['title'],
                    description=find_dict['description'],
                    remediation=find_dict['remediation'],
                    host=find_dict.get('host'),
                    port=find_dict.get('port'),
                    protocol=find_dict.get('protocol'),
                    service=find_dict.get('service'),
                    evidence=find_dict.get('evidence')
                ))

            os_matches = []
            for os_dict in host_dict.get('os_matches', []):
                os_matches.append(OSMatch(
                    name=os_dict['name'],
                    accuracy=os_dict['accuracy'],
                    osclass=os_dict.get('osclass', [])
                ))

            hosts.append(Host(
                ip=host_dict['ip'],
                hostname=host_dict.get('hostname'),
                state=host_dict.get('state', 'unknown'),
                os_matches=os_matches,
                services=services,
                findings=findings,
                mac_address=host_dict.get('mac_address'),
                mac_vendor=host_dict.get('mac_vendor')
            ))

        result = ScanResult(
            meta=meta,
            hosts=hosts,
            summary=data.get('summary', {})
        )

        # Generate HTML report
        if args.out_html:
            html_path = Path(args.out_html)
            generate_html_report(result, html_path)
            print(f"HTML report: {html_path}")

        # Generate CSV report
        if args.out_csv:
            csv_path = Path(args.out_csv)
            generate_csv_report(result, csv_path)
            print(f"CSV report: {csv_path}")

        if not args.out_html and not args.out_csv:
            logger.warning("No output format specified. Use --out-html and/or --out-csv")

    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        sys.exit(1)


def handle_all(args):
    """Handle all command (discover + scan + report)."""
    # Step 1: Discover or use provided CIDRs
    if args.auto_cidr:
        logger.info("Discovering local networks...")
        try:
            cidrs = discover_local_networks()
            if not cidrs:
                logger.error("No local networks discovered")
                sys.exit(1)
            cidrs_str = " ".join(cidrs)
        except Exception as e:
            logger.error(f"Discovery failed: {e}")
            sys.exit(1)
    elif args.cidr:
        cidrs_str = args.cidr
    else:
        logger.error("Must specify either --auto-cidr or --cidr")
        sys.exit(1)

    # Step 2: Run scan
    # Build temporary args object for scan
    class ScanArgs:
        pass

    scan_args = ScanArgs()
    scan_args.cidr = cidrs_str
    scan_args.profile = args.profile
    scan_args.mode = args.mode
    scan_args.top = args.top
    scan_args.ports = args.ports
    scan_args.udp = args.udp
    scan_args.udp_ports = args.udp_ports
    scan_args.timing = args.timing
    scan_args.host_timeout = args.host_timeout
    scan_args.max_retries = args.max_retries
    scan_args.script_timeout = args.script_timeout
    scan_args.allow_intrusive = args.allow_intrusive
    scan_args.i_am_authorized = args.i_am_authorized
    scan_args.nmap_path = args.nmap_path
    scan_args.save_xml = args.save_xml
    scan_args.batch_size = args.batch_size
    scan_args.nse_strict = args.nse_strict
    scan_args.fail_on_errors = args.fail_on_errors
    scan_args.prefer_vulners = args.prefer_vulners
    scan_args.trust_discovery = args.trust_discovery
    scan_args.out = args.out
    scan_args.quiet = getattr(args, 'quiet', False)
    scan_args.verbose = getattr(args, 'verbose', False)

    handle_scan(scan_args)

    # Step 3: Generate reports
    out_dir = Path(args.out)
    json_path = out_dir / "scan.json"

    if json_path.exists():
        class ReportArgs:
            pass

        report_args = ReportArgs()
        report_args.from_json = str(json_path)
        report_args.out_html = str(out_dir / "report.html")
        report_args.out_csv = str(out_dir / "findings.csv")

        handle_report(report_args)

        print("\n" + "="*80)
        print("ALL TASKS COMPLETE")
        print("="*80)
        print(f"Scan JSON: {json_path}")
        print(f"HTML Report: {out_dir / 'report.html'}")
        print(f"CSV Report: {out_dir / 'findings.csv'}")
        print("="*80 + "\n")


if __name__ == "__main__":
    main()
