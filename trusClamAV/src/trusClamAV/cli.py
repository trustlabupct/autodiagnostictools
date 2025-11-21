"""
Command-line interface for trusClamAV.

Author: Volodymyr Dubetskyy
Last updated: October 14, 2025
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import signal
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import List, Optional

from .clamav_backend import (
    ClamAVError,
    ClamAVInstallError,
    ClamAVScanError,
    ClamAVUpdateError,
    check_admin,
    cleanup_artifacts,
    discover,
    get_database_info,
    get_default_paths,
    get_remediation_hints,
    install_linux,
    install_windows,
    run_scan,
    update_db,
    write_reports,
)
from .config_schema import (
    ClamAVConfig,
    resolve_output_prefix,
    load_config,
)


def _configure_logging(log_file: Optional[str], level: str) -> None:
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.handlers.clear()
    logger.addHandler(console)

    # Rotating file handler
    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(str(path), maxBytes=5 * 1024 * 1024, backupCount=5)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)


def cmd_doctor(args: argparse.Namespace) -> int:
    config = load_config(args.config, args)
    discovery = discover(config.clamav_dir, config.db_dir)
    db_info = get_database_info(discovery.database_dir)

    payload = {
        "os": platform.system().lower(),
        "paths": {
            "clamscan": discovery.clamscan_path,
            "clamdscan": discovery.clamdscan_path,
            "freshclam": discovery.freshclam_path,
            "db_dir": discovery.database_dir,
            "config_dir": discovery.config_dir,
            "logs_dir": discovery.logs_dir,
            "reports_dir": discovery.reports_dir,
        },
        "versions": {
            "clamav": discovery.clamav_version,
            "engine": discovery.engine_version,
        },
        "db": {
            "age_days": db_info.get("age_days"),
            "exists": db_info.get("exists"),
        },
        "discovery_method": discovery.discovery_method,
        "admin": check_admin(),
        "hints": get_remediation_hints(discovery),
    }

    if args.json:
        json.dump(payload, sys.stdout, indent=2, ensure_ascii=True)
        sys.stdout.write("\n")
    else:
        print("trusClamAV Doctor")
        print("-----------------")
        print(f"OS               : {payload['os']}")
        print(f"Admin            : {'yes' if payload['admin'] else 'no'}")
        print(f"ClamAV version   : {payload['versions']['clamav'] or 'unknown'}")
        print(f"Engine version   : {payload['versions']['engine'] or 'unknown'}")
        print(f"clamscan path    : {payload['paths']['clamscan'] or 'missing'}")
        print(f"clamdscan path   : {payload['paths']['clamdscan'] or 'missing'}")
        print(f"freshclam path   : {payload['paths']['freshclam'] or 'missing'}")
        print(f"database dir     : {payload['paths']['db_dir']}")
        print(f"config dir       : {payload['paths']['config_dir']}")
        print(f"logs dir         : {payload['paths']['logs_dir']}")
        print(f"reports dir      : {payload['paths']['reports_dir']}")
        print(f"discovery method : {payload['discovery_method']}")
        print(f"db exists        : {'yes' if payload['db']['exists'] else 'no'}")
        if payload["db"]["age_days"] is not None:
            print(f"db age (days)    : {payload['db']['age_days']}")
        print("\nHints:")
        if payload["hints"]:
            for hint in payload["hints"]:
                print(f" - {hint}")
        else:
            print(" - None")

    return 0


def cmd_install(args: argparse.Namespace) -> int:
    system = platform.system()
    discovery = discover(args.clamav_dir, args.db_dir)
    if discovery.found and discovery.freshclam_path:
        print("ClamAV already available.")
        print(f"clamscan: {discovery.clamscan_path}")
        print(f"freshclam: {discovery.freshclam_path}")
        return 0

    if system == "Windows":
        actions: List[str] = []
        if not check_admin():
            print("Run an elevated PowerShell (Run as Administrator) to install ClamAV.")
            return 0
        try:
            actions = install_windows(zip_url=args.zip_url, sha256=args.sha256, dry_run=args.dry_run)
        except ClamAVInstallError as exc:
            logging.error("%s", exc)
            return 1
        finally:
            discovery = discover(args.clamav_dir, args.db_dir)
        if actions:
            print("Executed:")
            for action in actions:
                print(f"  {action}")
    else:
        actions = []
        if not check_admin():
            print("Run the following commands with sudo:")
            try:
                planned = install_linux(dry_run=True)
            except ClamAVInstallError as exc:
                logging.error("%s", exc)
                return 1
            for line in planned:
                print(f"  sudo {line}")
            return 0
        try:
            actions = install_linux(dry_run=args.dry_run)
        except ClamAVInstallError as exc:
            logging.error("%s", exc)
            return 1
        if actions:
            print("Executed:")
            for action in actions:
                print(f"  {action}")
        discovery = discover(args.clamav_dir, args.db_dir)

    if discovery.found:
        print("ClamAV installation verified:")
        print(f"  clamscan : {discovery.clamscan_path}")
        print(f"  clamdscan: {discovery.clamdscan_path}")
        print(f"  freshclam: {discovery.freshclam_path}")
        print(f"  database : {discovery.database_dir}")
        return 0

    print("ClamAV binaries still not detected. Check the logs for details.")
    return 1


def cmd_update(args: argparse.Namespace) -> int:
    config = load_config(args.config, args)
    discovery = discover(config.clamav_dir, config.db_dir)

    if not discovery.found or not discovery.freshclam_path:
        logging.error("ClamAV not found. Run 'trusclamav install' first.")
        return 2

    timeout = args.timeout or config.timeout
    try:
        update_db(discovery, timeout=timeout, retries=args.retries, allow_failure=True)
    except ClamAVUpdateError as exc:
        if discovery.database_exists:
            logging.warning("Update failed but database exists: %s", exc)
            return 0
        logging.error("%s", exc)
        return 2

    if not config.quiet:
        print("Virus database updated.")
    return 0


def _write_cancelled(prefix: Path, targets: List[str], discovery) -> None:
    payload = {
        "schema_version": "1.0",
        "timestamp": "",
        "tool": {
            "name": "trusClamAV",
            "clamav_version": discovery.clamav_version or "unknown",
            "engine": "cancelled",
        },
        "targets": [str(Path(t).resolve()) for t in targets],
        "exclusions": [],
        "files_scanned": 0,
        "infected_count": 0,
        "infected_files": [],
        "elapsed_seconds": 0.0,
        "status": "cancelled",
        "errors": ["Scan cancelled by user."],
    }
    write_reports(prefix, "", "Scan cancelled by user.", payload, ["txt", "json"])


def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config, args)
    targets = config.targets or args.targets

    if not targets:
        logging.error("Provide at least one --targets path.")
        return 2

    discovery = discover(config.clamav_dir, config.db_dir)
    if not discovery.found:
        logging.error("ClamAV executables not found. Run 'trusclamav install'.")
        return 2

    prefix = resolve_output_prefix(config.out)
    timeout = args.timeout or config.timeout
    db_override = args.db_dir or config.db_dir

    cancelled = {"flag": False}

    def handle_signal(signum, frame):  # noqa: ARG001
        cancelled["flag"] = True
        raise KeyboardInterrupt()

    previous_handler = signal.signal(signal.SIGINT, handle_signal)

    try:
        result = run_scan(
            discovery=discovery,
            targets=targets,
            exclude=config.exclude,
            include=config.include,
            include_ext=config.include_ext,
            max_filesize=config.max_filesize,
            max_scansize=config.max_scansize,
            prefer_clamd=config.use_clamd,
            timeout=timeout,
            output_prefix=str(prefix),
            formats=config.formats,
            db_override=db_override,
            dry_run=config.dry_run,
        )
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT, previous_handler)
        _write_cancelled(prefix, targets, discovery)
        print("\nScan cancelled by user. Partial reports saved.")
        return 2
    except ClamAVScanError as exc:
        signal.signal(signal.SIGINT, previous_handler)
        logging.error("%s", exc)
        return 2

    signal.signal(signal.SIGINT, previous_handler)

    status = result.get("status")
    if status == "infected":
        exit_code = 1
    elif status in {"clean", "dry-run"}:
        exit_code = 0
    else:
        exit_code = 2

    if not config.quiet:
        print("Scan complete.")
        print(f"Status          : {status}")
        print(f"Files scanned   : {result.get('files_scanned')}")
        print(f"Infected files  : {result.get('infected_count')}")
        reports = result.get("reports", {})
        if "txt" in reports:
            print(f"Report (txt)    : {reports['txt']}")
        if "json" in reports:
            print(f"Report (json)   : {reports['json']}")

    return exit_code


def cmd_cleanup(args: argparse.Namespace) -> int:
    defaults = get_default_paths()
    config = load_config(args.config, args)
    output_root = resolve_output_prefix(config.out).parent

    roots = [
        defaults["logs"],
        defaults["reports"],
        defaults["tmp"],
        defaults["database"],
        Path.cwd() / "logs",
        Path.cwd() / "reports",
    ]
    if output_root not in roots:
        roots.append(output_root)

    patterns = [
        "*.log",
        "*.txt",
        "*.json",
        "*.tmp",
        "*.spec",
        "*.pyc",
        "__pycache__",
        "scan_output.*",
        "scan.*",
    ]

    purge_db = Path(args.purge_db_dir).resolve() if args.purge_db_dir else None

    result = cleanup_artifacts(roots, patterns, dry_run=args.dry_run, purge_db_dir=purge_db)
    if not getattr(args, "quiet", False):
        print("Cleanup summary:")
        print(f"  removed items : {len(result['removed'])}")
        print(f"  bytes reclaimed: {result['bytes_reclaimed']}")
        if result["errors"]:
            print("Errors encountered:")
            for line in result["errors"]:
                print(f"  - {line}")
            return 1
    elif result["errors"]:
        logging.error("Errors encountered during cleanup: %s", "; ".join(result["errors"]))
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trusclamav", description="Cross-platform ClamAV companion.")
    parser.add_argument("--config", help="Path to configuration file.")
    parser.add_argument("--log-file", help="Override log file location.")
    parser.add_argument("--log-level", default="INFO", help="Logging level (default: INFO).")
    parser.add_argument("--timeout", type=int, help="Default timeout for long-running operations (seconds).")
    parser.add_argument("--quiet", action="store_true", help="Suppress informational output where applicable.")
    parser.add_argument("--dry-run", action="store_true", help="Preview actions without making changes.")
    parser.add_argument("--clamav-dir", help="Override discovery directory for ClamAV.")
    parser.add_argument("--db-dir", help="Override database directory.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="Inspect environment and report status.")
    doctor.add_argument("--json", action="store_true", help="Emit JSON diagnostic information.")
    doctor.set_defaults(func=cmd_doctor)

    install = subparsers.add_parser("install", help="Install ClamAV using native tooling.")
    install.add_argument("--zip-url", help="Windows-only: URL to a ClamAV ZIP archive.")
    install.add_argument("--sha256", help="Windows-only: SHA256 checksum for the ZIP archive.")
    install.add_argument("--dry-run", action="store_true", dest="install_dry_run", help="Preview installation commands without executing them.")
    install.set_defaults(func=cmd_install)

    update = subparsers.add_parser("update", help="Update virus signatures with freshclam.")
    update.add_argument("--retries", type=int, default=1, help="Number of attempts (default: 1).")
    update.add_argument("--timeout", type=int, dest="update_timeout", help="Override default timeout just for update.")
    update.add_argument("--quiet", action="store_true", dest="update_quiet", help="Suppress informational output for update.")
    update.set_defaults(func=cmd_update)

    scan = subparsers.add_parser("scan", help="Scan targets using ClamAV.")
    scan.add_argument("--targets", nargs="+", help="Files or directories to scan.")
    scan.add_argument("--exclude", nargs="*", help="Glob patterns to exclude.")
    scan.add_argument("--include", nargs="*", help="Regular expressions for files to include.")
    scan.add_argument("--include-ext", nargs="*", help="File extensions to include (for example .pdf .docx).")
    scan.add_argument("--max-filesize", help="Skip files larger than this size (e.g. 50M).")
    scan.add_argument("--max-scansize", help="Limit per-file scan data to this size (e.g. 200M).")
    scan.add_argument("--out", help="Output prefix for reports.")
    scan.add_argument("--format", nargs="+", choices=["txt", "json"], help="Report formats to generate.")
    scan.add_argument("--use-clamd", action="store_true", help="Prefer clamdscan when available.")
    scan.add_argument("--dry-run", action="store_true", dest="scan_dry_run", help="Simulate the scan without invoking ClamAV.")
    scan.add_argument("--quiet", action="store_true", dest="scan_quiet", help="Suppress informational output for this scan.")
    scan.add_argument("--timeout", type=int, dest="scan_timeout", help="Override the scan timeout.")
    scan.set_defaults(func=cmd_scan)

    cleanup = subparsers.add_parser("cleanup", help="Remove cached reports and temporary files.")
    cleanup.add_argument("--purge-db-dir", help="Delete a database directory (use with caution).")
    cleanup.add_argument("--dry-run", action="store_true", dest="cleanup_dry_run", help="Preview cleanup operations without deleting.")
    cleanup.add_argument("--quiet", action="store_true", dest="cleanup_quiet", help="Suppress informational output for cleanup.")
    cleanup.set_defaults(func=cmd_cleanup)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Harmonise duplicated flags supplied after subcommands.
    for attr in ("install_dry_run", "scan_dry_run", "cleanup_dry_run"):
        if getattr(args, attr, False):
            args.dry_run = True
    for attr in ("scan_quiet", "cleanup_quiet", "update_quiet"):
        if getattr(args, attr, False):
            args.quiet = True
    if getattr(args, "scan_timeout", None) is not None:
        args.timeout = args.scan_timeout
    if getattr(args, "update_timeout", None) is not None:
        args.timeout = args.update_timeout

    # Configure logging before dispatch
    config = load_config(args.config, args)
    _configure_logging(args.log_file or config.log_file, args.log_level or config.log_level)

    try:
        return args.func(args)
    except ClamAVError as exc:
        logging.error("%s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
