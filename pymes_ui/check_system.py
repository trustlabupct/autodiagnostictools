#!/usr/bin/env python3
"""
PYMEs Unified UI - System Check Script
Validates that all requirements are met before running the application

Author: Volodymyr Dubetskyy
Organization: TRUST Lab UPCT
© 2025 TRUST Lab UPCT
"""

import sys
import os
import subprocess
from pathlib import Path

# ANSI color codes
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

OK = f"{GREEN}[OK]{RESET}"
WARN = f"{YELLOW}[WARN]{RESET}"
ERR = f"{RED}[ERROR]{RESET}"
INFO = f"{CYAN}[INFO]{RESET}"

def print_header():
    """Print header"""
    print(f"{BLUE}{'=' * 70}{RESET}")
    print(f"{BLUE}{BOLD}   PYMEs Unified Security Toolkit - System Check{RESET}")
    print(f"{BLUE}{'=' * 70}{RESET}\n")

def check_python_version():
    """Check Python version"""
    print(f"{INFO} Checking Python version...")

    version_info = sys.version_info
    version_str = f"{version_info.major}.{version_info.minor}.{version_info.micro}"

    if version_info.major >= 3 and version_info.minor >= 9:
        print(f"  {OK} Python {version_str} (meets requirement: 3.9+)")
        return True
    else:
        print(f"  {ERR} Python {version_str} (requires 3.9 or higher)")
        return False

def check_tkinter():
    """Check if tkinter is available"""
    print(f"\n{INFO} Checking tkinter...")

    try:
        import tkinter
        tk_version = tkinter.TkVersion
        print(f"  {OK} tkinter {tk_version} is available")
        return True
    except ImportError:
        print(f"  {ERR} tkinter not found")
        print(f"  {WARN} Install with:")
        print(f"    Ubuntu/Debian: sudo apt-get install python3-tk")
        print(f"    Fedora/RHEL:   sudo dnf install python3-tkinter")
        print(f"    Arch Linux:    sudo pacman -S tk")
        return False

def check_tool_directory(name, path):
    """Check if a tool directory exists"""
    if path.exists() and path.is_dir():
        print(f"  {OK} {name} found at {path}")
        return True
    else:
        print(f"  {WARN} {name} not found at {path}")
        return False

def check_tools():
    """Check for integrated tool directories"""
    print(f"\n{INFO} Checking integrated tools...")

    script_dir = Path(__file__).parent
    base_dir = script_dir.parent

    tools = {
        'TrusLAN': base_dir / 'truslan',
        'trusClamAV': base_dir / 'trusClamAV',
        'trustMITRE': base_dir / 'trusMITRE'
    }

    found = 0
    for name, path in tools.items():
        if check_tool_directory(name, path):
            found += 1

    print(f"\n  Found {found}/{len(tools)} tools")
    return found > 0

def check_command(cmd_name, cmd_list, required=False):
    """Check if a command exists"""
    try:
        result = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        if result.returncode == 0:
            output = result.stdout.decode('utf-8').strip()
            # Extract version if present
            version = output.split('\n')[0] if output else 'found'
            print(f"  {OK} {cmd_name} - {version}")
            return True
        else:
            if required:
                print(f"  {ERR} {cmd_name} not found")
            else:
                print(f"  {WARN} {cmd_name} not found (optional)")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        if required:
            print(f"  {ERR} {cmd_name} not found")
        else:
            print(f"  {WARN} {cmd_name} not found (optional)")
        return False

def check_external_tools():
    """Check for external tool dependencies"""
    print(f"\n{INFO} Checking external tool dependencies...")

    # Required for TrusLAN
    check_command('nmap', ['nmap', '--version'], required=False)

    # Required for trusClamAV
    check_command('clamscan', ['clamscan', '--version'], required=False)

    return True

def check_venv():
    """Check for virtual environment"""
    print(f"\n{INFO} Checking virtual environment...")

    script_dir = Path(__file__).parent
    base_dir = script_dir.parent
    venv_path = base_dir / 'trusMITRE' / '.venv'

    if venv_path.exists():
        print(f"  {OK} Virtual environment found at {venv_path}")

        # Check if it has Python
        if sys.platform == 'win32':
            venv_python = venv_path / 'Scripts' / 'python.exe'
        else:
            venv_python = venv_path / 'bin' / 'python'

        if venv_python.exists():
            print(f"  {OK} Python executable found in venv")
            return True
        else:
            print(f"  {WARN} Python executable not found in venv")
            return False
    else:
        print(f"  {WARN} No virtual environment found")
        print(f"    This is optional but recommended for trustMITRE")
        return True

def check_permissions():
    """Check file permissions"""
    print(f"\n{INFO} Checking file permissions...")

    script_dir = Path(__file__).parent

    files_to_check = [
        script_dir / 'main.py',
        script_dir / 'launch.sh'
    ]

    all_ok = True
    for file_path in files_to_check:
        if file_path.exists():
            if os.access(file_path, os.X_OK):
                print(f"  {OK} {file_path.name} is executable")
            else:
                print(f"  {WARN} {file_path.name} is not executable")
                print(f"    Run: chmod +x {file_path}")
                all_ok = False
        else:
            print(f"  {WARN} {file_path.name} not found")

    return all_ok

def print_summary(checks):
    """Print summary of checks"""
    print(f"\n{BLUE}{'=' * 70}{RESET}")
    print(f"{BOLD}Summary:{RESET}\n")

    passed = sum(1 for result in checks.values() if result)
    total = len(checks)

    for check_name, result in checks.items():
        status = f"{OK} PASS" if result else f"{ERR} FAIL"
        print(f"  {status} - {check_name}")

    print(f"\n{BOLD}Result: {passed}/{total} checks passed{RESET}")

    if passed == total:
        print(f"\n{OK} All checks passed. You're ready to run the application.")
        print(f"\n{INFO} To launch:")
        print("  ./launch.sh")
        print("  or")
        print("  python3 main.py")
        return True
    else:
        print(f"\n{WARN} Some checks failed or have warnings.")
        print("Review the issues above and install missing dependencies.")
        print(f"\n{INFO} Quick fix:")
        print("  ./install.sh  # Run the installation helper")
        return False

def main():
    """Main entry point"""
    print_header()

    # Run all checks
    checks = {
        'Python Version (3.9+)': check_python_version(),
        'tkinter Library': check_tkinter(),
        'Tool Directories': check_tools(),
        'External Tools': check_external_tools(),
        'Virtual Environment': check_venv(),
        'File Permissions': check_permissions()
    }

    # Print summary
    success = print_summary(checks)

    print(f"\n{BLUE}{'=' * 70}{RESET}\n")

    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
