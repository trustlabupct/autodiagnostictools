#!/bin/bash
#
# PYMEs Unified Security Toolkit Launcher
# Launches the unified GUI for TrusLAN, trusClamAV, and trustMITRE
#
# Author: Volodymyr Dubetskyy
# Organization: TRUST Lab UPCT
# © 2025 TRUST Lab UPCT

# Don't exit on error for arithmetic operations
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

OK="${GREEN}[OK]${NC}"
WARN="${YELLOW}[WARN]${NC}"
ERR="${RED}[ERROR]${NC}"
INFO="${CYAN}[INFO]${NC}"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   PYMEs Unified Security Toolkit Launcher${NC}"
echo -e "${BLUE}   TrusLAN | trusClamAV | trustMITRE${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if running with elevated privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${WARN} Not running with elevated privileges"
    echo -e "${WARN} Some operations may require root/sudo access:"
    echo -e "${WARN}   - TrusLAN: Network scanning, UDP ports"
    echo -e "${WARN}   - trusClamAV: Installing ClamAV, updating databases"
    echo -e "${WARN}   - trustMITRE: Live Sysmon collection (Windows)"
    echo ""
    echo -e "${INFO} To run with elevated privileges:"
    echo -e "${INFO}   sudo $0"
    echo ""
    read -p "Continue without elevated privileges? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Exiting. Run with: sudo $0"
        exit 0
    fi
    echo ""
fi

# Check Python version
echo -e "${INFO} Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${OK} Found Python ${PYTHON_VERSION}"
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}')
    echo -e "${OK} Found Python ${PYTHON_VERSION}"
    PYTHON_CMD="python"
else
    echo -e "${ERR} Python not found!"
    echo "Please install Python 3.9 or higher"
    exit 1
fi

# Check Python version >= 3.9
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]); then
    echo -e "${ERR} Python 3.9+ required (found ${PYTHON_VERSION})"
    exit 1
fi

# Check for tkinter
echo -e "${INFO} Checking tkinter..."
if $PYTHON_CMD -c "import tkinter" 2>/dev/null; then
    echo -e "${OK} tkinter is available"
else
    echo -e "${ERR} tkinter not found!"
    echo ""
    echo "Please install tkinter:"
    echo "  Ubuntu/Debian: sudo apt-get install python3-tk"
    echo "  Fedora/RHEL:   sudo dnf install python3-tkinter"
    echo "  macOS:         (should be included with Python)"
    exit 1
fi

# Check for tools
echo -e "${INFO} Checking integrated tools..."

TOOLS_FOUND=0
TOOLS_TOTAL=3

if [ -d "$BASE_DIR/truslan" ]; then
    echo -e "${OK} TrusLAN found"
    TOOLS_FOUND=$((TOOLS_FOUND + 1))
else
    echo -e "${WARN} TrusLAN not found at $BASE_DIR/truslan"
fi

if [ -d "$BASE_DIR/trusClamAV" ]; then
    echo -e "${OK} trusClamAV found"
    TOOLS_FOUND=$((TOOLS_FOUND + 1))
else
    echo -e "${WARN} trusClamAV not found at $BASE_DIR/trusClamAV"
fi

if [ -d "$BASE_DIR/trusMITRE" ]; then
    echo -e "${OK} trustMITRE found"
    TOOLS_FOUND=$((TOOLS_FOUND + 1))
else
    echo -e "${WARN} trustMITRE not found at $BASE_DIR/trusMITRE"
fi

if [ $TOOLS_FOUND -eq 0 ]; then
    echo -e "${ERR} No tools found!"
    echo "Please ensure tools are installed in the correct directory structure"
    exit 1
fi

echo -e "${INFO} Found $TOOLS_FOUND/$TOOLS_TOTAL tools"

# Check for venv
if [ -d "$BASE_DIR/trusMITRE/.venv" ]; then
    echo -e "${INFO} Virtual environment found, activating..."
    source "$BASE_DIR/trusMITRE/.venv/bin/activate"
    echo -e "${OK} Using venv Python: $(which python)"
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   Starting PYMEs Unified Security Toolkit...${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Launch the application
cd "$SCRIPT_DIR"
exec $PYTHON_CMD main.py "$@"
