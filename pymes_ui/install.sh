#!/bin/bash
#
# PYMEs Unified Security Toolkit - Installation Script
# Direct installation with module selection
#
# Author: Volodymyr Dubetskyy
# Organization: TRUST Lab UPCT
# © 2025 TRUST Lab UPCT

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

# Default: install all modules
INSTALL_TRUSLAN=false
INSTALL_TRUSCLAMAV=false
INSTALL_TRUSTMITRE=false
INSTALL_ALL=false

# Parse arguments
if [ $# -eq 0 ]; then
    INSTALL_ALL=true
else
    for arg in "$@"; do
        case $arg in
            truslan)
                INSTALL_TRUSLAN=true
                ;;
            trusclamav)
                INSTALL_TRUSCLAMAV=true
                ;;
            trustmitre)
                INSTALL_TRUSTMITRE=true
                ;;
            all)
                INSTALL_ALL=true
                ;;
            *)
                echo -e "${RED}Unknown module: $arg${NC}"
                echo "Usage: $0 [truslan] [trusclamav] [trustmitre] [all]"
                echo "No arguments = install all"
                exit 1
                ;;
        esac
    done
fi

# Set all to true if INSTALL_ALL is true
if [ "$INSTALL_ALL" = true ]; then
    INSTALL_TRUSLAN=true
    INSTALL_TRUSCLAMAV=true
    INSTALL_TRUSTMITRE=true
fi

echo -e "${BLUE}PYMEs Unified Security Toolkit - Installation${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

# Check Python
PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo -e "${RED}ERROR: Python not found${NC}"
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}Python: ${PYTHON_VERSION}${NC}"

# Check pip
PIP_CMD=""
if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    PIP_CMD="pip"
else
    echo -e "${RED}ERROR: pip not found${NC}"
    exit 1
fi

# Check tkinter
if ! $PYTHON_CMD -c "import tkinter" 2>/dev/null; then
    echo -e "${YELLOW}Installing tkinter...${NC}"
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y python3-tk
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y python3-tkinter
    elif command -v yum &> /dev/null; then
        sudo yum install -y python3-tkinter
    elif command -v pacman &> /dev/null; then
        sudo pacman -S tk
    else
        echo -e "${RED}ERROR: Cannot install tkinter automatically${NC}"
        exit 1
    fi
fi

echo ""

# Install TrusLAN
if [ "$INSTALL_TRUSLAN" = true ]; then
    if [ -d "$BASE_DIR/truslan" ]; then
        echo -e "${BLUE}[TrusLAN]${NC}"
        cd "$BASE_DIR/truslan"

        # Create or use existing venv
        if [ ! -d ".venv" ]; then
            echo "Creating virtual environment for TrusLAN..."
            $PYTHON_CMD -m venv .venv
        fi

        source .venv/bin/activate

        if [ -f "requirements.txt" ]; then
            pip install -r requirements.txt
            echo -e "${GREEN}TrusLAN dependencies installed${NC}"
        fi

        deactivate

        # Check nmap
        if ! command -v nmap &> /dev/null; then
            echo -e "${YELLOW}nmap not found. Install manually if needed.${NC}"
        fi
        echo ""
    else
        echo -e "${YELLOW}TrusLAN directory not found${NC}"
    fi
fi

# Install trusClamAV
if [ "$INSTALL_TRUSCLAMAV" = true ]; then
    if [ -d "$BASE_DIR/trusClamAV" ]; then
        echo -e "${BLUE}[trusClamAV]${NC}"
        cd "$BASE_DIR/trusClamAV"

        # Create or use existing venv
        if [ ! -d ".venv" ]; then
            echo "Creating virtual environment for trusClamAV..."
            $PYTHON_CMD -m venv .venv
        fi

        source .venv/bin/activate

        if [ -f "requirements.txt" ]; then
            pip install -r requirements.txt
            echo -e "${GREEN}trusClamAV dependencies installed${NC}"
        fi

        deactivate

        # Check ClamAV
        if ! command -v clamscan &> /dev/null; then
            echo -e "${YELLOW}ClamAV not found. Use 'doctor' command in UI to install.${NC}"
        fi
        echo ""
    else
        echo -e "${YELLOW}trusClamAV directory not found${NC}"
    fi
fi

# Install trustMITRE
if [ "$INSTALL_TRUSTMITRE" = true ]; then
    if [ -d "$BASE_DIR/trusMITRE" ]; then
        echo -e "${BLUE}[trustMITRE]${NC}"
        cd "$BASE_DIR/trusMITRE"

        # Create or use existing venv
        if [ ! -d ".venv" ]; then
            echo "Creating virtual environment for trustMITRE..."
            $PYTHON_CMD -m venv .venv
        fi

        source .venv/bin/activate

        if [ -f "requirements.txt" ]; then
            pip install -r requirements.txt
        fi

        if [ -f "requirements-dev.txt" ]; then
            pip install -r requirements-dev.txt
        fi

        pip install -e .
        echo -e "${GREEN}trustMITRE dependencies installed${NC}"
        deactivate
        echo ""
    else
        echo -e "${YELLOW}trustMITRE directory not found${NC}"
    fi
fi

# Make scripts executable
cd "$SCRIPT_DIR"
chmod +x launch.sh main.py check_system.py 2>/dev/null || true

echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}Installation complete${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
echo "Launch: ./launch.sh or python3 main.py"
echo "Check: ./check_system.py"
echo ""
