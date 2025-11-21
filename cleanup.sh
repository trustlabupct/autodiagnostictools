#!/bin/bash

# Cleanup Script for PYMEs Projects
# Removes temporary files, caches, and build artifacts
# Safe to run - only removes generated/temporary files

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                    PYMEs Projects Cleanup Script                            ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Working directory: $SCRIPT_DIR"
echo ""

# Counter for removed items
REMOVED_COUNT=0

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Python Cache Files (__pycache__, *.pyc, *.pyo)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Remove __pycache__ directories
PYCACHE_COUNT=$(find . -type d -name "__pycache__" ! -path "*/.venv/*" 2>/dev/null | wc -l)
if [ "$PYCACHE_COUNT" -gt 0 ]; then
    find . -type d -name "__pycache__" ! -path "*/.venv/*" -exec rm -rf {} + 2>/dev/null
    echo "[OK] Removed $PYCACHE_COUNT __pycache__ directories"
    REMOVED_COUNT=$((REMOVED_COUNT + PYCACHE_COUNT))
else
    echo "  (no __pycache__ directories found)"
fi

# Remove .pyc files
PYC_COUNT=$(find . -type f -name "*.pyc" ! -path "*/.venv/*" 2>/dev/null | wc -l)
if [ "$PYC_COUNT" -gt 0 ]; then
    find . -type f -name "*.pyc" ! -path "*/.venv/*" -exec rm -f {} + 2>/dev/null
    echo "[OK] Removed $PYC_COUNT .pyc files"
    REMOVED_COUNT=$((REMOVED_COUNT + PYC_COUNT))
else
    echo "  (no .pyc files found)"
fi

# Remove .pyo files
PYO_COUNT=$(find . -type f -name "*.pyo" ! -path "*/.venv/*" 2>/dev/null | wc -l)
if [ "$PYO_COUNT" -gt 0 ]; then
    find . -type f -name "*.pyo" ! -path "*/.venv/*" -exec rm -f {} + 2>/dev/null
    echo "[OK] Removed $PYO_COUNT .pyo files"
    REMOVED_COUNT=$((REMOVED_COUNT + PYO_COUNT))
else
    echo "  (no .pyo files found)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. Build Artifacts (*.egg-info, build/, dist/)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Remove egg-info directories
for egg_info in truslan/src/truslan.egg-info trusClamAV/src/trusClamAV.egg-info trusMITRE/src/trustmitre.egg-info; do
    if [ -d "$egg_info" ]; then
        rm -rf "$egg_info"
        echo "[OK] Removed: $egg_info"
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
done

# Remove build and dist directories
for build_dir in truslan/build truslan/dist trusClamAV/build trusClamAV/dist trusMITRE/build trusMITRE/dist; do
    if [ -d "$build_dir" ]; then
        rm -rf "$build_dir"
        echo "[OK] Removed: $build_dir"
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
done

if [ "$REMOVED_COUNT" -eq 0 ]; then
    echo "  (no build artifacts found)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. Test Artifacts (.pytest_cache, .coverage, .tox)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Remove pytest cache
for pytest_cache in truslan/.pytest_cache trusClamAV/.pytest_cache trusMITRE/.pytest_cache .pytest_cache; do
    if [ -d "$pytest_cache" ]; then
        rm -rf "$pytest_cache"
        echo "[OK] Removed: $pytest_cache"
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
done

# Remove coverage and tox
for test_artifact in .coverage htmlcov .tox; do
    if [ -e "$test_artifact" ]; then
        rm -rf "$test_artifact"
        echo "[OK] Removed: $test_artifact"
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
done

# Remove test compiled files
if [ -d "trusMITRE/.compiled_test" ]; then
    rm -rf "trusMITRE/.compiled_test"
    echo "[OK] Removed: trusMITRE/.compiled_test"
    REMOVED_COUNT=$((REMOVED_COUNT + 1))
fi

# Remove benchmark directories
for benchmark_dir in truslan/.benchmarks trusClamAV/.benchmarks trusMITRE/.benchmarks .benchmarks; do
    if [ -d "$benchmark_dir" ]; then
        rm -rf "$benchmark_dir"
        echo "[OK] Removed: $benchmark_dir"
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
done

# Remove mypy and ruff cache directories
for cache_dir in .mypy_cache .ruff_cache; do
    for tool_dir in truslan trusClamAV trusMITRE .; do
        if [ -d "$tool_dir/$cache_dir" ]; then
            rm -rf "$tool_dir/$cache_dir"
            echo "[OK] Removed: $tool_dir/$cache_dir"
            REMOVED_COUNT=$((REMOVED_COUNT + 1))
        fi
    done
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. Linter/Type Checker Cache (.mypy_cache, .ruff_cache)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  (handled in test artifacts section above)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. Temporary Files (*.tmp, *.bak, *~, scan results)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Remove temporary scan results (may need sudo)
if [ -f "trusClamAV/scan_result.txt" ]; then
    if [ -w "trusClamAV/scan_result.txt" ]; then
        rm -f "trusClamAV/scan_result.txt"
        echo "[OK] Removed: trusClamAV/scan_result.txt"
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    else
        echo "[WARN] trusClamAV/scan_result.txt requires sudo (skipped)"
        echo "  Run: sudo rm trusClamAV/scan_result.txt"
    fi
fi

# Remove backup files (*~)
BACKUP_COUNT=$(find . -type f -name "*~" ! -path "*/.venv/*" 2>/dev/null | wc -l)
if [ "$BACKUP_COUNT" -gt 0 ]; then
    find . -type f -name "*~" ! -path "*/.venv/*" -exec rm -f {} + 2>/dev/null
    echo "[OK] Removed $BACKUP_COUNT backup files (*~)"
    REMOVED_COUNT=$((REMOVED_COUNT + BACKUP_COUNT))
fi

# Remove .bak files
BAK_COUNT=$(find . -type f -name "*.bak" ! -path "*/.venv/*" 2>/dev/null | wc -l)
if [ "$BAK_COUNT" -gt 0 ]; then
    find . -type f -name "*.bak" ! -path "*/.venv/*" -exec rm -f {} + 2>/dev/null
    echo "[OK] Removed $BAK_COUNT .bak files"
    REMOVED_COUNT=$((REMOVED_COUNT + BAK_COUNT))
fi

# Remove .tmp files
TMP_COUNT=$(find . -type f -name "*.tmp" ! -path "*/.venv/*" 2>/dev/null | wc -l)
if [ "$TMP_COUNT" -gt 0 ]; then
    find . -type f -name "*.tmp" ! -path "*/.venv/*" -exec rm -f {} + 2>/dev/null
    echo "[OK] Removed $TMP_COUNT .tmp files"
    REMOVED_COUNT=$((REMOVED_COUNT + TMP_COUNT))
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. IDE/Editor Files (.vscode, .idea, *.swp, .DS_Store)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Remove IDE directories
for ide_dir in .vscode .idea; do
    if [ -d "$ide_dir" ]; then
        rm -rf "$ide_dir"
        echo "[OK] Removed: $ide_dir"
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
done

# Remove Vim swap files
SWP_COUNT=$(find . -type f -name ".*.swp" ! -path "*/.venv/*" 2>/dev/null | wc -l)
if [ "$SWP_COUNT" -gt 0 ]; then
    find . -type f -name ".*.swp" ! -path "*/.venv/*" -exec rm -f {} + 2>/dev/null
    echo "[OK] Removed $SWP_COUNT Vim swap files"
    REMOVED_COUNT=$((REMOVED_COUNT + SWP_COUNT))
fi

# Remove macOS .DS_Store files
DS_COUNT=$(find . -type f -name ".DS_Store" 2>/dev/null | wc -l)
if [ "$DS_COUNT" -gt 0 ]; then
    find . -type f -name ".DS_Store" -exec rm -f {} + 2>/dev/null
    echo "[OK] Removed $DS_COUNT .DS_Store files"
    REMOVED_COUNT=$((REMOVED_COUNT + DS_COUNT))
fi

# Remove Windows Thumbs.db files
THUMBS_COUNT=$(find . -type f -name "Thumbs.db" 2>/dev/null | wc -l)
if [ "$THUMBS_COUNT" -gt 0 ]; then
    find . -type f -name "Thumbs.db" -exec rm -f {} + 2>/dev/null
    echo "[OK] Removed $THUMBS_COUNT Thumbs.db files"
    REMOVED_COUNT=$((REMOVED_COUNT + THUMBS_COUNT))
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "[OK] Cleanup complete!"
echo "[OK] Removed approximately $REMOVED_COUNT items"
echo ""

echo "Preserved (important files/directories):"
echo "  [OK] Virtual environments (.venv)"
echo "  [OK] Source code (all .py files)"
echo "  [OK] Configuration files (pyproject.toml, requirements.txt)"
echo "  [OK] Documentation (README.md, etc.)"
echo "  [OK] Analytics data (trusMITRE/analytics/)"
echo "  [OK] Compiled analytics (trusMITRE/.compiled/)"
echo "  [OK] Output directories (trusMITRE/output/, trusMITRE/logs/)"
echo "  [OK] Test data (trusMITRE/logs/test.jsonl)"
echo "  [OK] Issue examples (trusClamAV/issue/)"
echo ""

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                          Cleanup Complete!                                  ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Note: Virtual environments (.venv) were preserved."
echo "      Run './install.sh' in each tool directory if you need to reinstall."
echo ""
