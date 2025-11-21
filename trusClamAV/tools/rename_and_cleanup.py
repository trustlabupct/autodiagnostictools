#!/usr/bin/env python3
"""
Cleanup script for trusClamAV legacy artifacts.

This script performs:
1. Updates any remaining legacy references
2. Cleans up old cache files and directories
3. Provides a summary of changes

Note: The original migration from clamav_module to trusClamAV is complete.
This tool is kept for maintenance purposes.
"""

import os
import re
import shutil
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Set

class RenameAndCleanup:
    """Handles the renaming and cleanup process."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.old_name = "trusClamAV"
        self.new_name = "trusClamAV"
        self.changed_files: List[Tuple[str, str]] = []
        self.deleted_files: List[str] = []
        self.created_files: List[str] = []
        self.errors: List[str] = []

    def run(self) -> None:
        """Execute the complete rename and cleanup process."""
        print(f"Starting migration from '{self.old_name}' to '{self.new_name}'...")
        print("=" * 70)

        # Step 1: Clean up caches and legacy files first
        self.cleanup_legacy_files()

        # Step 2: Rename the main package directory
        self.rename_package_directory()

        # Step 3: Update all imports and references
        self.update_imports_and_references()

        # Step 4: Update configuration files
        self.update_config_files()

        # Step 5: Clean up any remaining caches
        self.cleanup_caches()

        # Step 6: Print summary
        self.print_summary()

    def cleanup_legacy_files(self) -> None:
        """Remove legacy and unnecessary files."""
        print("\n1. Cleaning up legacy files...")

        legacy_files = [
            # Legacy files with spaces in names
            "Windows ClamAV Handler.py",
            # Temporary files
            "tempCodeRunnerFile.py",
            # Old scan outputs in root
            "scan_output.txt",
            "output/trusclamav/scan.txt",
            "output/trusclamav/scan.json",
            "security_scan.log",
            # Duplicate GUI in parent
            "../gui.py",
            "../main.py",
        ]

        legacy_dirs = [
            # Cache directories
            "__pycache__",
            "../__pycache__",
            # Strange Windows path directory
            "C:\\ProgramData",
            "../C:\\ProgramData",
            # Legacy directory if exists
            "legacy",
        ]

        # Clean files
        for file_path in legacy_files:
            full_path = self.project_root / self.old_name / file_path
            if full_path.exists():
                try:
                    full_path.unlink()
                    self.deleted_files.append(str(full_path.relative_to(self.project_root)))
                    print(f"  [OK] Deleted: {file_path}")
                except Exception as e:
                    self.errors.append(f"Failed to delete {file_path}: {e}")
                    print(f"  [ERROR] Failed to delete {file_path}: {e}")

        # Clean directories
        for dir_path in legacy_dirs:
            full_path = self.project_root / self.old_name / dir_path
            if full_path.exists():
                try:
                    shutil.rmtree(full_path)
                    self.deleted_files.append(str(full_path.relative_to(self.project_root)))
                    print(f"  [OK] Deleted directory: {dir_path}")
                except Exception as e:
                    self.errors.append(f"Failed to delete {dir_path}: {e}")
                    print(f"  [ERROR] Failed to delete {dir_path}: {e}")

    def rename_package_directory(self) -> None:
        """Rename the main package directory."""
        print("\n2. Renaming package directory...")

        old_path = self.project_root / self.old_name
        new_path = self.project_root / self.new_name

        if old_path.exists():
            if new_path.exists():
                print(f"  [WARN] {self.new_name} already exists. Backing up...")
                backup_path = self.project_root / f"{self.new_name}_backup"
                shutil.move(str(new_path), str(backup_path))
                print(f"  [OK] Backed up to {backup_path}")

            try:
                shutil.move(str(old_path), str(new_path))
                self.changed_files.append((str(old_path.relative_to(self.project_root)),
                                          str(new_path.relative_to(self.project_root))))
                print(f"  [OK] Renamed: {self.old_name}/ → {self.new_name}/")
            except Exception as e:
                self.errors.append(f"Failed to rename directory: {e}")
                print(f"  [ERROR] Failed to rename directory: {e}")
                sys.exit(1)
        else:
            print(f"  [INFO] {self.old_name} directory not found, checking if already renamed...")
            if new_path.exists():
                print(f"  [OK] {self.new_name} already exists")
            else:
                print(f"  [ERROR] Neither {self.old_name} nor {self.new_name} found!")
                sys.exit(1)

    def update_imports_and_references(self) -> None:
        """Update all Python imports and string references."""
        print("\n3. Updating imports and references...")

        package_path = self.project_root / self.new_name

        # Patterns to replace
        replacements = [
            # Import statements
            (r'from\s+clamav_module', f'from {self.new_name}'),
            (r'import\s+clamav_module', f'import {self.new_name}'),
            # CLI invocations
            (r'python\s+-m\s+clamav_module', f'python -m {self.new_name}'),
            (r'"trusClamAV"', f'"{self.new_name}"'),
            (r"'trusClamAV'", f"'{self.new_name}'"),
            # Program names
            (r'prog=[\'""]clamav_module[\'""]', f"prog='{self.new_name}'"),
            # Module references
            (r'clamav_module\.', f'{self.new_name}.'),
            # Log paths
            (r'%ProgramData%\\clamav_module', f'%ProgramData%\\{self.new_name}'),
            (r'ProgramData\\\\clamav_module', f'ProgramData\\\\{self.new_name}'),
        ]

        # Process all Python files
        for py_file in package_path.rglob("*.py"):
            self._update_file(py_file, replacements)

        # Process configuration files
        for config_file in package_path.glob("*.toml"):
            self._update_file(config_file, replacements)

        for config_file in package_path.glob("*.md"):
            self._update_file(config_file, replacements)

    def _update_file(self, file_path: Path, replacements: List[Tuple[str, str]]) -> None:
        """Update a single file with the given replacements."""
        try:
            content = file_path.read_text(encoding='utf-8')
            original_content = content

            for pattern, replacement in replacements:
                content = re.sub(pattern, replacement, content)

            if content != original_content:
                file_path.write_text(content, encoding='utf-8')
                rel_path = file_path.relative_to(self.project_root)
                self.changed_files.append((str(rel_path), str(rel_path)))
                print(f"  [OK] Updated: {rel_path}")
        except Exception as e:
            self.errors.append(f"Failed to update {file_path}: {e}")
            print(f"  [ERROR] Failed to update {file_path}: {e}")

    def update_config_files(self) -> None:
        """Update package configuration files."""
        print("\n4. Updating configuration files...")

        package_path = self.project_root / self.new_name

        # Update pyproject.toml
        pyproject_path = package_path / "pyproject.toml"
        if pyproject_path.exists():
            try:
                content = pyproject_path.read_text()

                # Update package name
                content = re.sub(r'name\s*=\s*"[^"]*"', f'name = "{self.new_name}"', content)

                # Update console script entry points
                content = re.sub(
                    r'clamav\s*=\s*"clamav_module\.cli:main"',
                    f'trusclamav = "{self.new_name}.cli:main"',
                    content
                )

                # Update any module references
                content = content.replace(self.old_name, self.new_name)

                pyproject_path.write_text(content)
                print(f"  [OK] Updated pyproject.toml")
            except Exception as e:
                self.errors.append(f"Failed to update pyproject.toml: {e}")
                print(f"  [ERROR] Failed to update pyproject.toml: {e}")

        # Update README if it exists
        readme_path = package_path / "README.md"
        if readme_path.exists():
            try:
                content = readme_path.read_text()
                content = content.replace(self.old_name, self.new_name)
                content = content.replace("clamav-module", "trusClamAV")
                content = content.replace("ClamAV Module", "trusClamAV")
                readme_path.write_text(content)
                print(f"  [OK] Updated README.md")
            except Exception as e:
                self.errors.append(f"Failed to update README.md: {e}")

    def cleanup_caches(self) -> None:
        """Clean up any Python cache files."""
        print("\n5. Cleaning up cache files...")

        package_path = self.project_root / self.new_name

        # Find and remove all __pycache__ directories
        cache_dirs = list(package_path.rglob("__pycache__"))
        for cache_dir in cache_dirs:
            try:
                shutil.rmtree(cache_dir)
                self.deleted_files.append(str(cache_dir.relative_to(self.project_root)))
                print(f"  [OK] Deleted: {cache_dir.relative_to(self.project_root)}")
            except Exception as e:
                self.errors.append(f"Failed to delete {cache_dir}: {e}")

        # Remove .pyc files
        pyc_files = list(package_path.rglob("*.pyc"))
        for pyc_file in pyc_files:
            try:
                pyc_file.unlink()
                self.deleted_files.append(str(pyc_file.relative_to(self.project_root)))
                print(f"  [OK] Deleted: {pyc_file.relative_to(self.project_root)}")
            except Exception as e:
                self.errors.append(f"Failed to delete {pyc_file}: {e}")

    def print_summary(self) -> None:
        """Print a summary of all changes."""
        print("\n" + "=" * 70)
        print("MIGRATION SUMMARY")
        print("=" * 70)

        print(f"\n[OK] Migration succeeded from '{self.old_name}' to '{self.new_name}'")

        if self.changed_files:
            print(f"\n[INFO] Modified/Renamed {len(self.changed_files)} items:")
            for old, new in self.changed_files[:10]:  # Show first 10
                if old != new:
                    print(f"   {old} → {new}")
                else:
                    print(f"   {new}")
            if len(self.changed_files) > 10:
                print(f"   ... and {len(self.changed_files) - 10} more")

        if self.deleted_files:
            print(f"\n[INFO] Deleted {len(self.deleted_files)} files/directories:")
            for file_path in self.deleted_files[:10]:  # Show first 10
                print(f"   {file_path}")
            if len(self.deleted_files) > 10:
                print(f"   ... and {len(self.deleted_files) - 10} more")

        if self.errors:
            print(f"\n[ERROR] Errors encountered ({len(self.errors)}):")
            for error in self.errors:
                print(f"   {error}")

        print("\n" + "=" * 70)
        print("NEXT STEPS:")
        print("=" * 70)
        print("1. Test the new package:")
        print(f"   python -m {self.new_name} doctor")
        print("2. Update any external references or documentation")
        print("3. Commit the changes to version control")
        print("4. Update any deployment scripts or CI/CD pipelines")

        if self.errors:
            print(f"\n[WARN] {len(self.errors)} errors occurred. Please review and fix manually.")
            sys.exit(1)


def main():
    """Main entry point."""
    # Determine project root
    script_path = Path(__file__).resolve()

    # Try to find project root (parent of trusClamAV)
    current = script_path.parent
    while current != current.parent:
        if (current / "trusClamAV").exists():
            project_root = current
            break
        current = current.parent
    else:
        print("Error: Could not find project root (trusClamAV directory)")
        sys.exit(1)

    print(f"Project root: {project_root}")

    # Run the migration
    migrator = RenameAndCleanup(project_root)
    migrator.run()


if __name__ == "__main__":
    main()
