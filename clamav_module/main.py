from clamav import (
    check_if_root,
    checkClamInstallation,
    startClamdWSL,
    scanDirectories,
)

from changeConfiguration import modify_clamd_conf


def main():
    """Main function of the script."""
    print("Welcome to the ClamAV script on WSL2")
    clamd_conf_path = "/etc/clamav/clamd.conf"
    modify_clamd_conf(clamd_conf_path)
    check_if_root()  # Check if running as root
    checkClamInstallation()  # Check and install ClamAV if necessary
    startClamdWSL()  # Start clamd in WSL
    scanDirectories()  # Scan Windows user directories


# Run the main function if this file is being executed directly
if __name__ == "__main__":
    main()
