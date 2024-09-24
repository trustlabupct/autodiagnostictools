import os
import subprocess
import sys


def check_if_root():
    """Checks if the script is being run as root."""
    if os.geteuid() != 0:
        print("This script requires administrator privileges.")
        print("Restarting the script with 'sudo'...")
        subprocess.call(["sudo", "python3"] + sys.argv)
        sys.exit()


def ensure_directory_exists(directory):
    """Checks if a directory exists, and if not, creates it with the appropriate permissions."""
    try:
        if not os.path.exists(directory):
            print(f"Creating directory: {directory}")
            os.makedirs(directory)
            subprocess.run(["chown", "clamav:clamav", directory], check=True)
            print(f"Directory created and permissions set for: {directory}")
        else:
            print(f"The directory already exists: {directory}")
    except Exception as e:
        print(f"Error ensuring the existence of the directory {directory}: {e}")


def checkClamInstallation():
    """Checks if ClamAV is installed and installs it if necessary."""
    try:
        print("Checking if ClamAV is installed...")
        result = subprocess.run(
            ["which", "clamdscan"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print("ClamAV is already installed on the system.")
        print("Installation path is: " + result.stdout.decode("utf-8").strip())
        print("Checking if the database is up to date...")
        subprocess.run(["freshclam"], check=True)
        print("The ClamAV database is up to date.")
    except subprocess.CalledProcessError:
        print("ClamAV is not installed. Proceeding to install it...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(
                ["apt-get", "install", "-y", "clamav", "clamav-daemon"], check=True
            )
            subprocess.run(
                [
                    "sed",
                    "-i",
                    "-e",
                    "s/^NotifyClamd/#NotifyClamd/g",
                    "/etc/clamav/freshclam.conf",
                ],
                check=True,
            )
            print("ClamAV installation completed successfully.")
            subprocess.run(["freshclam"], check=True)
            print("The ClamAV database is up to date.")
        except subprocess.CalledProcessError as e:
            print(f"Error during ClamAV installation: {e}")


def startClamdWSL():
    """Starts the clamd service in WSL if it's not already running."""
    directory = "/var/run/clamav"
    ensure_directory_exists(directory)  # Ensure the directory exists
    try:
        result = subprocess.run(
            ["pgrep", "clamd"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if result.returncode == 0:
            print("The clamd service is already running.")
        else:
            print("Starting clamd service manually in WSL...")
            result = subprocess.run(
                ["clamd"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            if result.returncode == 0:
                print("The clamd service has been started manually in WSL.")
            else:
                print(f"Failed to start the clamd service: {result.stderr.strip()}")
    except Exception as e:
        print(f"Error trying to start clamd: {e}")


def windows_to_wsl_path(windows_path):
    """Converts a Windows path to WSL format."""
    return windows_path.replace("C:\\", "/mnt/c/", 1).replace("\\", "/")


def get_windows_user_directories():
    """Gets a list of user directories from C:\\Users within WSL."""
    try:
        result = subprocess.run(
            ["/mnt/c/Windows/System32/cmd.exe", "/c", "dir /b C:\\Users"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        user_dirs = result.stdout.strip().split("\n")
        if user_dirs:
            return user_dirs
        else:
            raise ValueError("No user directories found in C:\\Users.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error retrieving Windows user directories: {e}")


def scanDirectories():
    """Scans Windows user directories for infected files."""
    try:
        user_dirs = get_windows_user_directories()
        directories = ["/mnt/c/Program Files (x86)/"]
        for user_dir in user_dirs:
            downloads_directory_windows = os.path.join(
                "C:\\Users", user_dir, "Downloads"
            )
            documents_directory_windows = os.path.join(
                "C:\\Users", user_dir, "Documents"
            )

            downloads_directory_wsl = windows_to_wsl_path(downloads_directory_windows)
            documents_directory_wsl = windows_to_wsl_path(documents_directory_windows)

            if os.path.exists(downloads_directory_wsl):
                directories.append(downloads_directory_wsl)
            if os.path.exists(documents_directory_wsl):
                directories.append(documents_directory_wsl)

        for directory in directories:
            print(f"Scanning directory: {directory}")
            try:
                result = subprocess.run(
                    ["clamdscan", directory],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                if "FOUND" in result.stdout:
                    print(f"Infected files found in {directory}:")
                    print("Output obtained: " + result.stdout)
                else:
                    print(
                        f"Scan completed without finding infected files in {directory}."
                    )
                    print("Errors found: " + result.stderr)
                    print("Output obtained: " + result.stdout)
            except subprocess.CalledProcessError as e:
                print(f"Error scanning {directory}: {e.stderr}")
                print(f"Standard output: {e.stdout}")
    except Exception as e:
        print(f"An error occurred: {e}")
