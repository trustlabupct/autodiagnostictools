import os


def modify_clamd_conf(clamd_conf_path):
    # Directories to exclude
    directories = [
        r"Program Files \(x86\)/Google/Chrome/User Data/",
        r"Program Files \(x86\)/Mozilla Firefox/",
        r"Program Files \(x86\)/Microsoft/Edge/",
        r"Program Files \(x86\)/Microsoft/Office/",
        r"Program Files \(x86\)/Microsoft/Visual Studio/",
        r"Program Files \(x86\)/Steam/",
        r"Program Files \(x86\)/Origin/",
        r"Program Files \(x86\)/Java/",
        r"Program Files \(x86\)/Adobe/",
        r"Program Files \(x86\)/Common Files/",
        r"Program Files \(x86\)/Eclipse/",
        r"Program Files \(x86\)/Python/",
        r"Program Files \(x86\)/Ruby/",
        r"Program Files \(x86\)/Adobe/Flash Player/",
        r"Program Files \(x86\)/Updates/",
        r"Program Files \(x86\)/Logs/",
    ]

    # Prepare lines to exclude directories
    exclude_lines_dir = [f"ExcludePath ^/{dir}" for dir in directories]

    try:
        # Read the current content of clamd.conf
        with open(clamd_conf_path, "r") as file:
            content = file.readlines()

        # Reopen the file to append the modifications
        with open(clamd_conf_path, "a") as file:  # Using "a" to avoid overwriting
            # Add directory exclusions if they're not already present
            for exclude_line in exclude_lines_dir:
                if exclude_line not in content:
                    file.write(exclude_line + "\n")

        print(f"Modifications successfully applied to {clamd_conf_path}")

    except Exception as e:
        print(f"Error modifying {clamd_conf_path}: {e}")


# Path to the clamd.conf file (adjust this path as needed)
