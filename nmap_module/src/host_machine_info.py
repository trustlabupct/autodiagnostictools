import subprocess
import re
import ipaddress


def get_windows_ip():
    # Execute the ipconfig command
    result = subprocess.run(
        ["/mnt/c/Windows/System32/wsl.exe", "ipconfig.exe"], capture_output=True
    )

    # Decode the output, replacing invalid characters
    stdout = result.stdout.decode("utf-8", errors="replace")

    return stdout


def extract_ip_and_subnet(output):
    # Define regex patterns for different languages
    patterns = [
        {
            "ipv4": re.compile(r"IPv4 Address[^\d]*(\d+\.\d+\.\d+\.\d+)"),  # English
            "subnet": re.compile(r"Subnet Mask[^\d]*: (\d+\.\d+\.\d+\.\d+)"),  # English
        },
        {
            "ipv4": re.compile(r"Adresse IPv4[^\d]*(\d+\.\d+\.\d+\.\d+)"),  # French
            "subnet": re.compile(r"Masque[^\n]*: (\d+\.\d+\.\d+\.\d+)"),  # French
        },
        {
            "ipv4": re.compile(r"Dirección IPv4[^\d]*(\d+\.\d+\.\d+\.\d+)"),  # Spanish
            "subnet": re.compile(
                r"Máscara de subred[^\d]*: (\d+\.\d+\.\d+\.\d+)"
            ),  # Spanish
        },
        # Add more languages as needed
    ]

    ipv4_addresses = []
    subnet_masks = []

    for pattern in patterns:
        ipv4_addresses.extend(pattern["ipv4"].findall(output))
        subnet_masks.extend(pattern["subnet"].findall(output))

    # Create a dictionary matching IP addresses to subnet masks
    ip_subnet_dict = {ip: subnet for ip, subnet in zip(ipv4_addresses, subnet_masks)}

    return ip_subnet_dict


def get_cidr_ranges(ip_subnet_dict):
    cidr_list = []

    # For each IP address and its subnet mask
    for ip, subnet_mask in ip_subnet_dict.items():
        # Create the CIDR range and add it to the list
        network = ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)
        cidr_list.append(str(network))

    return cidr_list


if __name__ == "__main__":
    # Retrieve and display IP information
    ip_info = get_windows_ip()
    print("IP Info:\n", ip_info)

    # Extract IP addresses and their subnet masks
    ip_subnet_dict = extract_ip_and_subnet(ip_info)

    # Display the dictionary of IP addresses and subnet masks
    print("IP and Subnet Masks:\n", ip_subnet_dict)

    cidr_ranges = get_cidr_ranges(ip_subnet_dict)
    print("CIDR Ranges:", cidr_ranges)
