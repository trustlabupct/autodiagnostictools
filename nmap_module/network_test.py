from src.host_machine_info import get_windows_ip, extract_ip_and_subnet, get_cidr_ranges
from src.requests import host_scanner, port_scanner_tcp_syn, port_scanner_udp
from src.parameters import Host, PortRange
import time


# Function for execution of the following process : info sys of windows host -> host scan on ip range -> TCP SYN scan -> UDP Scan
def scan_all(port_range_tcp: str, port_range_udp: str):
    # Retrieve and display IP information
    ip_info = get_windows_ip()

    # Extract IP addresses and their subnet masks
    ip_subnet_dict = extract_ip_and_subnet(ip_info)

    # Final list of CIDR Ranges
    cidr_ranges = get_cidr_ranges(ip_subnet_dict)
    cidr_string = " ".join(cidr_ranges)

    # Create IP instance and check if it is valid
    host_instance = Host(cidr_string)
    host_validation = host_instance.is_ip_valid()

    # Create port instance and check if it is valid
    port_instance_tcp = PortRange(port_range_tcp)
    port_validation_tcp = port_instance_tcp.is_port_valid()

    # Create port instance and check if it is valid
    port_instance_udp = PortRange(port_range_udp)
    port_validation_udp = port_instance_udp.is_port_valid()

    # If everything is valid -> host scan -> TCP SYN scan -> UDP Scan
    if (
        host_validation is True
        and port_validation_tcp is True
        and port_validation_udp is True
    ):
        hosts_list = host_scanner(cidr_string)  # Host scanning
        final_list = [
            (host, "") for host, _ in hosts_list
        ]  # Preparing the list for other function operations
        print(hosts_list)
        # TCP SYN and UDP Scans
        print(port_scanner_tcp_syn(final_list, port_range_tcp))
        print(port_scanner_udp(final_list, port_range_udp))
    else:
        # Print errors if you have one
        if host_validation is not True:
            print(host_validation)
        if port_validation_tcp is not True:
            print(port_validation_tcp)
        if port_validation_udp is not True:
            print(port_validation_udp)


if __name__ == "__main__":
    # Start timer
    start_time = time.time()

    # Use nmap to scan the most important : host / TCP Syn / UDP
    scan_all("1000", "100")

    # Calculate and print the execution timing
    end_time = time.time()
    print(f"Execution Time : {end_time - start_time:.2f} secondes")
