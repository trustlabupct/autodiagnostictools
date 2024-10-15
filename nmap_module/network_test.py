from nmap_module.src.host_machine_info import get_ip_info, extract_ip_and_subnet, get_cidr_ranges
from nmap_module.src.requests import host_scanner, port_scanner_tcp_syn, port_scanner_udp
from nmap_module.src.parameters import Host, PortRange
import time


def scan_all(port_range_tcp: str, port_range_udp: str):
    print(f"scan_all function called")  # Debug
    # Retrieve and display IP information
    ip_info = get_ip_info()

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

    # If everything is valid -> host scan -> TCP SYN scan -> UDP scan
    if (
        host_validation is True
        and port_validation_tcp is True
        and port_validation_udp is True
    ):
        hosts_list = host_scanner(cidr_string)  # Host scanning
        final_list = [
            (host, "") for host, _ in hosts_list
        ]  # Preparing the list for other function operations
        active_hosts = hosts_list  # Store active hosts

        # TCP SYN and UDP scans
        tcp_results = port_scanner_tcp_syn(final_list, port_range_tcp)
        udp_results = port_scanner_udp(final_list, port_range_udp)

        # Return active hosts with scan results
        print(f"Execution finished")  # Debug
        return active_hosts, tcp_results, udp_results
    else:
        # Print errors if there are any
        if host_validation is not True:
            print(host_validation)
        if port_validation_tcp is not True:
            print(port_validation_tcp)
        if port_validation_udp is not True:
            print(port_validation_udp)

    return [], {}, {}  # Return empty values in case of errors


if __name__ == "__main__":
    # Start timer
    start_time = time.time()

    # Use nmap to scan the most important: host / TCP Syn / UDP
    scan_all("1000", "100")

    # Calculate and print the execution timing
    end_time = time.time()
    print(f"Execution Time: {end_time - start_time:.2f} seconds")
