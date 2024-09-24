import nmap
import time


# Take IP range and nmap parameter as entries and return a list of tuple of every host with their state that are up
def host_scanner(ip_range):
    nmScan = nmap.PortScanner()  # Initialize the port scanner
    nmScan.scan(hosts=ip_range, arguments="-sn")  # Only discovery phase
    return [(x, nmScan[x]["status"]["state"]) for x in nmScan.all_hosts()]


# Process a TCP Syn scan with a host list and a port_range as parameters
def port_scanner_tcp_syn(hosts_list, port_range):
    nmScan = nmap.PortScanner()  # Initialize the port scanner
    final_hosts = " ".join([host[0] for host in hosts_list])
    # Process a TCP Syn scan and skip discovery phase
    print(
        nmScan.scan(hosts=final_hosts, arguments=f" -sS -Pn --top-ports {port_range}")
    )
    scan_results = {}

    # Browse each host and retrieve the status of open or filtered ports
    for host in nmScan.all_hosts():
        if "tcp" in nmScan[host]:
            # Check for TCP results
            for port, port_data in nmScan[host]["tcp"].items():
                if port_data["state"] in [
                    "open",
                    "filtered",
                ]:  # Keep only 'open' or 'filtered'
                    if host not in scan_results:
                        scan_results[host] = (
                            {}
                        )  # Initialize a subdictionary for each host
                    scan_results[host][str(port)] = port_data[
                        "state"
                    ]  # Add the port and its state
                    service_name = port_data.get("name", "unknown")
                    scan_results[host][str(port)] = {
                        "state": port_data["state"],
                        "service": service_name,
                    }  # Add the port details
    return scan_results


# Process a UDP scan with a host list and a port_range as parameters
def port_scanner_udp(hosts_list, port_range):
    nmScan = nmap.PortScanner()  # Initialize the port scanner
    final_hosts = " ".join([host[0] for host in hosts_list])
    nmScan.scan(
        hosts=final_hosts, arguments=f" -sU -Pn --top-ports {port_range}"
    )  # Skip discovery phase and process a UDP scan
    scan_results = {}

    # Browse each host and retrieve the status of open or filtered ports
    for host in nmScan.all_hosts():
        if "udp" in nmScan[host]:  # Check for UDP results
            for port, port_data in nmScan[host]["udp"].items():
                if port_data["state"] in [
                    "open",
                    "filtered",
                ]:  # Keep only 'open' or 'filtered'
                    if host not in scan_results:
                        scan_results[host] = (
                            {}
                        )  # Initialize a subdictionary for each host
                    scan_results[host][str(port)] = port_data[
                        "state"
                    ]  # Add the port and its state
                    # Add the port, its state, and the service name (if available)
                    service_name = port_data.get("name", "unknown")
                    scan_results[host][str(port)] = {
                        "state": port_data["state"],
                        "service": service_name,
                    }  # Add the port details
    return scan_results


if __name__ == "__main__":
    from parameters import Host, PortRange

    # Start timer
    start_time = time.time()

    # Create IP instance and check if it is valid
    host_instance = Host("192.168.56.0/24")
    host_validation = host_instance.is_ip_valid()

    # Create port instance and check if it is valid
    port_instance_tcp = PortRange("1000")
    port_validation_tcp = port_instance_tcp.is_port_valid()
    # Create port instance and check if it is valid
    port_instance_udp = PortRange("100")
    port_validation_udp = port_instance_udp.is_port_valid()

    # If everything is valid -> host scan -> TCP SYN scan -> UDP Scan
    if (
        host_validation == True
        and port_validation_tcp == True
        and port_validation_udp == True
    ):
        active_hosts = host_scanner(host_instance.ip_range)
        for host, status in active_hosts:
            print("{0} : {1}".format(host, status))
        print(port_scanner_tcp_syn(active_hosts, port_instance_tcp.port_range))
        print(port_scanner_udp(active_hosts, port_instance_udp.port_range))

    # Print errors if you have one
    if host_validation != True:
        print(host_validation)
    if port_validation_tcp != True:
        print(host_validation_tcp)
    if port_validation_udp != True:
        print(host_validation_udp)

    # Calculate and print the execution timing
    end_time = time.time()
    print(f"Execution time : {end_time - start_time:.2f} seconds")
