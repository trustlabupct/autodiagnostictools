import typer
from src.requests import host_scanner, port_scanner_tcp_syn, port_scanner_udp
from src.parameters import Ip, PortRange 
import time


app = typer.Typer()

@app.command()
def scan_all(ip_range: str, port_range_tcp: str, port_range_udp: str):

    # Creation of instance
    ip_instance = Ip(ip_range)
    ip_validation = ip_instance.is_ip_valid()

    port_instance_tcp = PortRange(port_range_tcp)
    port_validation_tcp = port_instance_tcp.is_port_valid()

    port_instance_udp = PortRange(port_range_udp)
    port_validation_udp = port_instance_udp.is_port_valid()

    # Check if there is the correct format
    if ip_validation is True and port_validation_tcp is True and port_validation_udp is True:
        hosts_list = host_scanner(ip_range)  # Host scanning
        final_list = [(host, '') for host, _ in hosts_list]  # Formatting list
        print (hosts_list)
        # Scan TCP SYN and UDP
        print(port_scanner_tcp_syn(final_list, port_range_tcp))
        print(port_scanner_udp(final_list, port_range_udp))
    else:
        # Print errors
        if ip_validation is not True:
            print(ip_validation)
        if port_validation_tcp is not True:
            print(port_validation_tcp)
        if port_validation_udp is not True:
            print(port_validation_udp)
    # Calculate and print the execution timing
    end_time = time.time()
    print(f"Execution Time : {end_time - start_time:.2f} secondes")


if __name__ == "__main__":
    # Start timer
    start_time = time.time() 
    app()
