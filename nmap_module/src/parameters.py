import ipaddress
import re
import socket


class Host:
    def __init__(self, ip_range):
        self.ip_range = ip_range

    def is_ip_valid(self):
        # Split addresses by spaces
        ip_addresses = self.ip_range.split()
        for ip in ip_addresses:
            try:
                # Check if it is a network or an IP address
                ipaddress.ip_network(ip, strict=False)
            except ValueError:
                return "Invalid IP Format !"  # Return the error message
        return True


class PortRange:
    def __init__(self, port_range):
        self.port_range = port_range

    # Check if it is a valid port
    def is_port_valid(self):

        # For a specific port
        if re.fullmatch(r"\d+", self.port_range):
            port = int(self.port_range)
            if 1 <= port <= 65535:
                return True
            else:
                return "Invalid Port Range!"

        # For a range of ports
        if re.fullmatch(r"\d+-\d+", self.port_range):
            port_start, port_end = map(int, self.port_range.split("-"))
            if 1 <= port_start <= port_end <= 65535:
                return True
            else:
                return "Invalid Port Range!"

        return "Invalid Port Range!"


if __name__ == "__main__":
    host1 = Host("192.168.1.0/24")  # True
    host2 = Host("192.168.1.0")  # True
    host3 = Host("192.168.1.024")  # False
    host4 = Host("192.168.1.0/50")  # False
    host5 = Host("192")  # False
    host6 = Host("172.28.128.0/20 192.168.56.0/24")  # True
    host7 = Host("172.28.128.0/20 192.168.56ij4 172.20.10.0/28")  # False
    print(
        f"IP tests results are: {host1.is_ip_valid()}, {host2.is_ip_valid()}, {host3.is_ip_valid()}, {host4.is_ip_valid()}, {host5.is_ip_valid()}, {host6.is_ip_valid()}, {host7.is_ip_valid()}"
    )

    port1 = PortRange("1000")  # True
    port2 = PortRange("1000-2200")  # True
    port3 = PortRange("200-20")  # False
    port4 = PortRange("-20000")  # False
    port5 = PortRange("20000-")  # False
    port6 = PortRange("oeihfozei")  # False
    port7 = PortRange("1212121212")  # False
    print(
        f"Port tests results are: {port1.is_port_valid()}, {port2.is_port_valid()}, {port3.is_port_valid()}, {port4.is_port_valid()}, {port5.is_port_valid()}, {port6.is_port_valid()}, {port7.is_port_valid()}"
    )
