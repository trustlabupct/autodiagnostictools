import ipaddress
import re
import socket

class Ip:
    def __init__(self, ip_range):
        self.ip_range = ip_range

    def is_ip_valid(self):
        try:
            ipaddress.ip_network(self.ip_range, strict=False)
            return True
        except ValueError:
            try:
                # Attempt to resolve domain name to IP
                socket.gethostbyname(self.ip_range)
                return True
            except socket.error:
                return "Invalid IP Range or Domain Name !"

class PortRange:
    def __init__(self, port_range):
        self.port_range = port_range


    def is_port_valid(self):
        
        # For a specific port
        if re.fullmatch(r"\d+", self.port_range):
            port = int(self.port_range)
            if 1 <= port <= 65535:
                return True
            else:
                return "Invalid Port Range !"

        # For a range of ports
        if re.fullmatch(r"\d+-\d+", self.port_range):
            port_start, port_end = map(int, self.port_range.split('-'))
            if 1 <= port_start <= port_end <= 65535:
                return True
            else:
                return "Invalid Port Range !"
        
        return "Invalid Port Range !"


if __name__ == "__main__":
    ip1 = Ip('192.168.1.0/24') # True
    ip2 = Ip('192.168.1.0') # True
    ip3 = Ip('192.168.1.024') # False
    ip4 = Ip('192.168.1.0/50') # False
    ip5 = Ip('192') # False
    print(f'Les résultats de tests ip sont : {ip1.is_ip_valid()}, {ip2.is_ip_valid()}, {ip3.is_ip_valid()}, {ip4.is_ip_valid()}, {ip5.is_ip_valid()}')


    port1 = PortRange("1000") # True
    port2 = PortRange("1000-2200") # True
    port3 = PortRange("200-20") # False
    port4 = PortRange("-20000") # False
    port5 = PortRange("20000-") # False
    port6 = PortRange("oeihfozei") # False
    port7 = PortRange("1212121212") # False
    print(f'Les résultats de tests de ports sont :{port1.is_port_valid()}, {port2.is_port_valid()}, {port3.is_port_valid()}, {port4.is_port_valid()}, {port5.is_port_valid()}, {port6.is_port_valid()}, {port7.is_port_valid()}')