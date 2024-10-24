## Useful Sites
https://pypi.org/project/python-nmap/  
https://www.studytonight.com/network-programming-in-python/integrating-port-scanner-with-nmap  
https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/ -> provides the 1000 most used ports by UDP or TCP

## Useful Commands
--> If I want to listen on a TCP port "sudo nc -lvp 8888"  
--> If I want to listen on a UDP port "sudo socat UDP-RECVFROM:53,fork EXEC:'/bin/echo "UDP port is open"'" -> This will not simply work by listening with netcat  
because Nmap will not get a response and will consider the port to be closed  
--> sudo nmap -sU -Pn 192.168.56.102 -F --max-retries 2 --host-timeout 10m -> For UDP to save time  
--> to format my files with Black for Python "black ."  

## Test Zones
Private: 192.168.56.0/24  
Public: koulier.ovh = 51.79.157.107 / scanme.nmap.org = 45.33.32.156
