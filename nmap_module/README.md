## Sites Utiles
https://pypi.org/project/python-nmap/  
https://www.studytonight.com/network-programming-in-python/integrating-port-scanner-with-nmap  
https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/ -> donne les 1000 ports les plus utilisés par udp ou tcp  

## Commandes utiles
--> Si je veux écouter sur un port TCP "sudo nc -lvp 8888"  
--> Si je veux écouter sur un port UDP "sudo socat UDP-RECVFROM:53,fork EXEC:'/bin/echo "UDP port is open"'" -> Cela ne fonctionnera pas simplement en écoutant avec netcat  
car Nmap n'obtiendra pas de réponse et considérera que le port est fermé  
--> sudo nmap -sU -Pn 192.168.56.102  -F --max-retries 2 --host-timeout 10m -> Pour UDP pour gagner du temps  
--> pour formatter mes fichiers avec black python "black ."

## Zones de Test
Privé : 192.168.56.0/24  
Public : koulier.ovh = 51.79.157.107  / scanme.nmap.org = 45.33.32.156
