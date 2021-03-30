import scapy.all as scapy
import sys

if (len(sys.argv) != 2):
    print(f'[*] Usage: python3 {sys.argv[0]} <Hosts to scan>')
    print(f'[*] Example: python3 {sys.argv[0]} 192.168.1.0/24')
    sys.exit(0)

def scan(ip):
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp = scapy.ARP(pdst=ip)
    arp_request = broadcast/arp
    answered = scapy.srp(arp_request, timeout=2, verbose=0)[0]
    print('IP\t\t\tMAC Address')
    print('--------------\t\t------------------')
    for element in answered:
        print(element[1].psrc + '\t\t' + element[1].hwsrc)

scan(sys.argv[1])
