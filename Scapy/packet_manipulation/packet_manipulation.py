from scapy.all import *
from scapy.all import IPOption

fragmented_packets = fragment(IP(dst="8.8.8.8")/ ICMP(), fragsize=20 )

for packet in fragmented_packets:
    print(packet.show())
    send(packet)

