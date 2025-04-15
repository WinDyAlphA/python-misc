from scapy.all import *

pcap_file = rdpcap('capture.pcap')

for packet in pcap_file:
    if packet.haslayer(TCP) and packet[TCP].flags == "S" and packet[TCP].dport > 1000:
        print(f"SYN packet detected on port {packet[TCP].dport}")
