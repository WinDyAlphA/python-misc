from scapy.all import sniff, IP, wrpcap, Raw, TCP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"IP Source: {src_ip} -> IP Destination: {dst_ip}")
    else:
        print("Non IP packet")

packets = sniff(prn=packet_callback, count=100)
wrpcap("packets.pcap", packets)
print("Packets saved to packets.pcap")

print("-"*100)
# Capture avec filtre HTTP
packets = sniff(prn=packet_callback, count=1, filter="tcp port 80")
wrpcap("http_packets.pcap", packets)
print("HTTP packets saved to http_packets.pcap")

print("-"*100)

# Capture avec filtre ARP
packets = sniff(prn=packet_callback, count=1, filter="arp")
wrpcap("arp_packets.pcap", packets)
print("ARP packets saved to arp_packets.pcap")

print("-"*100)
