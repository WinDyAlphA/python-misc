from scapy.all import *

def detect_arp_spoofing(packets):
  arp_table = {}
  for packet in packets:
    if packet.haslayer(ARP) and packet[ARP].op == 2:
      ip = packet[ARP].psrc
      mac = packet[ARP].hwsrc
      if ip in arp_table and arp_table[ip] != mac:
        print(f"🛑 ARP spoofing detected: {ip} is pretending to be {mac} 🔴")
      else:
        arp_table[ip] = mac

if __name__ == "__main__":
  pcap_file = rdpcap('arpspoof.pcap')
  detect_arp_spoofing(pcap_file)
