from scapy.all import *

pcap_file = rdpcap('nmap.pcap')

THRESHOLD = 100

def detect_syn_flood(packets):
  syn_count = 0
  for packet in packets:
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
      syn_count += 1
  return syn_count > THRESHOLD

if __name__ == "__main__":
  if detect_syn_flood(pcap_file):
    print("🔴 SYN flood detected 🔴")
  else:
    print("🟢 No SYN flood detected 🟢")

