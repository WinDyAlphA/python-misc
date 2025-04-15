from scapy.all import *
import re

malicious_data = []


def detect_arp_spoofing(packets):
  global malicious_data
  arp_table = {}
  for packet in packets:
    if packet.haslayer(ARP) and packet[ARP].op == 2:
      ip = packet[ARP].psrc
      mac = packet[ARP].hwsrc
      if ip in arp_table and arp_table[ip] != mac:
        print(f"🛑 ARP spoofing detected: {ip} is pretending to be {mac} 🔴")
        malicious_data.append(packet)
      else:
        arp_table[ip] = mac


malicious_patterns = [
    b"eval(base64_decode",
    b"<script>alert",
    b"SELECT * FROM users WHERE", 
    re.compile(b"password=\w{1,5}")
]

def detect_malicious_patterns(packets):
  global malicious_data
  for i, pkt in enumerate(packets):
    if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            for pattern in malicious_patterns:
                if isinstance(pattern, bytes):
                    if pattern in payload:
                        print(f"🛑 Alerte - Paquet #{i}, pattern détecté: {pattern} 🛑")
                        print(f"Source: {pkt[IP].src}:{pkt.sport} ---> Destination: {pkt[IP].dst}:{pkt.dport}")
                        print(f"Payload: {payload[:50]}..." if len(payload) > 50 else f"Payload: {payload}")
                        print("-" * 50)
                        malicious_data.append(pkt)
                elif isinstance(pattern, re.Pattern):
                    if pattern.search(payload):
                        print(f"🛑 Alerte - Paquet #{i}, Regex pattern detected 🛑")
                        print(f"Source: {pkt[IP].src}:{pkt.sport} ---> Destination: {pkt[IP].dst}:{pkt.dport}")
                        print(f"Payload: {payload[:50]}..." if len(payload) > 50 else f"Payload: {payload}")
                        print("-" * 50)
                        malicious_data.append(pkt)

def detect_port_scan(packets):
  global malicious_data
  ip_ports = {}
  ip_packets = {}
  
  for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
      src_ip = pkt[IP].src
      dst_port = pkt[TCP].dport
      
      if src_ip not in ip_ports:
        ip_ports[src_ip] = set()
        ip_packets[src_ip] = []
        
      ip_ports[src_ip].add(dst_port)
      ip_packets[src_ip].append(pkt)
      if len(ip_ports[src_ip]) > 100:
        print(f"🛑 Port scan detected: {src_ip} has connected to more than 100 different ports 🔴")
        malicious_data.extend(ip_packets[src_ip])

def detect_syn_flood(packets):
  global malicious_data
  ip_syn_count = {}
  ip_packets = {}
  
  for packet in packets:
    if packet.haslayer(TCP) and packet[TCP].flags == "S" and packet.haslayer(IP):
      src_ip = packet[IP].src
      
      if src_ip not in ip_syn_count:
        ip_syn_count[src_ip] = 0
        ip_packets[src_ip] = []
        
      ip_syn_count[src_ip] += 1
      ip_packets[src_ip].append(packet)
      
      if ip_syn_count[src_ip] > 100:
        print(f"🔴 SYN flood detected from {src_ip} 🔴")
        malicious_data.extend(ip_packets[src_ip])
