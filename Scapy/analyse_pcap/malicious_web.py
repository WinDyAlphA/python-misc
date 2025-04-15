from scapy.all import *
import re

def detect_malicious_patterns(packets, patterns):
    for i, pkt in enumerate(packets):
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            for pattern in patterns:
                if isinstance(pattern, bytes):
                    if pattern in payload:
                        print(f"🛑 Alerte - Paquet #{i}, pattern détecté: {pattern} 🛑")
                        print(f"Source: {pkt[IP].src}:{pkt.sport} ---> Destination: {pkt[IP].dst}:{pkt.dport}")
                        print(f"Payload: {payload[:50]}..." if len(payload) > 50 else f"Payload: {payload}")
                        print("-" * 50)
                elif isinstance(pattern, re.Pattern):
                    if pattern.search(payload):
                        print(f"🛑 Alerte - Paquet #{i}, Regex pattern detected 🛑")
                        print(f"Source: {pkt[IP].src}:{pkt.sport} ---> Destination: {pkt[IP].dst}:{pkt.dport}")
                        print(f"Payload: {payload[:50]}..." if len(payload) > 50 else f"Payload: {payload}")
                        print("-" * 50)

malicious_patterns = [
    b"eval(base64_decode",
    b"<script>alert",
    b"SELECT * FROM users WHERE", 
    re.compile(b"password=\w{1,5}")
]

pcap_file = rdpcap('malicious_traffic.pcap')
detect_malicious_patterns(pcap_file, malicious_patterns)