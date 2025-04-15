import csv
from scapy.all import rdpcap, Ether, IP, TCP, UDP

class PcapToCsvConverter:
    def __init__(self, pcap_file, csv_file):
        self.pcap_file = pcap_file
        self.csv_file = csv_file

    def convert(self):
        packets = rdpcap(self.pcap_file)
        with open(self.csv_file, 'w', newline='') as csvfile:
            fieldnames = [
                'frame_no', 'timestamp', 'eth_src', 'eth_dst', 'ip_version',
                'src', 'dst', 'proto', 'l4_proto', 'src_port', 'dst_port',
                'length', 'ttl', 'tos', 'flags', 'window_size', 'seq', 'ack',
                'fragment_offset', 'options', 'payload_hex'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for idx, pkt in enumerate(packets, 1):
                row = {
                    'frame_no': idx,
                    'timestamp': pkt.time,
                    'eth_src': pkt[Ether].src if Ether in pkt else 'N/A',
                    'eth_dst': pkt[Ether].dst if Ether in pkt else 'N/A',
                    'ip_version': pkt[IP].version if IP in pkt else 'N/A',
                    'src': pkt[IP].src if IP in pkt else 'N/A',
                    'dst': pkt[IP].dst if IP in pkt else 'N/A',
                    'proto': pkt[IP].proto if IP in pkt else 'N/A',
                    'l4_proto': 'TCP' if TCP in pkt else ('UDP' if UDP in pkt else 'N/A'),
                    'src_port': pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 'N/A'),
                    'dst_port': pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 'N/A'),
                    'length': len(pkt),
                    'ttl': pkt[IP].ttl if IP in pkt else 'N/A',
                    'tos': pkt[IP].tos if IP in pkt else 'N/A',
                    'flags': pkt[TCP].flags if TCP in pkt else ('N/A' if UDP not in pkt else ''),
                    'window_size': pkt[TCP].window if TCP in pkt else 'N/A',
                    'seq': pkt[TCP].seq if TCP in pkt else 'N/A',
                    'ack': pkt[TCP].ack if TCP in pkt else 'N/A',
                    'fragment_offset': pkt[IP].frag if IP in pkt else 'N/A',
                    'options': pkt[TCP].options if TCP in pkt else (pkt[IP].options if IP in pkt else 'N/A'),
                    'payload_hex': (
                        bytes(pkt[TCP].payload).hex() if TCP in pkt else
                        (bytes(pkt[UDP].payload).hex() if UDP in pkt else '')
                    )
                }
                writer.writerow(row)