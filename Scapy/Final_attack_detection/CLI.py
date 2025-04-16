from scapy.all import *
import argparse
from detector import detect_arp_spoofing, detect_malicious_patterns, detect_syn_flood, detect_port_scan, malicious_data
import time
import threading
import sys
import select
import csv
import os
import signal
from pcap2csv import PcapToCsvConverter

synflood_enabled = True
port_scan_enabled = True
arp_spoofing_enabled = True
malicious_patterns_enabled = True
sniff_enabled = True

data = []
output_file = ""
packets_buffer = []
buffer_start_time = None

def keyboard_listener():
    global synflood_enabled, port_scan_enabled, arp_spoofing_enabled, malicious_patterns_enabled, output_file, data, malicious_data, sniff_enabled
    print("[n] -> activer/désactiver la détection de port scan.")
    print("[a] -> activer/désactiver la détection d'ARP spoofing.")
    print("[s] -> activer/désactiver la détection SYN flood.")
    print("[m] -> activer/désactiver la détection de motifs malveillants.")
    print("[q] -> quitter")
    while True:
        if sys.stdin in select.select([sys.stdin], [], [], 0.1)[0]:
            key = sys.stdin.readline().strip()
            if key.lower() == "s":
                synflood_enabled = not synflood_enabled
                state = "activée" if synflood_enabled else "désactivée"
                print(f"Détection SYN flood {state}.")
            if key.lower() == "n":
                port_scan_enabled = not port_scan_enabled
                state = "activée" if port_scan_enabled else "désactivée"
                print(f"Détection port scan {state}.")
            if key.lower() == "a":
                arp_spoofing_enabled = not arp_spoofing_enabled
                state = "activée" if arp_spoofing_enabled else "désactivée"
                print(f"Détection ARP spoofing {state}.")
            if key.lower() == "m":
                malicious_patterns_enabled = not malicious_patterns_enabled
                state = "activée" if malicious_patterns_enabled else "désactivée"
                print(f"Détection de motifs malveillants {state}.")
            if key.lower() == "q":
                print("Commandes prise en compte, enregistrement des fichiers...")
                #stop le sniffer
                sniff_enabled = False
                wrpcap(output_file + "_all.pcap", data)
                wrpcap(output_file + "_malicious.pcap", malicious_data)
                converter = PcapToCsvConverter(output_file + "_all.pcap", output_file + "_all.csv")
                converter.convert()
                converter = PcapToCsvConverter(output_file + "_malicious.pcap", output_file + "_malicious.csv")
                converter.convert()
                #pcap2csv(output_file + "_all.pcap", output_file + "_all.csv")
                #pcap2csv(output_file + "_malicious.pcap", output_file + "_malicious.csv")
                time.sleep(2)
                print("Quitter...")
                os._exit(0)
                
def packet_callback(packet):
    global data, packets_buffer, buffer_start_time
    data.append(packet)
    if buffer_start_time is None:
        buffer_start_time = time.time()
    packets_buffer.append(packet)
    if time.time() - buffer_start_time > 10:
        if synflood_enabled:
            detect_syn_flood(packets_buffer)
        if arp_spoofing_enabled:
            detect_arp_spoofing(packets_buffer)
        if malicious_patterns_enabled:
            detect_malicious_patterns(packets_buffer)
        if port_scan_enabled:
            detect_port_scan(packets_buffer)
        packets_buffer = []
        buffer_start_time = time.time()

def analyse_direct():
    t = threading.Thread(target=keyboard_listener, daemon=True)
    t.start()
    sniff(prn=packet_callback)

def analyser_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    detect_malicious_patterns(packets)
    detect_syn_flood(packets)
    detect_arp_spoofing(packets)
    detect_port_scan(packets)


def csv_parser(f, data):
    writer = csv.writer(f)
    writer.writerow(["timestamp", "source", "destination", "protocol", "length", "summary"])
    for packet in data:
        timestamp = getattr(packet, "time", "")
        src = dst = proto = length = ""
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
        elif packet.haslayer(ARP):
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
            proto = "ARP"
        length = len(packet)
        summary = packet.summary()
        writer.writerow([timestamp, src, dst, proto, length, summary])
            
             
def write_to_csv():
    global data, malicious_data, output_file
    print("Enregistrement des fichiers csv...")
    with open(output_file + "_all.csv", "w") as f:
        csv_parser(f, data)
    with open(output_file + "_malicious.csv", "w") as f:
        csv_parser(f, malicious_data)
    print("Fichiers csv enregistrés avec succès")

def stop_filter(packet):
    global sniff_enabled
    return not sniff_enabled

def capture(out_file, interface=None):
    global data, output_file, sniff_enabled
    output_file = out_file
    t = threading.Thread(target=keyboard_listener, daemon=True)
    t.start()
    if interface is None:
        sniff(prn=packet_callback, stop_filter=stop_filter)
    else:
        sniff(prn=packet_callback, iface=interface, stop_filter=stop_filter)
    
    # Ajouter la sauvegarde ici aussi
    wrpcap(output_file + "_all.pcap", data)
    wrpcap(output_file + "_malicious.pcap", malicious_data)
    converter = PcapToCsvConverter(output_file + "_all.pcap", output_file + "_all.csv")
    converter.convert()
    converter = PcapToCsvConverter(output_file + "_malicious.pcap", output_file + "_malicious.csv")
    converter.convert() 



def menu():
    parser = argparse.ArgumentParser(description="Outil CLI pour analyser ou capturer des paquets réseau.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_analyze = subparsers.add_parser("analyze", help="Analyser un fichier pcap")
    parser_analyze.add_argument("pcap_file", help="Chemin du fichier pcap à analyser")

    parser_capture = subparsers.add_parser("capture", help="Capturer et analyser des paquets en direct")
    parser_capture.add_argument("output_file", help="Chemin du fichier pcap à enregistrer without extension")
    parser_capture.add_argument("-i", "--interface", help="Interface de capture (ex: eth0, wlan0, lo). Par défaut : eth0 pour linux, en0 pour macos")
    
    args = parser.parse_args()

    if args.command == "analyze":
        analyser_pcap(args.pcap_file)
    elif args.command == "capture":
        capture(args.output_file, args.interface)


def main():
    menu()

if __name__ == "__main__":
    main()