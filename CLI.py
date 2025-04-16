import threading
from scapy.all import sniff, wrpcap
from PcapToCsvConverter import PcapToCsvConverter

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