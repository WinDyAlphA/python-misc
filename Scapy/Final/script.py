from scapy.all import sniff, IP, wrpcap
from collections import Counter
import time
import os
THRESHOLD = 20
INTERVAL_RESET = 60
ip_counter = Counter()
last_reset = time.time()


timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

newpath = timestamp
if not os.path.exists(newpath):
    os.makedirs(newpath)

def packet_callback(packet):
    global last_reset

    if time.time() - last_reset > INTERVAL_RESET:
        ip_counter.clear()
        last_reset = time.time()
        print("IP counter reset")

    if IP in packet:
        src_ip = packet[IP].src
        ip_counter[src_ip] += 1

        if ip_counter[src_ip] > THRESHOLD:
            print("🛑 ALERTE 🛑: Trafic suspect détecté!")
            print(f"IP {src_ip} a envoyé {ip_counter[src_ip]} paquets, Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

            wrpcap(f"{timestamp}/suspicious_traffic_{src_ip}.pcap", packet, append=True)


# Démarrage de la capture
print("[+] Démarrage de la surveillance réseau...")
print(f"[+] Seuil d'alerte: {THRESHOLD} paquets")
print(f"[+] Intervalle de reset: {INTERVAL_RESET} secondes")
print("[+] Appuyez sur Ctrl+C pour arrêter\n")


sniff(prn=packet_callback, store=False)