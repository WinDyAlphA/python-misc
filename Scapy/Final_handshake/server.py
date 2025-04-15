#!/usr/bin/env python3
from scapy.all import *
import socket
import threading
import time

# config
SERVER_IP = '143.110.170.33'
CLIENT_IP = '165.232.101.164'
SERVER_PORT = 8010
CLIENT_PORT = 8011

conf.verb = 1

def start_tcp_socket():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((SERVER_IP, SERVER_PORT))
        sock.listen(5)
        print("socket ouvert " + SERVER_IP + ":" + str(SERVER_PORT))
        while True:
            time.sleep(1)
    except Exception as e:
        print("erreur socket: " + str(e))

def handle_packets(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == SERVER_PORT:
        flags = packet[TCP].flags
        src_ip = packet[IP].src
        src_port = packet[TCP].sport
        
        # syn
        if 'S' in flags and not 'A' in flags:
            print("syn recu de " + src_ip)
            
            if src_ip == CLIENT_IP:
                print("ok c'est le bon client")
                syn_ack = IP(src=SERVER_IP, dst=src_ip)/TCP(sport=SERVER_PORT, 
                                                        dport=src_port,
                                                        flags="SA", 
                                                        seq=1000,
                                                        ack=packet[TCP].seq + 1)
                send(syn_ack, verbose=1)
                print("synack envoye")
            else:
                print("mauvaise source")
        
        # ack final
        elif 'A' in flags and not 'S' in flags and not 'P' in flags and not 'F' in flags:
            print("ack recu de " + src_ip)
            print("handshake ok!")
        
        # data
        elif 'P' in flags and 'A' in flags:
            print("data de " + src_ip)
            if packet.haslayer(Raw):
                print("contenu: " + str(packet[Raw].load))
            
            ack = IP(src=SERVER_IP, dst=src_ip)/TCP(sport=SERVER_PORT,
                                                dport=src_port,
                                                flags="A",
                                                seq=packet[TCP].ack,
                                                ack=packet[TCP].seq + len(packet[Raw].load) if packet.haslayer(Raw) else packet[TCP].seq + 1)
            send(ack, verbose=1)
            print("ack envoye")
        
        # fin
        elif 'F' in flags:
            print("fin recu")
            ack = IP(src=SERVER_IP, dst=src_ip)/TCP(sport=SERVER_PORT,
                                                dport=src_port,
                                                flags="A",
                                                seq=packet[TCP].ack,
                                                ack=packet[TCP].seq + 1)
            send(ack, verbose=1)
            
            fin_ack = IP(src=SERVER_IP, dst=src_ip)/TCP(sport=SERVER_PORT,
                                                    dport=src_port,
                                                    flags="FA",
                                                    seq=packet[TCP].ack,
                                                    ack=packet[TCP].seq + 1)
            send(fin_ack, verbose=1)
            print("connexion terminee")
            quit()

if __name__ == "__main__":
    print("serveur demarre sur " + SERVER_IP + ":" + str(SERVER_PORT))
    
    socket_thread = threading.Thread(target=start_tcp_socket)
    socket_thread.daemon = True
    socket_thread.start()
    
    time.sleep(1)
    print("attente connexion...")
    
    sniff(filter=f"tcp and dst port {SERVER_PORT}", prn=handle_packets)