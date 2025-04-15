#!/usr/bin/env python3
from scapy.all import *
import time

# IP et ports
SERVER_IP = '143.110.170.33'
CLIENT_IP = get_if_addr(conf.iface)
SERVER_PORT = 8010
CLIENT_PORT = 8011

conf.verb = 1

def main():
    # envoi du syn
    syn = IP(dst=SERVER_IP) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags='S', seq=1000)
    print("envoi syn...")
    send(syn, verbose=1)
    
    time.sleep(1)
    
    # reception syn-ack
    print("attente reponse...")
    resp = sr1(syn, timeout=2, verbose=1)
    
    if resp and resp.haslayer(TCP) and resp[TCP].flags == 'SA':
        print("ok syn-ack recu")
        
        # envoi ack
        ack = IP(dst=SERVER_IP) / TCP(sport=CLIENT_PORT, 
                                    dport=SERVER_PORT,
                                    flags='A',
                                    seq=resp[TCP].ack,
                                    ack=resp[TCP].seq + 1)
        send(ack, verbose=1)
        
        # envoi data
        data = IP(dst=SERVER_IP) / TCP(sport=CLIENT_PORT,
                                     dport=SERVER_PORT, 
                                     flags='PA',
                                     seq=resp[TCP].ack,
                                     ack=resp[TCP].seq + 1) / Raw(load="Hello server!")
        send(data, verbose=1)
        
        # fin connexion
        fin = IP(dst=SERVER_IP) / TCP(sport=CLIENT_PORT,
                                    dport=SERVER_PORT,
                                    flags='FA', 
                                    seq=resp[TCP].ack + len("Hello server!"),
                                    ack=resp[TCP].seq + 1)
        send(fin, verbose=1)
        
    else:
        print("erreur: pas de reponse")
    
if __name__ == "__main__":
    main()