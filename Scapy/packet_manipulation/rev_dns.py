from scapy.all import *

dns_reverse = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1,qd=DNSQR(qname="noahheraud.com", qtype="PTR"))

send(dns_reverse)

response = sniff(filter="udp port 53", count=1)

print(response[0].show())

