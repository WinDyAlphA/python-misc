from scapy.all import *
from scapy.all import IPOption
import threading


pkt = IP(dst="8.8.8.8") / TCP(dport=80, flags="S")

def task():
    for i in range(100):
        send(pkt)

thread1 = threading.Thread(target=task)
thread2 = threading.Thread(target=task)
thread3 = threading.Thread(target=task)

thread1.start()
thread2.start()
thread3.start()

thread1.join()
thread2.join()
thread3.join()

print("Finished")
