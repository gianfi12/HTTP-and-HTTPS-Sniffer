from scapy.all import *
from netfilterqueue import NetfilterQueue
import random

def randomMAC():
    x="52:54:00:%02x:%02x:%02x" % (random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),)
    return x

def print_and_accept(pkt):
    print pkt
    scapy_pkt=IP(pkt.get_payload())
    new_ip_dst=IP(pkt.get_payload())
    #pkt[Ether].src=randomMAC()
    new_ip_src='192.168.1.'+str(random.randint(30,100))
    print scapy_pkt.src
    print pkt
    #pkt.set_payload(str(scapy_pkt))
    #print IP(pkt.get_payload()).src
    print
    send(IP(src=new_ip_src,dst))
    pkt.drop()

nfqueue = NetfilterQueue()
nfqueue.bind(0, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()
