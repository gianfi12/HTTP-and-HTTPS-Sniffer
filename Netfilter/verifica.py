from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.utils import *
def print_and_accept(pkt):
    #print pkt
    data=IP(pkt.get_payload())
    print data[IP]
    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(99,print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print
