import pcapy,socket

pcapy.findalldevs()

max_bytes = 2**30
promiscuous = False
read_timeout = 0
pc = pcapy.open_live("wlp2s0", max_bytes, promiscuous, 0)

pc.setfilter('tcp')
x=0
def sniff_packet(hdr,data):
    global x
    payload=data[14:]
    ips=socket.inet_ntoa(payload[12:16])
    ipd=socket.inet_ntoa(payload[16:20])
    #print
    #print payload.encode("HEX")
    #print
    x+=len(payload)
try:
    x=x+pc.loop(-1, sniff_packet)
except KeyboardInterrupt:
    print
    print x
    print
