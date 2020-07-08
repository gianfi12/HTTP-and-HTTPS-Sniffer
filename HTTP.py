import socket, struct
from scapy.all import ETH_P_ALL
from scapy.all import select
from scapy.all import MTU
import multiprocessing
import time
import fcntl
start_time=time.time()
vettore=['F','S','R','P','A','U']

def obtain_flag(p):
    try:
        binary=str(bin(int(str(p),16)))
        V=0
        flag=''
        for j in reversed(binary):
            if j=='1':
                flag=flag+vettore[V]
            V=V+1
        return flag
    except:
        return '0'

class IPSniff:

    def __init__(self, interface_name, on_ip_incoming, on_ip_outgoing):

        self.interface_name = interface_name
        self.on_ip_incoming = on_ip_incoming
        self.on_ip_outgoing = on_ip_outgoing

        # The raw in (listen) socket is a L2 raw socket that listens
        # for all packets going through a specific interface.
        self.ins = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.ins.bind((self.interface_name, ETH_P_ALL))

    def __process_ipframe(self, pkt_type, ip_header, payload):

        # Extract the 20 bytes IP header, ignoring the IP options
        fields = struct.unpack("!BBHHHBBHII", ip_header)

        dummy_hdrlen = fields[0] & 0xf
        iplen = fields[2]

        ip_src = payload[12:16]
        ip_dst = payload[16:20]
        ip_frame = payload[0:14]

        if pkt_type == socket.PACKET_OUTGOING:
            if self.on_ip_outgoing is not None:
                self.on_ip_outgoing(ip_src, ip_dst, ip_frame,payload)

        else:
            if self.on_ip_incoming is not None:
                self.on_ip_incoming(ip_src, ip_dst, ip_frame,payload)

    def recv(self):
        while True:

            pkt, sa_ll = self.ins.recvfrom(MTU)

            if type == socket.PACKET_OUTGOING and self.on_ip_outgoing is None:
                continue
            elif self.on_ip_outgoing is None:
                continue

            if len(pkt) <= 0:
                break

            eth_header = struct.unpack("!6s6sH", pkt[0:14])

            dummy_eth_protocol = socket.ntohs(eth_header[2])

            if eth_header[2] != 0x800 :
                continue

            ip_header = pkt[14:34]
            payload = pkt[14:]
            self.__process_ipframe(sa_ll[2], ip_header,payload)

def analize_packet(ips,ipd,sp,dp,lenght,flag,http_connection):
    if flag.find('R',0,len(flag))!=-1:
        var=0
        puntatore=0
        while var<len(http_connection) and puntatore!=-1:
            try:
                puntatore=http_connection.index(ips,var,len(http_connection))
            except:
                puntatore=-1
            if puntatore!=-1 and http_connection[puntatore+1]==ipd and http_connection[puntatore+2]==sp and http_connection[puntatore+3]==dp:
                var=len(http_connection)
                http_connection[puntatore+6]=http_connection[puntatore+6]+lenght
                p=float(time.time()-start_time)-float(http_connection[puntatore+8])
                print str(http_connection[puntatore:puntatore+7]).strip('[]\''),p,'R',flag
                http_connection[puntatore:puntatore+10]=[]
            elif puntatore!=-1 and http_connection[puntatore-1]==ipd and http_connection[puntatore+1]==dp and http_connection[puntatore+2]==sp:
                var=len(http_connection)
                http_connection[puntatore+5]=http_connection[puntatore+5]+lenght
                p=float(time.time()-start_time)-float(http_connection[puntatore+7])
                print str(http_connection[puntatore-1:puntatore+7]).strip('[]\''),p,'R',flag
                http_connection[puntatore-1:puntatore+9]=[]
            elif  puntatore!=-1:
                var=var+8
            else:
                var=len(http_connection)
        if var==0 or puntatore==-1:
            print ips,ipd,sp,dp
    elif flag.find('F',0,len(flag))!=-1:
        var=0
        puntatore=0
        while var<len(http_connection) and puntatore!=-1:
            try:
                puntatore=http_connection.index(ips,var,len(http_connection))
            except:
                puntatore=-1
            if puntatore!=-1 and http_connection[puntatore+1]==ipd and http_connection[puntatore+2]==sp and http_connection[puntatore+3]==dp:
                var=len(http_connection)
                if http_connection[puntatore+4]==3:
                    http_connection[puntatore+5]=http_connection[puntatore+5]+lenght+66
                    p=float(time.time()-start_time)-float(http_connection[puntatore+8])
                    print str(http_connection[puntatore:puntatore+8]).strip('[]\''),p,'F',flag
                    http_connection[puntatore:puntatore+10]=[]
                else:
                    http_connection[puntatore+4]=2
            elif puntatore!=-1 and http_connection[puntatore-1]==ipd and http_connection[puntatore+1]==dp and http_connection[puntatore+2]==sp:
                var=len(http_connection)
                if http_connection[puntatore+3]==2:
                    http_connection[puntatore+4]=http_connection[puntatore+4]+lenght+66
                    p=float(time.time()-start_time)-float(http_connection[puntatore+7])
                    print str(http_connection[puntatore-1:puntatore+7]).strip('[]\''),p,'F',flag
                    http_connection[puntatore-1:puntatore+9]=[]
                else:
                    http_connection[puntatore+3]=3
            elif puntatore!=-1:
                var=var+8
            else:
                var=len(http_connection)
        if var==0 or puntatore==-1:
            print ips,ipd,sp,dp
    elif flag.find('SA',0,len(flag))!=-1:
        k=0
        puntatore=0
        while k<len(http_connection) and puntatore!=-1:
            try:
                puntatore=http_connection.index(ips,k,len(http_connection))
            except:
                puntatore=-1
            if http_connection[puntatore-1]==ipd and http_connection[puntatore+1]==dp and http_connection[puntatore+2]==sp:
                http_connection[puntatore+4]=http_connection[puntatore+4]+lenght
                http_connection[puntatore+3]=1
                http_connection[puntatore+8]=time.time()-start_time
                k=len(http_connection)
            else:
                k=k+8
    elif flag.find('S',0,len(flag))!=-1:
        k=0
        puntatore=0
        while k<len(http_connection) and puntatore!=-1:
            try:
                puntatore=http_connection.index(ipd,k,len(http_connection))
            except:
                puntatore=-1
            if puntatore!=-1 and http_connection[puntatore-1]==ips and http_connection[puntatore+1]==sp and http_connection[puntatore+2]==dp:
                http_connection[puntatore+5]=int(http_connection[puntatore+5])+lenght
                k=len(http_connection)
            else:
                k=k+8
        if k==len(http_connection) or puntatore==-1:
            http_connection.extend([ips,ipd,sp,dp,0,0,lenght,'0',time.time()-start_time,time.time()-start_time])
    else:
        var=0
        while var<len(http_connection):
            try:
                puntatore_1=http_connection.index(ips,var,len(http_connection))
            except:
                puntatore_1=-1
            if puntatore_1!=-1 and http_connection[puntatore_1+1]==ipd and http_connection[puntatore_1+2]==sp and http_connection[puntatore_1+3]==dp:
                http_connection[puntatore_1+6]=http_connection[puntatore_1+6]+lenght
                http_connection[puntatore_1+9]=str(time.time()-start_time)
                var=len(http_connection)
            elif puntatore_1!=-1 and http_connection[puntatore_1-1]==ipd and http_connection[puntatore_1+1]==dp and http_connection[puntatore_1+2]==sp:
                http_connection[puntatore_1+4]=http_connection[puntatore_1+4]+lenght
                http_connection[puntatore_1+8]=str(time.time()-start_time)
                var=len(http_connection)
            else:
                var=var+8


e_1,e_2=multiprocessing.Pipe()
def elaborate():
    http_connection=[]
    while True:
        pkt=e_2.recv()
        ips=pkt[0]
        ipd=pkt[1]
        payload=pkt[2]
        data=str(payload).encode("HEX")
        proto=str(data[18:20])
        stringa=data
        lenght=int(str(data[1]),16)*4*2
        sp=int(data[lenght:lenght+4],16)
        dp=int(data[lenght+4:lenght+8],16)
        p=data[lenght+26:lenght+28]
        lenght_T=len(data)/2
        p=data[lenght+26:lenght+28]
        if proto=='06':
            if dp==80:
                hx=hex(int(str(sp))).lstrip("0x")
                inizio=stringa.index(str(hx),0,len(stringa))
                posizione=inizio+len(str(hx))+20
                lenght_TCP_hx=stringa[posizione]
                lenght=int(str(lenght_TCP_hx),16)*4
                posizione_data=lenght*2+inizio
                host='-1'
                if stringa[posizione_data:posizione_data+6]=='474554':
                    try:
                        start=stringa.index('486f73743a',posizione_data,len(stringa))
                        end=stringa.index('0d0a436f',start,len(stringa))
                        host=str(stringa[start+12:end]).decode("HEX")
                    except:
                        pass
                if host!='-1':
                    x=0
                    try:
                        puntatore=http_connection.index(ips,0,len(http_connection))
                    except:
                        puntatore=-1
                    while x<len(http_connection) and puntatore!=-1:
                        if http_connection[puntatore+1]==ipd and http_connection[puntatore+2]==sp and http_connection[puntatore+3]==dp:
                            x=len(http_connection)
                            http_connection[puntatore+6]=http_connection[puntatore+6]+lenght_T
                            http_connection[puntatore+7]=host
                            http_connection[puntatore+9]=time.time()-start_time
                        else:
                            x=x+8
                            try:
                                puntatore=http_connection.index(ips,x,len(http_connection))
                            except:
                                puntatore=-1
            if dp==80 or sp==80:
                flag=obtain_flag(p)
                analize_packet(ips,ipd,sp,dp,lenght_T,flag,http_connection)

e=multiprocessing.Process(target=elaborate)
e.start()
print e.is_alive()

def sniff_packet(src, dst, frame,payload):
    ips=socket.inet_ntoa(src)
    ipd=socket.inet_ntoa(dst)
    e_1.send([ips,ipd,payload])


ip_sniff = IPSniff('br0', sniff_packet,sniff_packet).recv()
ip_sniff.recv()
