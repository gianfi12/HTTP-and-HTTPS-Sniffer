from netfilterqueue import NetfilterQueue
import binascii
from scapy.all import *
from string import *
memoria=[]

def print_and_accept(pkt):
    scapy_pkt=IP(pkt.get_payload())
    ips=scapy_pkt.src
    ipd=scapy_pkt.dst
    sp=scapy_pkt.sport
    dp=scapy_pkt.dport
    stringa=binascii.hexlify(pkt.get_payload())
    hx=hex(int(str(sp))).lstrip("0x")
    inizio=stringa.index(str(hx),0,len(stringa))
    posizione=inizio+len(str(hx))+20
    lenght_TCP_hx=stringa[posizione]
    lenght=int(str(lenght_TCP_hx),16)*4
    posizione_data=lenght*2+inizio-1
    index=stringa.find('160303',posizione_data,len(stringa))
    count=index
    lenght_p=len(stringa)-posizione_data
    lenght_TLS=0
    type=0
    while count<len(stringa) and count!=-1:
        lenght_TLS_hx=stringa[count+6:count+10]
        lenght_TLS=int(str(lenght_TLS_hx),16)*2
        type=stringa[count+10:count+12]
        index_certificate=count+10
        type=stringa[count+10:count+12]
        lenght_TLS_c=int(stringa[count+12:count+18],16)*2
        if len(stringa)-index_certificate<lenght_TLS_c and type=='0b':
            lenght_p=len(stringa)-index_certificate
            memoria.extend([ips,sp,ipd,dp,lenght_TLS_c+8,stringa[index_certificate:],lenght_p])
            count=len(stringa)
        elif type=='0b':
            count=len(stringa)
        elif type!='0b':
            count=index_certificate+8+lenght_TLS_c
            if lenght_TLS<=count:
                index=stringa.find('160303',count,len(stringa))
    try:
        index_mem=memoria.index(ips)
    except:
        index_mem=-1
    if index_mem!=-1 and memoria[index_mem+1]==sp and memoria[index_mem+2]==ipd and memoria[index_mem+3]==dp:
        var=memoria[index_mem+5]
        if type!='0b':
            if memoria[index_mem+4]-memoria[index_mem+6]<=len(stringa)-posizione_data:
                payload=var+stringa[posizione_data:posizione_data+memoria[index_mem+4]-memoria[index_mem+6]]
                print payload
                memoria[index_mem:index_mem+7]=[]
            else:
                payload=var+stringa[posizione_data:]
                lenght_pN=memoria[index_mem+6]+lenght_p
                memoria[index_mem+5]=payload
                memoria[index_mem+6]=lenght_pN

    #print pkt
    #print scapy_pkt.summary()
    #print stringa
    #print
    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(99,print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print
