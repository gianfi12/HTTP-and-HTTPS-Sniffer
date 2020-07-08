import fcntl
import threading
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64
import binascii
from OpenSSL import crypto
import socket, struct
from scapy.all import ETH_P_ALL
from scapy.all import select
from scapy.all import MTU
import multiprocessing
import time
start_time=time.time()
vettore=['F','S','R','P','A','U']
open('/home/gian/Desktop/Pass/access.log','w').close()
open('/home/gian/Desktop/Pass/refuse.log','w').close()

def hashing(ips,ipd,payload):
    list=ips.split('.',4)
    x1=list[-1]
    list=ipd.split('.',4)
    x2=list[-1]
    hash=(int(x1)+int(x2))%4
    code1[hash].send([ips,ipd,payload])

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

            pkt, sa_ll = self.ins.recvfrom(2**16)

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


def analize_packet(ips,ipd,key,dp,sp,flag,lenght,d):
    if flag.find('R',0,len(flag))!=-1:
        list=d.get(key)
        if list!=None:
            if list[0]==ips and list[1]==ipd and list[2]==sp and list[3]==dp:
                if list[4]=='0' and list[5]=='0':
                    pass
                else:
                    list[8]=list[8]+lenght
                    while True:
                        try:
                            f=open('/nf/access.log','a+')
                            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except IOError as e:
                            pass
                    f.write(str(list[:9]).strip('[]\'')+' '+str(float(time.time()-start_time-float(list[9])))+' '+'R'+'\n')
                    fcntl.flock(f, fcntl.LOCK_UN)
                    f.close()
                del d[key]
            elif list[0]==ipd and list[1]==ips and list[2]==dp and list[3]==sp:
                if list[4]=='0' and list[5]=='0':
                    pass
                else:
                    list[7]=list[7]+lenght
                    while True:
                        try:
                            f=open('/nf/access.log','a+')
                            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except IOError as e:
                            pass
                    f.write(str(list[:9]).strip('[]\'')+' '+str(float(time.time()-start_time-float(list[9])))+' '+'R'+'\n')
                    fcntl.flock(f, fcntl.LOCK_UN)
                    f.close()
                del d[key]
        else:
            while True:
                try:
                    fr=open('/nf/refuse.log','a+')
                    fcntl.flock(fr, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except IOError as e:
                    pass
            fr.write(str(ipd)+' '+str(ips)+' '+str(dp)+' '+str(sp)+'\n')
            fcntl.flock(fr, fcntl.LOCK_UN)
            fr.close

    elif flag.find('F',0,len(flag))!=-1:
        list=d.get(key)
        if list!=None:
            if list[0]==ips and list[1]==ipd and list[2]==sp and list[3]==dp:
                if list[4]=='0' and list[5]=='0':
                    del d[key]
                else:
                    list[8]=list[8]+lenght
                    if list[6]==3:
                        while True:
                            try:
                                f=open('/nf/access.log','a+')
                                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                break
                            except IOError as e:
                                pass
                        f.write(str(list[:9]).strip('[]\'')+' '+str(float(time.time()-start_time-float(list[9])))+' '+'F'+'\n')
                        fcntl.flock(f, fcntl.LOCK_UN)
                        f.close()
                        del d[key]
                    else:
                        list[6]=2
            elif list[0]==ipd and list[1]==ips and list[2]==dp and list[3]==sp:
                if list[4]=='0' and list[5]=='0':
                    del d[key]
                else:
                    list[7]=list[7]+lenght
                    if list[6]==2:
                        while True:
                            try:
                                f=open('/nf/access.log','a+')
                                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                break
                            except IOError as e:
                                pass
                        f.write(str(list[:9]).strip('[]\'')+' '+str(float(time.time()-start_time-float(list[9])))+' '+'F'+'\n')
                        fcntl.flock(f, fcntl.LOCK_UN)
                        f.close()
                        del d[key]
                    else:
                        list[6]=3
        else:
            while True:
                try:
                    fr=open('/nf/refuse.log','a+')
                    fcntl.flock(fr, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except IOError as e:
                    pass
            fr.write(str(ipd)+' '+str(ips)+' '+str(dp)+' '+str(sp)+'\n')
            fcntl.flock(fr, fcntl.LOCK_UN)
            fr.close()

    elif flag.find('SA',0,len(flag))!=-1:
        list=d.get(key)
        if list!=None:
            list[6]=1
            list[7]=list[7]+lenght
            d[key]=list
        else:
            print 'Error search SA'

    elif flag.find('S',0,len(flag))!=-1:
        list=d.get(key,None)
        if list==None:
            d[key]=[ips,ipd,sp,dp,'0','0',0,0,lenght,time.time()-start_time]
        else:
            list[8]=list[8]+lenght
            d[key]=list

    else:
        list=d.get(key,None)
        if list!=None:
            if list[0]==ips and list[1]==ipd and list[2]==sp and list[3]==dp:
                list[8]=list[8]+lenght
                d[key]=list
            else:
                list[7]=list[7]+lenght
                d[key]=list


ec_p1,ec_g1=multiprocessing.Pipe()
ec_p2,ec_g2=multiprocessing.Pipe()
ec_p3,ec_g3=multiprocessing.Pipe()
ec_p4,ec_g4=multiprocessing.Pipe()
ec_p5,ec_g5=multiprocessing.Pipe()
ec_p6,ec_g6=multiprocessing.Pipe()
ec_p7,ec_g7=multiprocessing.Pipe()
ec_p8,ec_g8=multiprocessing.Pipe()
code1=[ec_p1,ec_p2,ec_p3,ec_p4,ec_p5,ec_p6,ec_p7,ec_p8]
code2=[ec_g1,ec_g2,ec_g3,ec_g4,ec_g5,ec_g6,ec_g7,ec_g8]



def elaborate(x):
    #threading.Thread(target=pulizia_memoria)
    memoria=[]
    retrasmission=[]
    d={}
    ds={}
    while True:
        pkt=code2[x].recv()
        ips=pkt[0]
        ipd=pkt[1]
        payload=pkt[2]
        ip_lenght_hx=str(payload[0]).encode("HEX")
        ip_lenght=int(ip_lenght_hx[1],16)*8
        proto=str(payload[9:10]).encode("HEX")
        lenght_T=len(payload)
        p=str(payload[ip_lenght/2+13:ip_lenght/2+14]).encode("HEX")
        if proto=='06':
            sp=int(str(payload[ip_lenght/2:ip_lenght/2+2]).encode("HEX"),16)
            dp=int(str(payload[ip_lenght/2+2:ip_lenght/2+4]).encode("HEX"),16)
            if sp==443 or dp==443:
                list=ips.split('.',4)
                x1=list[-1]
                list=ipd.split('.',4)
                x2=list[-1]
                key=int(x1)+int(x2)+sp+dp
                list=d.get(key,None)
                if list!=None:
                    if list[4]=='0' and sp==443:
                        stringa=str(payload).encode("HEX")
                        hx=hex(int(str(sp))).lstrip("0x")
                        inizio=stringa.index(str(hx),0,len(stringa))
                        posizione=inizio+len(str(hx))+20
                        lenght_TCP_hx=stringa[posizione]
                        lenght=int(str(lenght_TCP_hx),16)*4
                        posizione_data=lenght*2+inizio-1
                        lenght_p=len(stringa)-posizione_data
                        lenght_TLS=0
                        total_lenght=len(stringa)-posizione_data
                        seq_num_hx=stringa[inizio+7:inizio+15]
                        seq_num=int(seq_num_hx,16)
                        next_seq_num=int(seq_num+total_lenght/2)
                        next_seq_num_hx=hex(next_seq_num).lstrip("0x").zfill(8)
                        next_seq_num_hx=next_seq_num_hx[:8]
                        type=0
                        index=stringa.find('160303',posizione_data,len(stringa))
                        lenght_TLS_hx=stringa[index+6:index+10]
                        try :
                            lenght_TLS=int(str(lenght_TLS_hx),16)*2
                        except:
                            index=-1
                        index_c=index+10
                        count=0
                        type=' '
                        marked=0
                        while index_c<len(stringa) and index!=-1:
                            type=stringa[index_c:index_c+2]
                            try:
                                lenght_TLS_c=int(stringa[index_c+2:index_c+8],16)*2
                            except:
                                break
                            if len(stringa)-index_c<lenght_TLS_c and type=='0b':
                                marked=1
                                lenght_p=len(stringa)-index_c
                                time_t=time.time()-start_time
                                memoria.extend([ips,sp,ipd,dp,lenght_TLS_c+8,stringa[index_c:],lenght_p,next_seq_num_hx,time_t])
                                index_c=len(stringa)
                            elif type=='0b':
                                certificate=stringa[index_c:index_c+8+lenght_TLS_c]
                                index_c=len(stringa)
                                try:
                                    certificate=certificate[20:]
                                    result='-----BEGIN CERTIFICATE-----\n'+base64.encodestring(binascii.unhexlify(certificate))+'-----END CERTIFICATE-----'
                                    cert=x509.load_pem_x509_certificate(result,default_backend())
                                    certs=crypto.load_certificate(crypto.FILETYPE_PEM,result)
                                    certs2=certs.get_subject()
                                    name=certs2.organizationName
                                    l=0
                                    list[4]=name
                                    d[key]=list
                                except:
                                    print certificate
                            elif type!='0b':
                                count=count+lenght_TLS_c+8
                                if lenght_TLS<=count:
                                    index=stringa.find('160303',count,len(stringa))
                                    index_c=index+10
                                    lenght_TLS_hx=stringa[index+6:index+10]
                                    try:
                                        lenght_TLS=int(str(lenght_TLS_hx),16)*2
                                    except:
                                        index_c=len(stringa)
                                else:
                                    index_c=index_c+8+lenght_TLS_c
                        try:
                            index_mem=memoria.index(ips,0,len(memoria))
                        except:
                            index_mem=-1
                        while index_mem!=-1:
                            if index_mem!=-1 and memoria[index_mem+1]==sp and memoria[index_mem+2]==ipd and memoria[index_mem+3]==dp:
                                var=memoria[index_mem+5]
                                if type!='0b':
                                    marked=1
                                    if str(seq_num_hx)==str(memoria[index_mem+7]):
                                        try:
                                            index_retr=retrasmission.index(ips,0,len(retrasmission))
                                        except:
                                            index_retr=-1
                                        while index_retr!=-1:
                                            if retrasmission[index_retr+1]==dp and retrasmission[index_retr+4]==next_seq_num_hx:
                                                stringa=stringa+retrasmission[index_retr+5]
                                                lenght_p=lenght_p+retrasmission[index_retr+2]
                                                next_seq_num_hx=next_seq_num_hx+hex(int(retrasmission[index_retr+3]/2))
                                                retrasmission[index_retr+6]=[]
                                                index_retr=index_retr-5
                                            try:
                                                index_retr=retrasmission.index(ips,index_retr+5,len(retrasmission))
                                            except:
                                                index_retr=-1
                                        if memoria[index_mem+4]-memoria[index_mem+6]<=len(stringa)-posizione_data:
                                            payload=var+stringa[posizione_data:posizione_data+memoria[index_mem+4]-memoria[index_mem+6]]
                                            certificate=payload
                                            index_mem=-1
                                            try:
                                                certificate=certificate[20:]
                                                result='-----BEGIN CERTIFICATE-----\n'+base64.encodestring(binascii.unhexlify(certificate))+'-----END CERTIFICATE-----'
                                                cert=x509.load_pem_x509_certificate(result,default_backend())
                                                certs=crypto.load_certificate(crypto.FILETYPE_PEM,result)
                                                certs2=certs.get_subject()
                                                name=certs2.organizationName
                                                l=0
                                                list[4]=name
                                                d[key]=list
                                            except:
                                                print certificate
                                        else:
                                            payload=var+stringa[posizione_data:]
                                            memoria[index_mem+7]=next_seq_num_hx
                                            lenght_pN=memoria[index_mem+6]+lenght_p
                                            memoria[index_mem+5]=payload
                                            memoria[index_mem+6]=lenght_pN
                                            memoria[index_mem+8]=time.time()-start_time
                                    else:
                                        retrasmission.extend([ips,dp,lenght_p,total_lenght,seq_num_hx,stringa[posizione_data:],(time.time()-start_time)])
                            if index_mem!=-1:
                                try:
                                    index_mem=memoria.index(ips,index_mem+8,len(memoria))
                                except:
                                    index_mem=-1
                    if list[5]=='0' and dp==443:
                        stringa=str(payload).encode("HEX")
                        hx=hex(int(str(sp))).lstrip("0x")
                        inizio=stringa.index(str(hx),0,len(stringa))
                        posizione=inizio+len(str(hx))+20
                        lenght_TCP_hx=stringa[posizione]
                        lenght=int(str(lenght_TCP_hx),16)*4
                        posizione_data=lenght*2+inizio-1
                        lenght_p=len(stringa)-posizione_data
                        lenght_TLS=0
                        total_lenght=len(stringa)-posizione_data
                        index_ch=stringa.find('160301',posizione_data,len(stringa))
                        t=posizione_data
                        e_name='0'
                        while t<len(stringa) and index_ch!=-1:
                            tot_ch=int(stringa[index_ch+6:index_ch+10],16)
                            if stringa[index_ch+10:index_ch+12]=='01' and stringa[index_ch+18:index_ch+22]=='0303':
                                t=len(stringa)
                                len_sid=int(stringa[index_ch+86:index_ch+88],16)*2
                                len_cs=int(stringa[index_ch+len_sid+88:index_ch+len_sid+92],16)*2
                                len_cm=int(stringa[index_ch+len_sid+len_cs+92:index_ch+len_sid+len_cs+94],16)*2
                                accu=index_ch+len_sid+len_cs+94+len_cm
                                types=stringa[accu+4:accu+8]
                                if types=='0015':
                                    padd=int(stringa[accu+8:accu+12],16)
                                else:
                                    padd=0
                                if padd==0:
                                    m=0
                                else:
                                    m=8
                                while m<len(stringa):
                                    type=stringa[accu+4+padd*2+m:accu+8+padd*2+m]
                                    len_me=stringa[accu+8+padd*2+m:accu+12+padd*2+m]
                                    if type=='0000':
                                        len_server_name=int(stringa[accu+18+padd*2+m:accu+padd*2+m+22],16)
                                        e_name=binascii.unhexlify(stringa[accu+22+padd*2+m:accu+22+padd*2+len_server_name*2+m])
                                        m=len(stringa)
                                    else:
                                        try:
                                            m=int(str(len_me),16)*2+m+8
                                        except:
                                            print len_me
                                            break
                                index_ch=-1
                            else:
                                t=index_ch+6
                                index_ch=stringa.find('160301',index_ch+tot_ch+10,len(stringa))
                        if e_name!='0':
                            list[5]=e_name
                            d[key]=list
                flag=obtain_flag(p)
                analize_packet(ips,ipd,key,dp,sp,flag,lenght_T,d)
            if dp==80 or sp==80:
                list=ips.split('.',4)
                x1=list[-1]
                list=ipd.split('.',4)
                x2=list[-1]
                key=int(x1)+int(x2)+sp+dp
                list=ds.get(key,None)
                list=ds.get(key)
                if list!=None:
                    if dp==80 and list[4]=='0':
                        stringa=str(payload).encode("HEX")
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
                            list[4]=host
                            d[key]=list
                flag=obtain_flag(p)
                analize_packet(ips,ipd,key,dp,sp,flag,lenght_T,ds)






e1=multiprocessing.Process(target=elaborate,args=(0,))
e2=multiprocessing.Process(target=elaborate,args=(1,))
e3=multiprocessing.Process(target=elaborate,args=(2,))
e4=multiprocessing.Process(target=elaborate,args=(3,))
e5=multiprocessing.Process(target=elaborate,args=(4,))
e6=multiprocessing.Process(target=elaborate,args=(5,))
e7=multiprocessing.Process(target=elaborate,args=(6,))
e8=multiprocessing.Process(target=elaborate,args=(7,))
e1.start()
print e1.is_alive()
e2.start()
print e2.is_alive()
e3.start()
print e3.is_alive()
e4.start()
print e4.is_alive()
e5.start()
print e5.is_alive()
e6.start()
print e6.is_alive()
e7.start()
print e7.is_alive()
e8.start()
print e8.is_alive()


def sniff_packet(src, dst, frame,payload):
    ips=socket.inet_ntoa(src)
    ipd=socket.inet_ntoa(dst)
    hashing(ips,ipd,payload)


ip_sniff = IPSniff('wlp2s0', sniff_packet, sniff_packet).recv()
ip_sniff.recv()
