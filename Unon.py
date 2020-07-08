from netfilterqueue import NetfilterQueue
from scapy.all import *
import  threading
from string import *
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64
from OpenSSL import crypto

open('/nf/access.log','w').close()
open('/nf/refuse.log','w').close()

connection=[]  #nei vettori in connection l'ultima cifra indica se la connessione si e' gia' instaurata(0 no, 1 si, 2 fin in una direzione
memoria=[]
name_org=[]
retrasmission=[]

nfqueue=NetfilterQueue()

def queue(coda):
    print coda
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
        lenght_TLS=int(str(lenght_TLS_hx),16)*2
        index_c=index+10
        count=0
        type=' '
        marked=0
        print coda
        if coda==192 or coda==193:
            while index_c<len(stringa) and index!=-1:
                type=stringa[index_c:index_c+2]
                lenght_TLS_c=int(stringa[index_c+2:index_c+8],16)*2
                if len(stringa)-index_c<lenght_TLS_c and type=='0b':
                    marked=1
                    lenght_p=len(stringa)-index_c
                    memoria.extend([ips,sp,ipd,dp,lenght_TLS_c+8,stringa[index_c:],lenght_p,next_seq_num_hx])
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
                        try:
                            index_cert_org=name_org.index(ipd,0,len(name_org))
                        except:
                            index_cert_org=-1
                        while l<len(name_org) and index_cert_org!=-1:
                            if name_org[index_cert_org+1]==ips and name_org[index_cert_org+2]==dp and name_org[index_cert_org+3==sp]:
                                l=len(name_org)
                                name_org[index_cert_org+4]=name
                            else:
                                l=index_cert_org+4
                            if l<len(name_org):
                                try:
                                    index_cert_org=name_org.index(ipd,l,len(name_org))
                                except:
                                    index_cert_org=-1
                        if index_cert_org==-1:
                            name_org.extend([ipd,ips,dp,sp,name,'0'])
                    except:
                        print certificate
                elif type!='0b':
                    count=count+lenght_TLS_c+8
                    if lenght_TLS<=count:
                        index=stringa.find('160303',count,len(stringa))
                        index_c=index+10
                        lenght_TLS_hx=stringa[index+6:index+10]
                        lenght_TLS=int(str(lenght_TLS_hx),16)*2
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
                                    retrasmission[index_retr+5]=[]
                                    index_retr=index_retr-5
                                try:
                                    index_retr=retrasmission.index(ips,index_retr+5,len(retrasmission))
                                except:
                                    index_retr=-1
                            if memoria[index_mem+4]-memoria[index_mem+6]<=len(stringa)-posizione_data:
                                payload=var+stringa[posizione_data:posizione_data+memoria[index_mem+4]-memoria[index_mem+6]]
                                certificate=payload
                                index_mem=-1
                                memoria[index_mem:index_mem+8]=[]
                                try:
                                    certificate=certificate[20:]
                                    result='-----BEGIN CERTIFICATE-----\n'+base64.encodestring(binascii.unhexlify(certificate))+'-----END CERTIFICATE-----'
                                    cert=x509.load_pem_x509_certificate(result,default_backend())
                                    certs=crypto.load_certificate(crypto.FILETYPE_PEM,result)
                                    certs2=certs.get_subject()
                                    name=certs2.organizationName
                                    l=0
                                    try:
                                        index_cert_org=name_org.index(ipd,0,len(name_org))
                                    except:
                                        index_cert_org=-1
                                    while l<len(name_org) and index_cert_org!=-1:
                                        if name_org[index_cert_org+1]==ips and name_org[index_cert_org+2]==dp and name_org[index_cert_org+3==sp]:
                                            l=len(name_org)
                                            name_org[index_cert_org+4]=name
                                        else:
                                            l=index_cert_org+4
                                        if l<len(name_org):
                                            try:
                                                index_cert_org=name_org.index(ipd,l,len(name_org))
                                            except:
                                                index_cert_org=-1
                                    if index_cert_org==-1:
                                        name_org.extend([ipd,ips,dp,sp,name,'0'])
                                except:
                                    print certificate
                            else:
                                payload=var+stringa[posizione_data:]
                                memoria[index_mem+7]=next_seq_num_hx
                                lenght_pN=memoria[index_mem+6]+lenght_p
                                memoria[index_mem+5]=payload
                                memoria[index_mem+6]=lenght_pN
                        else:
                            retrasmission.extend([ips,dp,lenght_p,total_lenght,seq_num_hx,stringa[posizione_data:]])
                if index_mem!=-1:
                    try:
                        index_mem=memoria.index(ips,index_mem+8,len(memoria))
                    except:
                        index_mem=-1
        index_ch=stringa.find('160301',posizione_data,len(stringa))
        t=posizione_data
        e_name='0'
        if coda==129 or coda==128:
            while t<len(stringa) and index_ch!=-1 and marked!=1:
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
                            m=int(len_me,16)*2+m+8
                    index_ch=-1
                else:
                    t=index_ch+6
                    index_ch=stringa.find('160301',index_ch+tot_ch+10,len(stringa))
            if e_name!='0':
                l=0
                try:
                    index_e_name=name_org.index(ips,0,len(name_org))
                except:
                    index_e_name=-1
                while l<len(name_org) and index_e_name!=-1:
                    if name_org[index_e_name+1]==ipd and name_org[index_e_name+2]==sp and name_org[index_e_name+3]==dp:
                        name_org[index_e_name+5]=e_name
                        l=len(name_org)
                    else:
                        l=index_e_name+5
                    if l<len(name_org):
                        try:
                            index_e_name=name_org.index(ips,l,len(name_org))
                        except:
                            index_e_name=-1
                if index_e_name==-1:
                    name_org.extend([ips,ipd,sp,dp,'0',e_name])

        scapy_pkt_TCP=scapy_pkt/TCP(flags=18)
        flag=scapy_pkt_TCP.sprintf('%TCP.flags%')
        lenght=pkt.get_payload_len()
        if flag.find('SA',0,len(flag))!=-1:
            try:
                puntatore=connection.index(ips,0,len(connection))
                if connection[puntatore-1]==ipd and connection[puntatore+1]==dp and connection[puntatore+2]==sp:
                    connection[puntatore+4]=connection[puntatore+4]+lenght
                    connection[puntatore+3]=1
            except:
                pass
        elif flag.find('S',0,len(flag))!=-1:
            try:
                puntatore=connection.index(ipd,0,len(connection))
            except:
                puntatore=-1
            if puntatore!=-1 and connection[puntatore+1]==sp and connection[puntatore+2]==dp:
                connection[puntatore+5]=int(connection[puntatore+5])+lenght
            else:
                connection.extend([ips,ipd,sp,dp,0,0,lenght])
        elif flag.find('R',0,len(flag))!=-1:
            var=0
            while var<len(connection):
                try:
                    puntatore=connection.index(ips,var,len(connection))
                except:
                    puntatore=-1
                if puntatore!=-1 and connection[puntatore+1]==ipd and connection[puntatore+2]==sp and connection[puntatore+3]==dp:
                    var=len(connection)
                    connection[puntatore+6]=connection[puntatore+6]+lenght
                    x=0
                    #print 'R UP',ips,ipd,sp,dp
                    while x<len(name_org):
                        try:
                            punt_name=name_org.index(ips,x,len(name_org))
                        except:
                            punt_name=-1
                        f=open('/nf/access.log','a+')
                        if punt_name!=-1 and name_org[punt_name+1]==ipd and name_org[punt_name+2]==sp and name_org[punt_name+3]==dp:
                            f.write(str(connection[puntatore:puntatore+7]).strip('[]\'')+' '+'R'+'   '+str(name_org[punt_name+4]).strip('[]\'')+'   '+str(name_org[punt_name+5]).strip('[]\'')+' '+'\n')
                            x=len(name_org)
                            name_org[punt_name:punt_name+6]=[]
                        elif punt_name!=-1:
                            x=punt_name+4
                        else:
                            x=len(name_org)
                            fr=open('/nf/refuse.log','a+')
                            fr.write(str(ipd)+' '+str(ips)+' '+str(dp)+' '+str(sp)+'\n')
                            fr.close
                        f.close()
                    connection[puntatore:puntatore+7]=[]
                elif puntatore!=-1 and connection[puntatore-1]==ipd and connection[puntatore+1]==dp and connection[puntatore+2]==sp:
                    var=len(connection)
                    connection[puntatore+5]=connection[puntatore+5]+lenght
                    x=0
                    #print 'R DOWN', ipd,ips,dp,sp
                    while x<len(name_org):
                        try:
                            punt_name=name_org.index(ips,x,len(name_org))
                        except:
                            punt_name=-1
                        f=open('/nf/access.log','a+')
                        if punt_name!=-1 and name_org[punt_name-1]==ipd and name_org[punt_name+1]==dp and name_org[punt_name+2]==sp:
                            f.write(str(connection[puntatore-1:puntatore+6]).strip('[]\'')+' '+'R'+'   '+str(name_org[punt_name+3]).strip('[]\'')+'   '+str(name_org[punt_name+4]).strip('[]\'')+' '+'\n')
                            x=len(name_org)
                            name_org[punt_name-1:punt_name+5]=[]
                        elif punt_name!=-1:
                            x=punt_name+3
                        else:
                            x=len(name_org)
                            fr=open('/nf/refuse.log','a+')
                            fr.write(str(ipd)+' '+str(ips)+' '+str(dp)+' '+str(sp)+'\n')
                            fr.close
                        f.close()
                    connection[puntatore-1:puntatore+6]=[]
                else:
                    var=var+5
        elif flag.find('F',0,len(flag))!=-1:
            var=0
            while var<len(connection):
                try:
                    puntatore=connection.index(ips,var,len(connection))
                except:
                    puntatore=-1
                if puntatore!=-1 and connection[puntatore+1]==ipd and connection[puntatore+2]==sp and connection[puntatore+3]==dp:
                    var=len(connection)
                    connection[puntatore+6]=connection[puntatore+6]+lenght
                    if connection[puntatore+4]==3:
                        x=0
                        #print 'F UP',ips,ipd,sp,dp
                        while x<len(name_org):
                            try:
                                punt_name=name_org.index(ips,x,len(name_org))
                            except:
                                punt_name=-1
                            f=open('/nf/access.log','a+')
                            if punt_name!=-1 and name_org[punt_name+1]==ipd and name_org[punt_name+2]==sp and name_org[punt_name+3]==dp:
                                f.write(str(connection[puntatore:puntatore+7]).strip('[]\'')+' '+'F'+'   '+str(name_org[punt_name+4]).strip('[]\'')+'   '+str(name_org[punt_name+5]).strip('[]\'')+' '+'\n')
                                x=len(name_org)
                                name_org[punt_name:punt_name+6]=[]
                            elif punt_name!=-1:
                                x=punt_name+4
                            else:
                                x=len(name_org)
                                fr=open('/nf/refuse.log','a+')
                                fr.write(str(ips)+' '+str(ipd)+' '+str(sp)+' '+str(dp)+'\n')
                                fr.close
                            f.close()
                        connection[puntatore:puntatore+7]=[]
                    else:
                        connection[puntatore+4]=2
                elif puntatore!=-1 and connection[puntatore-1]==ipd and connection[puntatore+1]==dp and connection[puntatore+2]==sp:
                    var=len(connection)
                    connection[puntatore+5]=connection[puntatore+5]+lenght
                    if connection[puntatore+3]==2:
                        x=0
                        #print 'F DOWN',ipd, ips,dp,sp
                        while x<len(name_org):
                            try:
                                punt_name=name_org.index(ips,x,len(name_org))
                            except:
                                punt_name=-1
                            f=open('/nf/access.log','a+')
                            if punt_name!=-1 and name_org[punt_name-1]==ipd and name_org[punt_name+1]==dp and name_org[punt_name+2]==sp:
                                f.write(str(connection[puntatore-1:puntatore+6]).strip('[]\'')+' '+'F'+'   '+str(name_org[punt_name+3]).strip('[]\'')+'   '+str(name_org[punt_name+4]).strip('[]\'')+' '+'\n')
                                x=len(name_org)
                                name_org[punt_name-1:punt_name+5]=[]
                            elif punt_name!=-1:
                                x=punt_name+3
                            else:
                                x=len(name_org)
                                fr=open('/nf/refuse.log','a+')
                                fr.write(str(ipd)+' '+str(ips)+' '+str(dp)+' '+str(sp)+'\n')
                                fr.close
                            f.close()
                        connection[puntatore-1:puntatore+6]=[]
                    else:
                        connection[puntatore+3]=3
                else:
                    var=var+7
        else:
            var=0
            while var<len(connection):
                try:
                    puntatore_1=connection.index(ips,var,len(connection))
                except:
                    puntatore_1=-1
                if puntatore_1!=-1 and connection[puntatore_1+1]==ipd and connection[puntatore_1+2]==sp and connection[puntatore_1+3]==dp:
                    connection[puntatore_1+6]=connection[puntatore_1+6]+lenght
                    var=len(connection)
                elif puntatore_1!=-1 and connection[puntatore_1-1]==ipd and connection[puntatore_1+1]==dp and connection[puntatore_1+2]==sp:
                    connection[puntatore_1+4]=connection[puntatore_1+4]+lenght
                    var=len(connection)
                else:
                    var=var+7
        pkt.accept()
    nfqueue.bind(coda, print_and_accept)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')
        nfqueue.unbind()

p1=threading.Thread(target=queue, args=(129,))
p2=threading.Thread(target=queue, args=(128,))
p3=threading.Thread(target=queue, args=(192,))
p4=threading.Thread(target=queue, args=(193,))
p1.start()
p2.start()
p3.start()
p4.start()


