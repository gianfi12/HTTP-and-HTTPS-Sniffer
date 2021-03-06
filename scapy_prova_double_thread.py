from scapy.all import *
import threading
import psutil
import time
from string import *
import binascii
import linecache
import psutil
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64
from OpenSSL import crypto
import sys
import os
from Queue import *
start_time=time.time()
ipv4 = os.popen('ip addr show enp3s0 | grep "\<inet\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()

open('/nf/access.log','w').close()
open('/nf/refuse.log','w').close()

vettore=['F','S','R','P','A','U']

def PrintException():
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)

def obtain_flag(p):
    binary=str(bin(int(p)))
    V=0
    flag=''
    for j in reversed(binary):
        if j=='1':
            flag=flag+vettore[V]
        V=V+1
    return flag


def pulizia_memoria():
    while True:

        j=0
        try:
            tempo=memoria[8]
        except:
            tempo=-1
        while int(float(tempo))+20<(time.time()-start_time) and tempo!=-1:
            #print memoria[j*9:j*9+4],memoria[j*9+6:j*9+9]
            memoria[j*9:j*9+9]=[]
            j=j+1
            try:
                tempo=memoria[8+j*9]
            except:
                tempo=-1
        j=0
        try:
            tempo1=connection[7]
        except:
            tempo1=-1
        while int(float(tempo1))+27<(time.time()-start_time) and tempo1!=-1:
            x=0
            while x<len(name_org):
                try:
                    punt_namex=name_org.index(connection[j*8],x,len(name_org))
                except:
                    punt_namex=-1
                f=open('/nf/access.log','a+')
                control=0
                try:
                    if punt_namex!=-1 and name_org[punt_namex+1]==connection[j*8+1] and name_org[punt_namex+2]==connection[j*8+2] and name_org[punt_namex+3]==connection[j*8+3]:
                        f.write(str(connection[j*8:j*8+7]).strip('[]\'')+' '+'NF'+'   '+str(name_org[punt_namex+4]).strip('[]\'')+'   '+str(name_org[punt_namex+5]).strip('[]\'')+' '+'\n')
                        x=len(name_org)
                        #name_org[punt_namex:punt_namex+7]=[]
                    elif punt_namex!=-1 and name_org[punt_namex-1]==connection[j*8+1] and name_org[punt_namex+1]==connection[j*8+2] and name_org[punt_namex+2]==connection[j*8+3]:
                        f.write(str(connection[j*8:j*8+7]).strip('[]\'')+' '+'NF'+'   '+str(name_org[punt_namex+3]).strip('[]\'')+'   '+str(name_org[punt_namex+4]).strip('[]\'')+' '+'\n')
                        x=len(name_org)
                        #name_org[punt_name-1:punt_name+6]=[]
                    else:
                        control=-1
                except:
                    control=-1
                if punt_namex!=-1 and control==-1:
                    x=punt_namex+5
                else:
                    x=len(name_org)
                    fr=open('/nf/refuse.log','a+')
                    fr.write(str(connection[j*8])+' '+str(connection[j*8+1])+' '+str(connection[j*8+2])+' '+str(connection[j*8+3])+'\n')
                    fr.close
                f.close()
            connection[j*8:j*8+8]=[]
            j=j+1
            try:
                tempo1=connection[j*8+7]
            except:
                tempo1=-1

        j=0
        try:
            tempo2=name_org[7]
        except:
            tempo2=-1
        while int(float(tempo2))+10<(time.time()-start_time) and tempo2!=-1:
            name_org[j*8:j*8+8]=[]
            j=j+1
            try:
                tempo2=name_org[j*8+7]
            except:
                tempo2=-1

        j=0
        try:
            tempo3=retrasmission[6]
        except:
            tempo3=-1
        try:
            while int(float(tempo3))+30<(time.time()-start_time) and tempo3!=-1:
                j=j+1
                retrasmission[j*7:j*7+7]=[]
                try:
                    tempo3=restrasmission[j*7+6]
                except:
                    tempo3=-1
        except:
            print 'Error tempo3'

        time.sleep(5)



def control():
    while True:
        print psutil.cpu_percent(interval=1), psutil.phymem_usage().percent,(time.time()-start_time)
        print name_org
        print
        time.sleep(20)

d=Queue()
u=Queue()

def download():
    while True:
        pkt=d.get()
        ips=pkt[IP].src
        ipd=pkt[IP].dst
        sp=pkt[TCP].sport
        dp=pkt[TCP].dport
        stringa=bytes(TCP()).encode("HEX")+str(pkt).encode("HEX")
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
        while index_c<len(stringa) and index!=-1:
            type=stringa[index_c:index_c+2]
            lenght_TLS_c=int(stringa[index_c+2:index_c+8],16)*2
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
                    l=0
                    try:
                        index_cert_org=name_org.index(ipd,0,len(name_org))
                    except:
                        index_cert_org=-1
                    while l<len(name_org) and index_cert_org!=-1:
                        if name_org[index_cert_org+1]==ips and name_org[index_cert_org+2]==dp and name_org[index_cert_org+3==sp]:
                            l=len(name_org)
                            name_org[index_cert_org+4]=name
                            name_org[index_cert_org+6]=time.time()-start_time
                        else:
                            l=index_cert_org+7
                        if l<len(name_org):
                            try:
                                index_cert_org=name_org.index(ipd,l,len(name_org))
                            except:
                                index_cert_org=-1
                    if index_cert_org==-1:
                        name_org.extend([ipd,ips,dp,sp,name,'0',(time.time()-start_time)])
                except:
                    print
                    print 'Error Certificate'
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
                                try:
                                    index_cert_org=name_org.index(ipd,0,len(name_org))
                                except:
                                    index_cert_org=-1
                                while l<len(name_org) and index_cert_org!=-1:
                                    if name_org[index_cert_org+1]==ips and name_org[index_cert_org+2]==dp and name_org[index_cert_org+3==sp]:
                                        l=len(name_org)
                                        name_org[index_cert_org+4]=name
                                        #name_org[index_cert_org+6]=time.time()-start_time
                                    else:
                                        l=index_cert_org+4
                                    if l<len(name_org):
                                        try:
                                            index_cert_org=name_org.index(ipd,l,len(name_org))
                                        except:
                                            index_cert_org=-1
                                if index_cert_org==-1:
                                    name_org.extend([ipd,ips,dp,sp,name,'0',(time.time()-start_time)])
                            except:
                                print
                                print 'Errore Certificate'
                                #print certificate
                                print
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
        p=pkt['TCP'].flags
        flag=obtain_flag(p)
        lenght=len(pkt[IP])
        if flag.find('SA',0,len(flag))!=-1:
            try:
                puntatore=connection.index(ips,0,len(connection))
                if connection[puntatore-1]==ipd and connection[puntatore+1]==dp and connection[puntatore+2]==sp:
                    connection[puntatore+4]=connection[puntatore+4]+lenght
                    connection[puntatore+3]=1
            except:
                pass
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
                        control=0
                        try:
                            if punt_name!=-1 and name_org[punt_name+1]==ipd and name_org[punt_name+2]==sp and name_org[punt_name+3]==dp:
                                f.write(str(connection[puntatore:puntatore+7]).strip('[]\'')+' '+'R'+'   '+str(name_org[punt_name+4]).strip('[]\'')+'   '+str(name_org[punt_name+5]).strip('[]\'')+' '+'\n')
                                #print 'guarda FIN/R UP',ipd,ips,sp,dp
                                x=len(name_org)
                                name_org[punt_name:punt_name+8]=[]
                            else:
                                control=-1
                        except:
                            control=-1
                        if punt_name!=-1 and control==-1:
                            x=punt_name+4
                        else:
                            x=len(name_org)
                            fr=open('/nf/refuse.log','a+')
                            fr.write(str(ipd)+' '+str(ips)+' '+str(dp)+' '+str(sp)+'\n')
                            fr.close
                        f.close()
                    connection[puntatore:puntatore+8]=[]
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
                        control=0
                        try:
                            if punt_name!=-1 and name_org[punt_name-1]==ipd and name_org[punt_name+1]==dp and name_org[punt_name+2]==sp:
                                f.write(str(connection[puntatore-1:puntatore+6]).strip('[]\'')+' '+'R'+'   '+str(name_org[punt_name+3]).strip('[]\'')+'   '+str(name_org[punt_name+4]).strip('[]\'')+' '+'\n')
                                #print 'guarda FIN/R DOWN',ipd,ips,sp,dp
                                x=len(name_org)
                                name_org[punt_name-1:punt_name+7]=[]
                            else:
                                control=-1
                        except:
                            control=-1
                        if punt_name!=-1 and control==-1:
                            x=punt_name+3
                        else:
                            x=len(name_org)
                            fr=open('/nf/refuse.log','a+')
                            fr.write(str(ipd)+' '+str(ips)+' '+str(dp)+' '+str(sp)+'\n')
                            fr.close
                        f.close()
                    connection[puntatore-1:puntatore+7]=[]
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
                            control=0
                            try:
                                if punt_name!=-1 and name_org[punt_name+1]==ipd and name_org[punt_name+2]==sp and name_org[punt_name+3]==dp:
                                    f.write(str(connection[puntatore:puntatore+7]).strip('[]\'')+' '+'F'+'   '+str(name_org[punt_name+4]).strip('[]\'')+'   '+str(name_org[punt_name+5]).strip('[]\'')+' '+'\n')
                                    #print 'guarda RST/F UP',ipd,ips,sp,dp
                                    x=len(name_org)
                                    name_org[punt_name:punt_name+8]=[]
                                else:
                                    control=-1
                            except:
                                control=1
                            if punt_name!=-1 and control==-1:
                                x=punt_name+4
                            else:
                                x=len(name_org)
                                fr=open('/nf/refuse.log','a+')
                                fr.write(str(ips)+' '+str(ipd)+' '+str(sp)+' '+str(dp)+'\n')
                                fr.close
                            f.close()
                        connection[puntatore:puntatore+8]=[]
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
                            control=0
                            try:
                                if punt_name!=-1 and name_org[punt_name-1]==ipd and name_org[punt_name+1]==dp and name_org[punt_name+2]==sp:
                                    f.write(str(connection[puntatore-1:puntatore+6]).strip('[]\'')+' '+'F'+'   '+str(name_org[punt_name+3]).strip('[]\'')+'   '+str(name_org[punt_name+4]).strip('[]\'')+' '+'\n')
                                    #print 'guarda RST/F DOWN',ipd,ips,sp,dp
                                    x=len(name_org)
                                    name_org[punt_name-1:punt_name+7]=[]
                                else:
                                    control=-1
                            except:
                                control=-1
                            if punt_name!=-1 and control==-1:
                                x=punt_name+3
                            else:
                                x=len(name_org)
                                fr=open('/nf/refuse.log','a+')
                                fr.write(str(ipd)+' '+str(ips)+' '+str(dp)+' '+str(sp)+'\n')
                                fr.close
                            f.close()
                        connection[puntatore-1:puntatore+7]=[]
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
                    connection[puntatore_1+7]=str(time.time()-start_time)
                    var=len(connection)
                elif puntatore_1!=-1 and connection[puntatore_1-1]==ipd and connection[puntatore_1+1]==dp and connection[puntatore_1+2]==sp:
                    connection[puntatore_1+4]=connection[puntatore_1+4]+lenght
                    connection[puntatore_1+6]=str(time.time()-start_time)
                    var=len(connection)
                else:
                    var=var+7


        #d.task_done()

def upload():
    while True:
        pkt=u.get()
        ips=pkt[IP].src
        ipd=pkt[IP].dst
        sp=pkt[TCP].sport
        dp=pkt[TCP].dport
        stringa=bytes(TCP()).encode("HEX")+str(pkt).encode("HEX")
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
        if True:
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
                        #name_org[index_e_name+6]=time.time()-start_time
                        l=len(name_org)
                    else:
                        l=index_e_name+5
                    if l<len(name_org):
                        try:
                            index_e_name=name_org.index(ips,l,len(name_org))
                        except:
                            index_e_name=-1
                if index_e_name==-1:
                    name_org.extend([ips,ipd,sp,dp,'0',e_name,(time.time()-start_time)])
        p=pkt['TCP'].flags
        flag=obtain_flag(p)
        lenght=len(pkt[IP])
        u.task_done()
        if flag.find('S',0,len(flag))!=-1:
            try:
                puntatore=connection.index(ipd,0,len(connection))
            except:
                puntatore=-1
            if puntatore!=-1 and connection[puntatore+1]==sp and connection[puntatore+2]==dp:
                connection[puntatore+5]=int(connection[puntatore+5])+lenght
            else:
                connection.extend([ips,ipd,sp,dp,0,0,lenght,str(time.time()-start_time)])
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
                        control=0
                        try:
                            if punt_name!=-1 and name_org[punt_name+1]==ipd and name_org[punt_name+2]==sp and name_org[punt_name+3]==dp:
                                f.write(str(connection[puntatore:puntatore+7]).strip('[]\'')+' '+'R'+'   '+str(name_org[punt_name+4]).strip('[]\'')+'   '+str(name_org[punt_name+5]).strip('[]\'')+' '+'\n')
                                #print 'guarda FIN/R UP',ipd,ips,sp,dp
                                x=len(name_org)
                                name_org[punt_name:punt_name+8]=[]
                            else:
                                control=-1
                        except:
                            control=-1
                        if punt_name!=-1 and control==-1:
                            x=punt_name+4
                        else:
                            x=len(name_org)
                            fr=open('/nf/refuse.log','a+')
                            fr.write(str(ipd)+' '+str(ips)+' '+str(dp)+' '+str(sp)+'\n')
                            fr.close
                        f.close()
                    connection[puntatore:puntatore+8]=[]
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
                        control=0
                        try:
                            if punt_name!=-1 and name_org[punt_name-1]==ipd and name_org[punt_name+1]==dp and name_org[punt_name+2]==sp:
                                f.write(str(connection[puntatore-1:puntatore+6]).strip('[]\'')+' '+'R'+'   '+str(name_org[punt_name+3]).strip('[]\'')+'   '+str(name_org[punt_name+4]).strip('[]\'')+' '+'\n')
                                #print 'guarda FIN/R DOWN',ipd,ips,sp,dp
                                x=len(name_org)
                                name_org[punt_name-1:punt_name+7]=[]
                            else:
                                control=-1
                        except:
                            control=-1
                        if punt_name!=-1 and control==-1:
                            x=punt_name+3
                        else:
                            x=len(name_org)
                            fr=open('/nf/refuse.log','a+')
                            fr.write(str(ipd)+' '+str(ips)+' '+str(dp)+' '+str(sp)+'\n')
                            fr.close
                        f.close()
                    connection[puntatore-1:puntatore+7]=[]
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
                            control=0
                            try:
                                if punt_name!=-1 and name_org[punt_name+1]==ipd and name_org[punt_name+2]==sp and name_org[punt_name+3]==dp:
                                    f.write(str(connection[puntatore:puntatore+7]).strip('[]\'')+' '+'F'+'   '+str(name_org[punt_name+4]).strip('[]\'')+'   '+str(name_org[punt_name+5]).strip('[]\'')+' '+'\n')
                                    #print 'guarda RST/F UP',ipd,ips,sp,dp
                                    x=len(name_org)
                                    name_org[punt_name:punt_name+8]=[]
                                else:
                                    control=-1
                            except:
                                control=1
                            if punt_name!=-1 and control==-1:
                                x=punt_name+4
                            else:
                                x=len(name_org)
                                fr=open('/nf/refuse.log','a+')
                                fr.write(str(ips)+' '+str(ipd)+' '+str(sp)+' '+str(dp)+'\n')
                                fr.close
                            f.close()
                        connection[puntatore:puntatore+8]=[]
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
                            control=0
                            try:
                                if punt_name!=-1 and name_org[punt_name-1]==ipd and name_org[punt_name+1]==dp and name_org[punt_name+2]==sp:
                                    f.write(str(connection[puntatore-1:puntatore+6]).strip('[]\'')+' '+'F'+'   '+str(name_org[punt_name+3]).strip('[]\'')+'   '+str(name_org[punt_name+4]).strip('[]\'')+' '+'\n')
                                    #print 'guarda RST/F DOWN',ipd,ips,sp,dp
                                    x=len(name_org)
                                    name_org[punt_name-1:punt_name+7]=[]
                                else:
                                    control=-1
                            except:
                                control=-1
                            if punt_name!=-1 and control==-1:
                                x=punt_name+3
                            else:
                                x=len(name_org)
                                fr=open('/nf/refuse.log','a+')
                                fr.write(str(ipd)+' '+str(ips)+' '+str(dp)+' '+str(sp)+'\n')
                                fr.close
                            f.close()
                        connection[puntatore-1:puntatore+7]=[]
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
                    connection[puntatore_1+7]=str(time.time()-start_time)
                    var=len(connection)
                elif puntatore_1!=-1 and connection[puntatore_1-1]==ipd and connection[puntatore_1+1]==dp and connection[puntatore_1+2]==sp:
                    connection[puntatore_1+4]=connection[puntatore_1+4]+lenght
                    connection[puntatore_1+6]=str(time.time()-start_time)
                    var=len(connection)
                else:
                    var=var+7

connection=[]  #nei vettori in connection l'ultima cifra indica se la connessione si e' gia' instaurata(0 no, 1 si, 2 fin in una direzione
memoria=[]
name_org=[]
retrasmission=[]

t=threading.Thread(target=control)
p=threading.Thread(target=pulizia_memoria)
down1=threading.Thread(target=download)
down2=threading.Thread(target=download)
down3=threading.Thread(target=download)
up=threading.Thread(target=upload)
down1.start()
print down1.isAlive()
down2.start()
print down2.isAlive()
down3.start()
print down3.isAlive()
up.start()
print up.isAlive()
t.start()
print t.isAlive()
p.start()
print p.isAlive()

def create_thread(pkt):
    ips=pkt[IP].src
    ipd=pkt[IP].dst
    sp=pkt[TCP].sport
    dp=pkt[TCP].dport
    if sp==443 and ipd!=ipv4 :
        d.put(pkt)
    elif dp==443 and ips!=ipv4:
        u.put(pkt)

sniff(prn=create_thread,filter="tcp",store=0)


