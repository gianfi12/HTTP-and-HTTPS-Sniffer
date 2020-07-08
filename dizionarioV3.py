import fcntl
import threading
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64
import binascii
from OpenSSL import crypto
import multiprocessing
import socket
import time
start_time=time.time()
vettore=['F','S','R','P','A','U']
open('/home/gian/Desktop/Pass/access.log','w').close()
open('/home/gian/Desktop/refuse.log','w').close()

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


def analize_packet(ips,ipd,key,dp,sp,flag,lenght,d):
    if flag.find('R',0,len(flag))!=-1:
        list=d.get(key)
        if list!=None:
            print 'R',ips,ipd,sp,dp
            if list[0]==ips and list[1]==ipd and list[2]==sp and list[3]==dp:
                if list[4]=='0' and list[5]=='0':
                    pass
                else:
                    list[8]=list[8]+lenght
                    while True:
                        try:
                            f=open('/home/gian/Desktop/Pass/access.log','a+')
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
                            f=open('/home/gian/Desktop/access.log','a+')
                            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except IOError as e:
                            pass
                    f.write(str(list[:9]).strip('[]\'')+' '+str(float(time.time()-start_time-float(list[9])))+' '+'R'+'\n')
                    fcntl.flock(f, fcntl.LOCK_UN)
                    f.close()
                del d[key]
        else:
            print 'R not found in list',ips,ipd,sp,dp
            while True:
                try:
                    fr=open('/home/gian/Desktop/refuse.log','a+')
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
            print 'F',ips,ipd,sp,dp
            if list[0]==ips and list[1]==ipd and list[2]==sp and list[3]==dp:
                if list[4]=='0' and list[5]=='0':
                    del d[key]
                else:
                    list[8]=list[8]+lenght
                    if list[6]==3:
                        while True:
                            try:
                                f=open('/home/gian/Desktop/Pass/access.log','a+')
                                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                break
                            except IOError as e:
                                print 'error print result'
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
                                f=open('/home/gian/Desktop/Pass/access.log','a+')
                                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                break
                            except IOError as e:
                                print 'error insert result'
                                pass
                        f.write(str(list[:9]).strip('[]\'')+' '+str(float(time.time()-start_time-float(list[9])))+' '+'F'+'\n')
                        fcntl.flock(f, fcntl.LOCK_UN)
                        f.close()
                        del d[key]
                    else:
                        list[6]=3
        else:
            print 'F not found in list',ips,ipd,sp,dp
            while True:
                try:
                    fr=open('/home/gian/Desktop/refuse.log','a+')
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
            pass
            #print 'Error search SA'

    elif flag.find('S',0,len(flag))!=-1:
        print 'S',ips,ipd,sp,dp
        list=d.get(key,None)
        if list==None:
            d[key]=[ips,ipd,sp,dp,'0','0',0,0,lenght,time.time()-start_time]
        else:
            list[8]=list[8]+lenght
            d[key]=list

    else:
        list=d.get(key,None)
        if list!=None:
            if list[1]==ips and list[0]==ipd:
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
    retrasmission=[]
    d={}
    ds={}
    certi={}
    t=int(time.time()-start_time)
    while True:
        pkt=code2[x].recv()
        ips=pkt[0]
        ipd=pkt[1]
        payload=pkt[2][14:]
        ip_lenght_hx=str(payload[0]).encode("HEX")
        ip_lenght=int(ip_lenght_hx[1],16)*8
        proto=str(payload[9:10]).encode("HEX")
        lenght_T=len(payload)
        p=str(payload[ip_lenght/2+13:ip_lenght/2+14]).encode("HEX")
        if proto=='06':
            try:
                sp=int(str(payload[ip_lenght/2:ip_lenght/2+2]).encode("HEX"),16)
            except:
                print
                print 'error sp'
                print payload[ip_lenght/2:ip_lenght/2+2]
            try:
                dp=int(str(payload[ip_lenght/2+2:ip_lenght/2+4]).encode("HEX"),16)
            except:
                print
                print 'error dp'
                print payload[ip_lenght/2+2:ip_lenght/2+4]
            if sp==443 or dp==443:
                f=int(time.time()-start_time)
                list=ips.split('.',4)
                x1=list[-1]
                list=ipd.split('.',4)
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
                        index=stringa.find('160303',posizione_data,len(stringa))
                        lenght_TLS_hx=stringa[index+6:index+10]
                        try :
                            lenght_TLS=int(str(lenght_TLS_hx),16)*2
                        except:
                            index=-1
                        index_c=index+10
                        count=0
                        type='0'
                        while index_c<len(stringa) and index!=-1:
                            type=stringa[index_c:index_c+2]
                            try:
                                lenght_TLS_c=int(stringa[index_c+2:index_c+8],16)*2
                            except:
                                break
                            if len(stringa)-index_c<lenght_TLS_c and type=='0b':
                                lenght_p=len(stringa)-index_c
                                time_t=time.time()-start_time
                                certi[key]=[ips,ipd,sp,dp,lenght_TLS_c+8,stringa[index_c:],lenght_p,next_seq_num_hx,time_t]
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
                                    print
                                    print 'certificate',name,sp,dp
                                    print
                                    l=0
                                    list[4]=name
                                    d[key]=list
                                except:
                                    print
                                    print 'error certificate',ipd,ips,sp,dp
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
                        lista=certi.get(key,None)
                        if lista!=None:
                                if type!='0b':
                                    if str(seq_num_hx)==str(lista[7]):
                                        var=lista[5]
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
                                        if lista[4]-lista[6]<=len(stringa)-posizione_data:
                                            payload=var+stringa[posizione_data:posizione_data+lista[4]-lista[6]]
                                            certificate=payload
                                            try:
                                                certificate=certificate[20:]
                                                result='-----BEGIN CERTIFICATE-----\n'+base64.encodestring(binascii.unhexlify(certificate))+'-----END CERTIFICATE-----'
                                                cert=x509.load_pem_x509_certificate(result,default_backend())
                                                certs=crypto.load_certificate(crypto.FILETYPE_PEM,result)
                                                certs2=certs.get_subject()
                                                name=certs2.organizationName
                                                l=0
                                                print
                                                print 'certificate',name,dp
                                                print
                                                list[4]=name
                                                del certi[key]
                                                d[key]=list
                                            except:
                                                print
                                                print 'error certificate',ipd,ips,sp,dp
                                                print certificate
                                        else:
                                            payload=var+stringa[posizione_data:]
                                            lista[7]=next_seq_num_hx
                                            lenght_pN=lista[6]+lenght_p
                                            lista[5]=payload
                                            lista[6]=lenght_pN
                                            lista[8]=time.time()-start_time
                                            certi[key]=lista
                                    else:
                                        retrasmission.extend([ips,dp,lenght_p,total_lenght,seq_num_hx,stringa[posizione_data:],(time.time()-start_time)])
                    if list[5]=='0' and dp==443:
                        stringa=str(payload).encode("HEX")
                        hx=hex(int(str(sp))).lstrip("0x")
                        inizio=stringa.index(str(hx),0,len(stringa))
                        posizione=inizio+len(str(hx))+20
                        lenght_TCP_hx=stringa[posizione]
                        lenght=int(str(lenght_TCP_hx),16)*4
                        posizione_data=lenght*2+inizio-1
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
                            list[5]='http'
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

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serversocket.bind(('127.0.0.1', 8888))
serversocket.listen(5)
while True:
    connection, address = serversocket.accept()
    while True:
        buf = connection.recv(65536)
        if len(buf) > 0:
            x=str(buf)
            try:
                proto=x[23].encode("HEX")
                if proto=="06":
                    ips=socket.inet_ntoa(x[26:30])
                    ipd=socket.inet_ntoa(x[30:34])
                    hashing(ips,ipd,x)
            except:
                pass

