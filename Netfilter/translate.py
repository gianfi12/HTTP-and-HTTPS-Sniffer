import binascii
from string import *

memoria=[]
ips=1

while ips!=0:
    stringa=raw_input('inserisci stringa')
    ips=raw_input('inserisci ips')
    ipd=raw_input('inserisci ipd')
    sp=int(raw_input('inserisci sp'))
    dp=int(raw_input('inserisci dp'))

    hx=hex(int(str(sp))).lstrip("0x")
    inizio=stringa.index(str(hx),0,len(stringa))
    posizione=inizio+len(str(hx))+20
    lenght_TCP_hx=stringa[posizione]
    lenght=int(str(lenght_TCP_hx),16)*4
    posizione_data=lenght*2+inizio-1
    index=stringa.find('160303',posizione_data,len(stringa))
    count=index
    index_certificate=-1
    lenght_p=len(stringa)-posizione_data

    while count<len(stringa) and count!=-1:
        lenght_TLS_hx=stringa[count+6:count+10]
        lenght_TLS=int(str(lenght_TLS_hx),16)*2
        if len(stringa)<lenght_TLS+count+9:
            index_certificate=stringa.find('0b',count+9,len(stringa))
        else:
            index_certificate=stringa.find('0b',count+9,count+9+lenght_TLS)
        if len(stringa)-index_certificate<lenght_TLS and index_certificate!=-1:
            lenght_p=len(stringa)-index_certificate
            memoria.extend([ips,sp,ipd,dp,lenght_TLS,stringa[index_certificate:],lenght_p])
        if index_certificate==-1:
            count=count+10+lenght_TLS
        elif index_certificate!=-1:
            count=len(stringa)
    try:
        index_mem=memoria.index(ips)
    except:
        index_mem=-1
    if index_mem!=-1 and memoria[index_mem+1]==sp and memoria[index_mem+2]==ipd and memoria[index_mem+3]==dp:
        var=memoria[index_mem+5]
        if index_certificate==-1:
            print memoria[index_mem+4]-memoria[index_mem+6],len(stringa)-posizione_data
            if memoria[index_mem+4]-memoria[index_mem+6]<=len(stringa)-posizione_data:
                payload=var+stringa[posizione_data:posizione_data+memoria[index_mem+4]-memoria[index_mem+6]]
                memoria[index_mem:index_mem+7]=[]
                print memoria
            else:
                payload=var+stringa[posizione_data:]
                lenght_pN=memoria[index_mem+6]+lenght_p
                memoria[index_mem+5]=payload
                memoria[index_mem+6]=lenght_pN
            print payload

