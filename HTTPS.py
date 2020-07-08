import httplib
import os
import time
import threading
import sys
import linecache
import requests
import random
import socket

start_time = time.time()
f=open("time.log","a+")
threads=[]

def PrintException():
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)


def richieste(x):
    src_ip="172.16.20."+str(x)
    os.system("wget -bqc -O /dev/null --bind-address=172.16.20."+str(x)+" https://172.16.21.1/nf.iso --no-check-certificate")


siti=['www.facebook.com','www.google.com','www.spotify.com','www.netflix.com','www.amazon.com','www.twitter.com','www.instagram.com','www.ebay.com','www.whatsapp.com','www.soundcloud.com','it.yahoo.com','it.wikipedia.org','www.asus.com','www.eprice.it','www.netgear.it','www.inter.it','www.cisco.com','www.python.org','www.twitch.tv','www.apple.com','www.microsoft.com','www.rockstargames.com','www.ferrari.com','www.hp.com','www.dell.com','www.youtube.com','www.nvidia.it','www.intel.it','www.comune.milano.it']

x=12
for i in range(0,5):
    os.system("wget -bqc -O /dev/null --limit-rate 25m "+str(x)+" https://127.0.0.1/nf.iso --no-check-certificate ")
    #print 'TIME:',str(time.time() - start_time)
    #thread=threading.Thread(target=richieste,args=(x,))
    x=x+11
    #thread.start()
    #threads.append(thread)
#for thread in threads:
    #thread.join()

f.write("---"+str(time.time() - start_time)+" seconds ---"+'\n\n')
f.close()
