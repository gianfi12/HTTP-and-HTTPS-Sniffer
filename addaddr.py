import sys
import os
import time

x=12
for i in range(0,20):
    os.system("ip addr add dev enp3s0f1 172.16.20."+str(x)+"/24")
    time.sleep(1)
    os.system("wget --bind-address=172.16.20."+str(x)+" \"http://nas.mobimesh.it:2060/login?UserName=ANY%2F"+str(x)+"&Password=mobimesh\"")
    #time.sleep(3)
    x=x+11
