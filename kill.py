import os

x=int(raw_input('inserisci pid first'))

for i in range(0,10):
    os.system('kill -9 '+str(x))
    x=x+3

