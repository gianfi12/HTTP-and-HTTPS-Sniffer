import socket
import sys
from struct import *

try:
    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x003))
except socket.error, msg:
    print 'socket coud not be created'
    sys.exit()

packet=s.recvfrom(65565)
print packet
