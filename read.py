import socket

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serversocket.bind(('127.0.0.1', 8888))
serversocket.listen(5)
bytes_total=0
try:
    while True:
        connection, address = serversocket.accept()
        while True:
            buf = connection.recv(65536)
            if len(buf) > 0:
                x=str(buf)
                bytes_total=len(x)+bytes_total
                try:
                    pass
                    #print x.encode("HEX")
                    #proto=x[9].encode("HEX")
                    #if proto=="06":
                        #sp=int(x[20:22].encode("HEX"),16)
                        #dp=int(x[22:24].encode("HEX"),16)
                        #ips=socket.inet_ntoa(x[12:16])
                        #ipd=socket.inet_ntoa(x[16:20])
                        #print sp,dp
                except:
                    pass
except KeyboardInterrupt:
    print bytes_total
