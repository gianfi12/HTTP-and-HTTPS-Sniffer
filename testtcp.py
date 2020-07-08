import socket
seq=bytearray.fromhex("aaa0000000000000000000000000000000")
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
            count=0
            try:
                #ips=socket.inet_ntoa(x[26:30])
                #ipd=socket.inet_ntoa(x[30:34])
                try:
                    i=x.index(seq,count,len(x))
                except:
                    i=-1
                while i!=-1 or count==0:
                    print
                    print x[count+82:i].encode("HEX")
                    print
                    print i
                    print
                    count=count+i+35
                    try:
                        i=x.index((seq,count,len(x)))
                    except:
                        i=-1
            except:
                pass
