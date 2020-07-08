import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 8888)
print >>sys.stderr, '\nstarting up on %s port %s\n' % server_address
sock.bind(server_address)

# Listen for incoming connection
sock.listen(1)

def send_control(state,xdiff,xactual):
  connection, client_address = sock.accept()
  connection.sendall(str(xactual)+str(state)+str(xdiff))
  data = connection.recv(2000)
  print data
  data = '\0'
