# Socket UDP and TCP server

import socket
import sys

HOST = '127.0.0.1'
PORT = 20002
buffer_size  = 1024

choice = raw_input(" UDP or TCP(U/T?):")

def udp_server():
    # Create socket
    udp_server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    # Bind to address and ip
    udp_server_socket.bind((HOST, PORT))
    print("UDP server up and listening")

    while(True):
        bytesAddressPair = udp_server_socket.recvfrom(buffer_size)
        #message = bytesAddressPair[0]
        #clientMsg = "Message from Client:{}".format(message)
        address = bytesAddressPair[1]
        clientIP  = "Client IP Address:{}".format(address)
        print("Received message from client.")
        print(clientIP)

        # Sending a reply to client
        udp_server_socket.sendto(str.encode("Hello UDP Client"), address)


def tcp_server():
    # Create socket
    tcp_server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    # Bind to address and ip
    tcp_server_socket.bind((HOST, PORT))
    tcp_server_socket.listen(5)
    print("TCP server up and listening")


    conn, addr = tcp_server_socket.accept()
    print('Connected by', addr)
    while True:
        data = conn.recv(buffer_size)
        #print(data)
        print("Received message from client.")
        print("Client IP Address: ",addr)
        if not data:
            break
        conn.sendall(str.encode("Hello TCP Client"))

def main():
    if (choice == "U") or (choice == "u"):
        udp_server()
    elif (choice == "T") or (choice == "t"):
        tcp_server()
    else:
        print("it's an invalid command.")

if __name__ == '__main__':
    main()
