#!/usr/bin/env python3
""" Makes a connection to localhost:5000/test/socket """

import socket         
mysock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
mysock.connect(('localhost', 5000))  
cmd = 'GET /test/socket HTTP/1.0\r\n\r\n'.encode()
mysock.send(cmd)    

if __name__ == "__main__":
    while True:
        data = mysock.recv(512)
        if (len(data) < 1):
            break       
        print(data.decode()) 
    mysock.close()
