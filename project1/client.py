import socket

HOST = "localhost" 
PORT = 8000   

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b'Hello world!')
    data = s.recv(1024)
