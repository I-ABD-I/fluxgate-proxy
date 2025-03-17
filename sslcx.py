import ssl
import socket

cx = ssl.create_default_context()
cx.check_hostname = False
cx.verify_mode = ssl.CERT_NONE
s = cx.wrap_socket(socket.create_connection(("127.0.0.1", 4000)), server_hostname="localhost")
print("sent hello")
s.send(b"hello")
print("recieved ", s.recv(1024))
print(s.recv(1024).decode())
