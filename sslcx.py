import ssl
import socket

cx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
s = cx.wrap_socket(socket.create_connection(("127.0.0.1", 4000)))
print("sent hello")
s.send(b"hello")
print("recieved ", s.recv(1024))