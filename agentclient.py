import struct


class InvalidMessage(Exception):
    pass


class Reader:
    def __init__(self, buffer: bytes):
        self.buffer = buffer
        self.cursor = 0

    def take(self, length: int) -> bytes:
        if self.cursor + length > len(self.buffer):
            raise InvalidMessage("Not enough bytes left")
        result = self.buffer[self.cursor:self.cursor + length]
        self.cursor += length
        return result


class Metrics:
    def __init__(self, cpu: float):
        self.cpu = cpu

    def encode(self) -> bytes:
        return struct.pack(">f", self.cpu)

    @staticmethod
    def decode(reader: 'Reader') -> 'Metrics':
        raw = reader.take(4)
        cpu = struct.unpack(">f", raw)[0]
        return Metrics(cpu)

    def __repr__(self):
        return f"Metrics(cpu={self.cpu})"


class Message:
    CONNECT = 0x00
    DISCONNECT = 0x01
    ACK = 0x02
    METRICS = 0x03

    def __init__(self, kind: str, payload=None):
        self.kind = kind
        self.payload = payload

    def encode(self) -> bytes:
        if self.kind == "Connect":
            return bytes([Message.CONNECT])
        elif self.kind == "Disconnect":
            return bytes([Message.DISCONNECT])
        elif self.kind == "Ack":
            return bytes([Message.ACK])
        elif self.kind == "Metrics":
            return bytes([Message.METRICS]) + self.payload.encode()
        else:
            raise InvalidMessage(f"Cannot encode unknown kind: {self.kind}")

    @staticmethod
    def decode(data: bytes) -> 'Message':
        reader = Reader(data)
        msg_type = reader.take(1)[0]

        if msg_type == Message.CONNECT:
            return Message("Connect")
        elif msg_type == Message.DISCONNECT:
            return Message("Disconnect")
        elif msg_type == Message.ACK:
            return Message("Ack")
        elif msg_type == Message.METRICS:
            metrics = Metrics.decode(reader)
            return Message("Metrics", payload=metrics)
        else:
            raise InvalidMessage(f"Unknown message type: {msg_type}")

    def __repr__(self):
        if self.payload:
            return f"Message({self.kind}, {self.payload})"
        return f"Message({self.kind})"


import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect(("172.18.0.10", 0xabd))

sock.send(Message("Connect").encode())
data = sock.recv(1024)

msg = Message.decode(data)
if msg.kind != "Ack":
    raise InvalidMessage("Expected Ack message")

while True:
    data = sock.recv(1024)
    msg = Message.decode(data)
    if msg.kind == "Disconnect":
        break
    elif msg.kind == "Metrics":
        print(msg.payload)
        sock.send(Message("Ack").encode())
        sock.makefile().flush()
    else:
        raise InvalidMessage(f"Unexpected message type: {msg.kind}")
