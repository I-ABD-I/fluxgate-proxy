import struct
import socket


class InvalidMessage(Exception):
    """
    Exception raised when a message is invalid or cannot be processed.

    Inherits from the base `Exception` class.
    """

    pass


class Reader:
    """
    A class that reads data from a byte buffer.

    Attributes:
        buffer (bytes): The byte buffer from which data will be read.
        cursor (int): The current position in the buffer, indicating where the next read will start.

    Methods:
        __init__(self, buffer: bytes) -> None:
            Initializes a new Reader instance with the given buffer and sets the cursor to 0.

        take(self, length: int) -> bytes:
            Reads the specified number of bytes from the buffer. Raises an `InvalidMessage` exception if there are not enough bytes left in the buffer.

    Example Usage:
        reader = Reader(b'\x00\x01\x02\x03')
        data = reader.take(2)  # Returns b'\x00\x01'
    """

    def __init__(self, buffer: bytes):
        """
        Initializes a new Reader instance.

        Arguments:
            buffer (bytes): The buffer to read from.

        Returns:
            None
        """
        self.buffer = buffer
        self.cursor = 0

    def take(self, length: int) -> bytes:
        """
        Reads the specified number of bytes from the buffer.

        Arguments:
            length (int): The number of bytes to read from the buffer.

        Returns:
            bytes: The bytes read from the buffer.

        Raises:
            InvalidMessage: If there are not enough bytes left in the buffer.
        """
        if self.cursor + length > len(self.buffer):
            raise InvalidMessage("Not enough bytes left")
        result = self.buffer[self.cursor : self.cursor + length]
        self.cursor += length
        return result


class Metrics:
    """
    A class that represents system metrics (e.g., CPU usage).

    Attributes:
        cpu (float): The CPU usage metric value.

    Methods:
        __init__(self, cpu: float) -> None:
            Initializes a Metrics instance with the given CPU value.

        encode(self) -> bytes:
            Encodes the CPU value into a byte format using `struct.pack`.

        decode(reader: Reader) -> Metrics:
            Decodes the byte data from the `Reader` to create a Metrics instance.

        __repr__(self) -> str:
            Returns a string representation of the Metrics instance.

    Example Usage:
        metrics = Metrics(75.5)
        encoded_metrics = metrics.encode()  # Encodes the metrics to bytes
        decoded_metrics = Metrics.decode(reader)  # Decodes bytes into a Metrics instance
    """

    def __init__(self, cpu: float):
        """
        Initializes the Metrics object with the CPU usage value.

        Arguments:
            cpu (float): The CPU usage value.

        Returns:
            None
        """
        self.cpu = cpu

    def encode(self) -> bytes:
        """
        Encodes the CPU usage value to bytes.

        Returns:
            bytes: The encoded CPU value in bytes format.
        """
        return struct.pack(">f", self.cpu)

    @staticmethod
    def decode(reader: "Reader") -> "Metrics":
        """
        Decodes a Metrics instance from the provided reader's buffer.

        Arguments:
            reader (Reader): The reader to get the byte data from.

        Returns:
            Metrics: A Metrics instance containing the decoded CPU value.
        """
        raw = reader.take(4)
        cpu = struct.unpack(">f", raw)[0]
        return Metrics(cpu)

    def __repr__(self):
        """
        Returns a string representation of the Metrics instance.

        Returns:
            str: A string like "Metrics(cpu=75.5)".
        """
        return f"Metrics(cpu={self.cpu})"


class Message:
    """
    A class that represents a message that can be sent or received in the system.

    Class Constants:
        CONNECT (int): A constant representing a connection message type.
        DISCONNECT (int): A constant representing a disconnection message type.
        ACK (int): A constant representing an acknowledgment message type.
        METRICS (int): A constant representing a metrics message type.

    Attributes:
        kind (str): The type of the message, which can be "Connect", "Disconnect", "Ack", or "Metrics".
        payload (optional): The data associated with the message. For example, the metrics payload for a "Metrics" message.

    Methods:
        __init__(self, kind: str, payload=None) -> None:
            Initializes a Message with a specified type and optional payload.

        encode(self) -> bytes:
            Encodes the message type and its payload into a byte format.

        decode(data: bytes) -> Message:
            Decodes a byte sequence into a Message instance.

        __repr__(self) -> str:
            Returns a string representation of the message with its type and payload (if any).

    Example Usage:
        msg = Message("Metrics", payload=Metrics(75.5))
        encoded_msg = msg.encode()  # Encodes the message into bytes
        decoded_msg = Message.decode(encoded_msg)  # Decodes the bytes back into a Message
    """

    CONNECT = 0x00
    DISCONNECT = 0x01
    ACK = 0x02
    METRICS = 0x03

    def __init__(self, kind: str, payload=None):
        """
        Initializes a Message instance with a given kind and optional payload.

        Arguments:
            kind (str): The type of the message (e.g., "Connect", "Disconnect", "Ack", "Metrics").
            payload (optional): The optional data associated with the message (e.g., Metrics data).

        Returns:
            None
        """
        self.kind = kind
        self.payload = payload

    def encode(self) -> bytes:
        """
        Encodes the message into bytes. The encoding differs based on the message type.

        Returns:
            bytes: The encoded byte sequence representing the message.

        Raises:
            InvalidMessage: If the message type is unknown and cannot be encoded.
        """
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
    def decode(data: bytes) -> "Message":
        """
        Decodes a byte sequence into a Message instance.

        Arguments:
            data (bytes): The byte data to decode into a message.

        Returns:
            Message: The decoded message.

        Raises:
            InvalidMessage: If the byte sequence does not correspond to a valid message type.
        """
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
        """
        Returns a string representation of the message.

        Returns:
            str: A string representation of the message with its type and payload (if any).
        """
        if self.payload:
            return f"Message({self.kind}, {self.payload})"
        return f"Message({self.kind})"


# Script to test sever-side impl for the agent protocol
# Socket-based communication example

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect(("172.18.0.10", 0xABD))

# Send a connect message
sock.send(Message("Connect").encode())
data = sock.recv(1024)

# Decode the received message
msg = Message.decode(data)
if msg.kind != "Ack":
    raise InvalidMessage("Expected Ack message")

# Loop to receive and process further messages
while True:
    data = sock.recv(1024)
    msg = Message.decode(data)
    if msg.kind == "Disconnect":
        break
    elif msg.kind == "Metrics":
        print(msg.payload)
        sock.send(Message("Ack").encode())  # Send acknowledgment for metrics
        sock.makefile().flush()  # Ensure data is sent immediately
    else:
        raise InvalidMessage(f"Unexpected message type: {msg.kind}")
