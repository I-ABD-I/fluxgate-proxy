import datetime
import select
import signal
from enum import Enum
from typing import Iterable, BinaryIO, Any

import firebase_admin
from firebase_admin import firestore, credentials


class IPCMessageType(Enum):
    """
    Enum representing the different types of IPC (Inter-Process Communication) messages.

    Attributes:
        NewConnection (int): Represents a message indicating a new connection.
        ConnectionClosed (int): Represents a message indicating a connection has been closed.
        DataReceived (int): Represents a message indicating that data has been received.
        Timeout (int): Represents a message indicating a timeout occurred during the communication.

    Example usage:
        message_type = IPCMessageType.NewConnection
    """

    NewConnection = 1
    ConnectionClosed = 2
    DataReceived = 3
    Timeout = 255


class IPCMessage:
    """
    A class representing a message in the Inter-Process Communication (IPC) system.

    Attributes:
        typ (IPCMessageType): The type of the message, represented by an `IPCMessageType` enum.
        data (bytes): The actual data associated with the message.

    Methods:
        __init__(self, typ: IPCMessageType, data: bytes) -> None:
            Initializes the IPCMessage instance with the given message type and data.

    Example Usage:
        message = IPCMessage(IPCMessageType.NewConnection, b"Some data")
    """

    def __init__(self, typ: IPCMessageType, data: bytes):
        """
        Initializes an IPCMessage instance.

        Arguments:
            typ (IPCMessageType): The type of the message.
            data (bytes): The data associated with the message.

        Returns:
            None
        """
        self.typ = typ
        self.data = data


class IPC:
    """
    A class to handle Inter-Process Communication (IPC) over a given channel.

    This class listens for incoming messages on a channel, which can be used to communicate
    between different processes or components. The channel is a `BinaryIO` object, and
    the messages are read and processed sequentially.

    Attributes:
        channel (BinaryIO): The channel over which IPC messages are transmitted.

    Methods:
        __init__(self, channel: BinaryIO) -> None:
            Initializes the IPC object with a communication channel.

        messages(self) -> Iterable[IPCMessage]:
            A generator that continuously listens for incoming messages on the channel and yields
            `IPCMessage` instances. It also handles timeouts when no messages are received within
            a specified time frame.

    Example Usage:
        ipc = IPC(channel)
        for message in ipc.messages():
            print(message.typ, message.data)
    """

    def __init__(self, channel: BinaryIO):
        """
        Initializes the IPC system with the given communication channel.

        Arguments:
            channel (BinaryIO): The communication channel used to send and receive messages.

        Returns:
            None
        """
        self.channel = channel

    def messages(self) -> Iterable[IPCMessage]:
        """
        Listens for incoming messages on the communication channel. This method uses `select.select`
        to wait for data to be available on the channel and yields IPC messages as they are received.

        If no message is received within 10 seconds, a timeout message is yielded.

        Yields:
            IPCMessage: A message with the type and data from the channel.
            If no message is received within the timeout period, it yields a Timeout message.

        Example:
            for message in ipc.messages():
                print(f"Message type: {message.typ}, Message data: {message.data}")
        """
        while True:
            # Wait for data to be available on the channel (timeout of 10 seconds)
            rlist, *_ = select.select([self.channel], [], [], 10)

            # If no data is received within the timeout period, yield a Timeout message
            if not rlist:
                yield IPCMessage(IPCMessageType.Timeout, None)
                continue

            # Read the incoming message from the channel
            line = rlist[0].readline()
            typ, data = line[0], line[1:]

            # Convert the type from byte to IPCMessageType enum
            typ = IPCMessageType(typ)

            # Yield an IPCMessage with the appropriate type and data
            yield IPCMessage(typ, data.strip())


class Server:
    """
    A class that simulates a server, tracking new connections, message logs, and elapsed time since the server started.

    Attributes:
        new_connections (int): A counter for the number of new connections made to the server.
        start (datetime.datetime): The timestamp when the server started.
        log (list[dict[str, Any]]): A list of logs for each new message received by the server,
                                    with information about the timestamp and message length.

    Methods:
        __init__(self) -> None:
            Initializes a new server instance with zero new connections, an empty log, and starts the timer.

        connect(self) -> None:
            Increments the counter for new connections by one.

        elapsed(self) -> datetime.timedelta:
            Returns the time elapsed since the server started.

        start_timer(self) -> None:
            Starts the timer by setting the `start` timestamp to the current time.

        new_message(self, length: int) -> bool:
            Adds a new log entry with the given message length and the current timestamp.
            Returns `True` if the number of log entries exceeds 16, otherwise `False`.

        update_record(self, server_name: str, db: Any) -> None:
            Updates the server's record in a database with the new connections count and the current message log.
            Resets the new connections count and log after the update.

    Example Usage:
        server = Server()
        server.connect()
        server.new_message(100)
        server.update_record('server_1', db)
    """

    new_connections: int
    start: datetime.datetime
    log: list[dict[str, Any]]

    def __init__(self):
        """
        Initializes a new server instance. The server starts with zero new connections, an empty log,
        and begins tracking the elapsed time from the moment of initialization.
        """
        self.new_connections = 0
        self.log = []
        self.start_timer()

    def connect(self):
        """
        Increments the count of new connections made to the server.
        This method should be called each time a new connection is established.

        Returns:
            None
        """
        self.new_connections += 1

    def elapsed(self):
        """
        Returns the amount of time that has passed since the server was started.

        Returns:
            datetime.timedelta: The elapsed time since the server started.
        """
        return datetime.datetime.now() - self.start

    def start_timer(self):
        """
        Starts the server's timer by setting the `start` timestamp to the current date and time.

        Returns:
            None
        """
        self.start = datetime.datetime.now()

    def new_message(self, length: int) -> bool:
        """
        Logs a new message to the server, including the message length and the timestamp.

        Arguments:
            length (int): The length of the new message being logged.

        Returns:
            bool: Returns `True` if the number of messages logged exceeds 16, otherwise `False`.
        """
        self.log.append(
            {
                "timestamp": datetime.datetime.now(),
                "length": length,
            }
        )
        # Print the log and connection count for debugging purposes (commented out)
        # print(self.log, self.new_connections)
        return len(self.log) > 16

    def update_record(self, server_name: str, db):
        """
        Updates the server's record in a given database. The update includes the current count of new connections
        and the log of messages that have been received by the server.

        After the update, the server's connection count and message log are reset, and the timer is restarted.

        Arguments:
            server_name (str): The name of the server to be updated in the database.
            db (Any): The database object where the server's record is stored.
                      The update logic assumes that `db.update()` can be used to update the server's record.

        Returns:
            None
        """
        print(
            map := {
                "new_connections": firestore.firestore.Increment(self.new_connections),
                "log": firestore.firestore.ArrayUnion(self.log),
            }
        )

        db.update(server_name, map)

        # Reset server's state after update
        self.log = []
        self.new_connections = 0
        self.start_timer()


class Database:
    """
    A class to interact with a Firestore database for managing server information.

    Attributes:
        db (firestore.firestore.Client): An instance of the Firestore client.
        servers_collection (google.cloud.firestore_v1.collection.CollectionReference):
            A reference to the 'servers' collection in Firestore.
    """

    def __init__(self, db: firestore.firestore.Client):
        """
        Initializes the Database object.

        Args:
            db (firestore.firestore.Client): An initialized Firestore client.
        """
        self.db = db
        self.servers_collection = self.db.collection("servers")

    def update(self, server_name: str, data: dict[str, Any]):
        """
        Updates or creates a document for a given server in the 'servers' collection.

        If the document for `server_name` exists, it will be updated with the
        fields in `data`. If it does not exist, a new document will be created.
        The `merge=True` option ensures that existing fields not present in `data`
        are preserved.

        Args:
            server_name (str): The name of the server, used as the document ID.
            data (dict[str, Any]): A dictionary containing the data to be set or merged
                                   into the server's document.
        """
        self.servers_collection.document(server_name).set(data, merge=True)


def main():
    import sys

    cred = credentials.Certificate("cred.json")
    firebase_app = firebase_admin.initialize_app(cred)
    db = firestore.client(firebase_app)
    db = Database(db)

    ipc = IPC(sys.stdin.buffer)

    state: dict[str, Server] = {}

    def signal_handler(_signal, _frame):
        for name, s in state.items():
            s.update_record(name, db)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    for msg in ipc.messages():
        if msg.typ == IPCMessageType.NewConnection:

            server_name = msg.data.decode()
            print("New connection", server_name)
            server = state.setdefault(server_name, Server())
            server.connect()

        # after here state[server] must exist
        elif msg.typ == IPCMessageType.ConnectionClosed:
            server_name = msg.data.decode()
            print(f"Connection closed {server_name}")
            # state[server_name].disconnect()

        elif msg.typ == IPCMessageType.DataReceived:
            length = int.from_bytes(msg.data[:8], byteorder=sys.byteorder)
            server_name = msg.data[8 : 8 + length].decode()
            print(f"Data received: {length=}, {server_name}")
            # state[server_name].update_data(length)
            if (server := state[server_name]).new_message(length):
                server.update_record(server_name, db)

        elif msg.typ == IPCMessageType.Timeout:
            print(state)
            for server_name, server in state.items():
                if server.elapsed() > datetime.timedelta(minutes=5):
                    server.start_timer()
                    server.update_record(server_name, db)
        else:
            print("Unknown message type")


if __name__ == "__main__":
    main()
