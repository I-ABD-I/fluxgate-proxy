import datetime
import select
import signal
from enum import Enum
from typing import Iterable, BinaryIO, Any

import firebase_admin
from firebase_admin import firestore, credentials


class IPCMessageType(Enum):
    NewConnection = 1
    ConnectionClosed = 2
    DataReceived = 3

    Timeout = 255


class IPCMessage:
    def __init__(self, typ, data):
        self.typ = typ
        self.data = data


class IPC:
    def __init__(self, channel: BinaryIO):
        self.channel = channel

    def messages(self) -> Iterable[IPCMessage]:
        while True:
            rlist, *_ = select.select([self.channel], [], [], 10)
            if not rlist:
                yield IPCMessage(IPCMessageType.Timeout, None)
                continue

            line = rlist[0].readline()
            typ, data = line[0], line[1:]
            typ = IPCMessageType(typ)
            yield IPCMessage(typ, data.strip())


class Server:
    new_connections: int
    start: datetime.datetime
    log: list[dict[str, Any]]

    def __init__(self):
        self.new_connections = 0
        self.log = []
        self.start_timer()

    def connect(self):
        self.new_connections += 1

    def elapsed(self):
        return datetime.datetime.now() - self.start

    def start_timer(self):
        self.start = datetime.datetime.now()

    def new_message(self, length) -> bool:
        self.log.append({
            "timestamp": datetime.datetime.now(),
            "length": length,
        })
        # print(self.log, self.new_connections)
        return len(self.log) > 16

    def update_record(self, server_name, db):
        print(map := {
            "new_connections": firestore.firestore.Increment(self.new_connections),
            "log": firestore.firestore.ArrayUnion(self.log),
        })

        db.update(server_name, map)

        self.log = []
        self.new_connections = 0
        self.start_timer()


class Database:
    def __init__(self, db: firestore.firestore.Client):
        self.db = db
        self.servers_collection = self.db.collection("servers")

    def update(self, server_name: str, data: dict[str, Any]):
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
            server_name = msg.data[8:8 + length].decode()
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
