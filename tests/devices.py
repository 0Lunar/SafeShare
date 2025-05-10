import sys

sys.path.append("../")

from utils.crypto_socket import CryptoSocket
from utils.exceptions import *
from utils.socket_manager import SocketManager
from server.handle_request import ConnectionHandler
from server.database import DatabaseHandler
from threading import Thread
import time
import os


os.environ.update({
    "DB_HOST": "localhost",
    "DB_USER": "root",
    "DB_PASSWORD": "root",
    "DB_NAME": "testdb"
})


def server() -> None:
    manager = SocketManager()
    s = CryptoSocket()
    db = DatabaseHandler()
    s.bind(("127.0.0.1", 9080))
    s.listen()
    
    conn = s.accept()
    
    manager.append(conn)
    
    handler = ConnectionHandler(
        conn=conn,
        db=db,
        sckmgr=manager
    )
    
    handler.handle()
    

def client() -> None:
    s = CryptoSocket()
    s.connect("127.0.0.1", 9080)
    print("Authenticating...")
    status = s.auth(b"0xLunar292", b"ImLunarHex!!!")
    print(f"Authenticated: {str(status)}")
    print(f"Getting device list...")
    devices = s.get_devices()
    print("\nDevices:")
    print('\n\t- '.join(devices))
    s.close()
    print("\nConnection closed")


def main() -> None:
    Thread(target=server).start()
    time.sleep(1)
    Thread(target=client).start()


if __name__ == "__main__":
    main()