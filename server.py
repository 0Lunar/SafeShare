from utils.crypto_socket import CryptoSocket
from utils.exceptions import *
from utils.socket_manager import SocketManager
import threading


IP = "127.0.0.1"
PORT = 9080

Manager = SocketManager()


def main() -> None:
    s = CryptoSocket()
    s.bind((IP, PORT))
    s.listen()
    
    while True:
        conn = s.accept()
        Manager.append(conn)


if __name__ == "__main__":
    main()