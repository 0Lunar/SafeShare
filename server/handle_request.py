from utils.crypto_socket import CryptoSocket
from utils.exceptions import *
from utils.socket_manager import SocketManager
from server.database import DatabaseHandler
from cryptography.hazmat.primitives.hashes import SHA256, Hash
import bcrypt


"""
Codes:
    - 0x00: authenticate
    - 0x01: get devices
    - 0x02: download file/folder
    - 0x03: upload file/folder
    
    admin:
        - 0x10: new user
        - 0x11: remove user
        - 0x12: ban user
        - 0x13: ban ip
        - 0x14: unban user
        - 0x15: unban ip
"""


class ConnectionHandler(object):
    def __init__(self, conn: CryptoSocket) -> None:
        """ Handle client requests """
        self._socket = conn
        self._authed = False
        self._admin = False
        self._db = DatabaseHandler()
        
    
    def handle() -> None:
        pass
    
    
    def signin(self, username: bytes, password: bytes) -> None:
        dig = Hash(SHA256())
        dig.update(username)
        hashed_user = dig.finalize()
        
        hashed_passwd = self._db.auth(hashed_user.hex())
        
        auth = bcrypt.checkpw(password, hashed_passwd)
        self._authed = auth
        
        self._socket.send_data(auth.to_bytes())