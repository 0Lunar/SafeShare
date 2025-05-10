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
    - 0x02: get dir content
    - 0x03: download file/folder
    - 0x04: upload file/folder
    - 0x0f: logout
    
    admin:
        - 0x10: new user
        - 0x11: remove user
        - 0x12: ban user
        - 0x13: ban ip
        - 0x14: unban user
        - 0x15: unban ip
        
    - 0xff close connection
"""


class ConnectionHandler(object):
    def __init__(self, conn: CryptoSocket, db: DatabaseHandler, sckmgr: SocketManager) -> None:
        """ Handle client requests """
        self._socket = conn
        self._authed = False
        self._admin = False
        self._db = db
        self._manager = sckmgr
        
    
    def handle(self) -> None:
        while True:
            payload = self._socket.recv_data()
            
            code = payload[0]
                        
            if code == 0:
                auth = payload[1:].split(b'\xff')
                
                if len(auth) != 2:
                    self._socket.send_data(b'\x00')
                
                username = auth[0]
                password = auth[1]
                
                self.signin(username, password)
            
            if code == 1:
                self.devices()
                
            if code == 0xff:
                self._socket.close()
                break
    
    
    def signin(self, username: bytes, password: bytes) -> None:
        dig = Hash(SHA256())
        dig.update(username)
        hashed_user = dig.finalize()
                
        hashed_passwd = self._db.auth(hashed_user.hex())
        hashed_passwd = hashed_passwd.encode()
        
        auth = bcrypt.checkpw(password, hashed_passwd)
        self._authed = auth
        
        
        if auth:
            self._manager.update_username(
                self._socket.fileno(),
                username.decode()
            )
            
            is_admin = self._db.is_admin(hashed_user.hex())
            
            if is_admin:
                self._admin = True
                auth = 2
        
        self._socket.send_data(auth.to_bytes())
        
    
    def devices(self) -> None:
        devices = []
        
        d = self._manager.list()
        
        for device in d:
            if d[device]["username"] is None:
                devices.append(d[device]["ip"])
            
            else:
                devices.append(d[device]["username"])
                
        payload = b'\xff'.join([dev.encode() for dev in devices])
        
        self._socket.send_data(payload)
        
        pass
    

    def list_dir(self, dir: str, device: str) -> list[str]:
        # TODO comando per ottenere file/cartelle dentro una cartella
        if not self._manager.contains(device):
            raise AuthenticationError("Device not found")
        
        conn = self._manager.get(device)
        
        payload = b'\x00' + dir
        
        conn.send_data(payload)
        info = conn.recv_data()
        
        info = [i.decode() for i in info.split("\xff")]
        
        return info