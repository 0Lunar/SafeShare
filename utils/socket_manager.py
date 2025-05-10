from utils.crypto_socket import CryptoSocket
import threading


class SocketManager(object):
    def __init__(self) -> None:
        """ Create a SocketManager object to manage multiple connections """
        
        self._sockets = {}
        self._lock = threading.Lock()
        
        
    def append(self, conn: CryptoSocket, username: str | None = None) -> None:
        if type(conn) != CryptoSocket:
            raise ValueError(f"Invalid type: {type(conn)}")
        
        with self._lock:
            conn_id = conn.fileno()

            self._sockets[conn_id] = {
                "ip": conn.ip,
                "port": conn.port,
                "socket": conn,
                "connected": conn.connected,
                "username": username
            }
            
            
    def update_username(self, conn_id: int, new_username: str) -> None:
        with self._lock:
            if conn_id not in self._sockets:
                raise ValueError("Invalid connection id")
            
            self._sockets[conn_id]["username"] = new_username
        
        
    def remove(self, conn_id: int) -> None:
        """ Remove a connection with the socket file descriptor """
        
        with self._lock:
            if self._sockets.pop(conn_id, None) is None:
                raise ValueError("Invalid connection id")
            
            
    def get(self, conn_id: int) -> CryptoSocket:
        """ Get a socket with the socket file descritpor """
        with self._lock:
            if conn_id not in self._sockets:
                raise ValueError("Invalid connection id")
        
            return self._sockets[conn_id]["socket"]
        
    
    def get(self, username: str) -> CryptoSocket:
        """ Get a socket with the username """
        with self._lock:
            if not self.contains(username):
                raise ValueError("Invalid username")
        
            for device in self._sockets:
                if self._sockets[device]["username"] == username:
                    return self._sockets[device]["socket"]
        
        
    def list(self) -> dict:
        with self._lock:
            return self._sockets
    
    
    def contains(self, username: str) -> bool:
        with self._lock:
            for device in self._sockets:
                if self._sockets[device]["username"] == username:
                    return True
                
            return False
        
    def clear(self) -> None:
        """ Clear all the saved connections """
        with self._lock:
            self._sockets.clear()
            
    
    def clear_and_close(self) -> None:
        """ Clear anc close all the saved connections """
        
        with self._lock:
            for conn in self._sockets:
                try:
                    self._sockets[conn]["socket"].close()
                except Exception as ex:
                    raise RuntimeError(f"Error closing connection with {self._sockets[conn]['ip']}:{self._sockets[conn]['port']} - {ex}") from ex
            
            self._sockets.clear()