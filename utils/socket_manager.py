from utils.crypto_socket import CryptoSocket
import threading


class SocketManager(object):
    def __init__(self) -> None:
        """ Create a SocketManager object to manage multiple connections """
        
        self._sockets = {}
        self._lock = threading.Lock()
        
    def append(self, conn: CryptoSocket) -> None:
        if type(conn) != CryptoSocket:
            raise ValueError(f"Invalid type: {type(conn)}")
        
        with self._lock:
            conn_id = conn.fileno()

            self._sockets[conn_id] = {
                "ip": conn.ip,
                "port": conn.port,
                "socket": conn,
                "connected": conn.connected
            }
        
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
        
    def list(self) -> dict:
        return self._sockets
        
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