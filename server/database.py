from utils.crypto_socket import CryptoSocket
from utils.exceptions import *
from utils.socket_manager import SocketManager
import mysql.connector
import os


class DatabaseHandler(object):
    def __init__(self):
        try:
            self._host = os.environ["DB_HOST"]
            self._user = os.environ["DB_USER"]
            self._password = os.environ["DB_PASSWORD"]
            self._database = os.environ["DB_NAME"]


            self._mysql = mysql.connector.connect(
                host=self._host,
                user=self._user,
                password=self._password,
                database=self._database
            )

            self._cursor = self._mysql.cursor()
        except KeyError as ex:
            raise RuntimeError(f"Missing environment variable: {ex}") from ex

        except mysql.connector.Error as ex:
            raise RuntimeError(f"Database connection error: {ex}") from ex
        
        except Exception as ex:
            raise RuntimeError(f"Unexpected error: {ex}") from ex
        

    def auth(self, username: str) -> str:
        self._cursor.execute("SELECT password FROM auth WHERE username=%s LIMIT 1", (username, ))
        passwd = self._cursor.fetchone()
        
        return passwd[0]
    
    
    def is_admin(self, username: str) -> bool:
        self._cursor.execute("SELECT is_admin FROM auth WHERE username=%s LIMIT 1", (username, ))
        out = self._cursor.fetchone()
        
        return out[0]
    
    
    def check_ban(self, username: str) -> bool:
        self._cursor.execute("SELECT 1 FROM auth WHERE username=%s LIMIT 1", (username, ))
        self._cursor.fetchone()

    
    def close(self) -> None:
        if self._cursor:
            self._cursor.close()
            
        if self._mysql:
            self._mysql.close()