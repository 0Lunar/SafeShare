import socket
import os
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import rsa as RSA
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.utils import int_to_bytes
from utils.exceptions import *
import bcrypt


class CryptoSocket(socket.socket):
    def __init__(self, init_socket: bool = True) -> None:
        self.ip = "127.0.0.1"
        self.port = 0
        
        if init_socket:
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
            self.initialized = True
        else:
            self.initialized = False
        
        self.connected = False
        
        self._socket = self
                
        self._key = None
        self._nonce = None
        self._hmac_key = None
        
        self._pk = None
        self._hmac = None
        
        self.authenticated = False
    
    
    def _import_object(self, conn: socket.socket, addr: tuple, key: bytes, hmac_key: bytes, rsa_key) -> None:
        if self.initialized:
            raise Exception("Connection already initialized")
        
        self.ip = addr[0]
        self.port = addr[1]
        
        self._socket = conn
        
        self._key = key
        self._nonce = None
        self._hmac_key = hmac_key
        
        self._hmac = HMAC(hmac_key, SHA256())
        self._pk = rsa_key
        self.connected = True
        
    
    
    def connect(self, ip: str, port: int) -> None:
        if self.connected:
            raise Exception("Already connected")
        
        if super().getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
            raise Exception("Socket in listening mode")
        
        self.ip = ip
        self.port = port
        
        ########## Three-way handshake ##########
        
        try:
            super().connect((self.ip, self.port))
        except Exception as ex:
            raise ConnectionError(f"Error connecting to {self.ip}:{self.port} - {ex}") from ex
        
        ########### Crypto handshake ##########
        
        # Export RSA public key
        self._pk = RSA.generate_private_key(
            public_exponent=0x10001,
            key_size=2048
        )
        
        pub_key = self._pk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Send the RSA public key
        try:
            self._socket.send(len(pub_key).to_bytes(4))
            self._socket.send(pub_key)
        except Exception as ex:
            self._socket.close()
            self.__init__()
            raise ConnectionError(f"Error sending RSA public key: {ex}") from ex
        
        # Recive ChaCha20 Key - Standard size 256 bit (32 bytes)
        try:
            key_len = self._socket.recv(4)
            key_len = int.from_bytes(key_len)
            key = self._socket.recv(key_len)
            self._key = self._pk.decrypt(
                key,
                padding.OAEP (
                    mgf=padding.MGF1(algorithm=SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )
        except Exception as ex:
            self._socket.close()
            self.__init__()
            raise ConnectionError(f"Error reciving ChaCha20 key: {ex}") from ex
        
        # Recive HMAC key - Size 256 bit (32 bytes)
        try:
            hmac_key_len = self._socket.recv(4)
            hmac_key_len = int.from_bytes(hmac_key_len)
            hmac_key = self._socket.recv(hmac_key_len)
            
            self._hmac_key = self._pk.decrypt(
                hmac_key,
                padding.OAEP (
                    mgf=padding.MGF1(algorithm=SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )
        except Exception as ex:
            self._socket.close()
            self.__init__()
            raise ConnectionError(f"Error reciving HMAC key: {ex}") from ex
        
        try:
            self._hmac = HMAC(
                key=self._hmac_key,
                algorithm=SHA256(),
                backend=backend
            )
        except Exception as ex:
            raise SecurityError(f"Error initializing HMAC class: {ex}") from ex
        
        self.connected = True
        
        
    def new_cipher(self) -> Cipher:
        # Create new Cipher object
        
        if not self._nonce or len(self._nonce) != 16 or type(self._nonce) != bytes:
            raise ValueError("Invalid ChaCha20 nonce")
        
        if not self._key or len(self._key) != 32 or type(self._key) != bytes:
            raise ValueError("Invalid ChaCha20 key")
        
        try:
            cipher = Cipher(
                ChaCha20(
                    key=self._key,
                    nonce=self._nonce
                ),
                mode=None,
                backend=backend
            )
        except Exception as ex:
            raise SecurityError(f"Error creating a new ChaCha20 cipher: {ex}") from ex
        
        return cipher
    
    
    def check_hmac(self,buffer: bytes, hash: bytes) -> bool:
        self._hmac.update(buffer)
        hmac = self._hmac.finalize()
        
        self._hmac = HMAC(
            key=self._hmac_key,
            algorithm=SHA256()
        )
        
        return hmac == hash
        
    
    def send_data(self, buffer: bytes) -> None:
        if not self.connected:
            raise Exception("Not connected")
        
        if type(buffer) != bytes:
            raise ValueError(f"Buffer must be bytes, not {str(type(buffer))}")
        
        self._nonce = os.urandom(16)
        
        try:
            cipher = self.new_cipher()
            ciphertext = cipher.encryptor().update(buffer) + cipher.encryptor().finalize()
            self._hmac.update(buffer) 
            hmac = self._hmac.finalize()
            self._hmac = HMAC(
                key=self._hmac_key,
                algorithm=SHA256(),
            )
        except KeyboardInterrupt as ex:
            raise EncryptionFailure(f"Error encrypting data: {ex}") from ex
        
        payload = self._nonce + ciphertext + hmac
        
        try:
            self._socket.send(len(payload).to_bytes(8))
            self._socket.send(payload)
        except Exception as ex:
            raise ConnectionError(f"Error sending data: {ex}") from ex
        
    
    def recv_data(self) -> bytes:
        if not self.connected:
            raise Exception("Not connected")
        
        try:
            buffer_size = self._socket.recv(8)
            buffer_size = int.from_bytes(buffer_size)
        
            encrypted_buffer = self._socket.recv(buffer_size)
        except Exception as ex:
            raise ConnectionError(f"Error reciving encrypted buffer: {ex}") from ex
                
        nonce = encrypted_buffer[:16]
        ciphertext = encrypted_buffer[16:-32]
        hmac = encrypted_buffer[-32:]
        
        self._nonce = nonce
        cipher = self.new_cipher()
        
        buffer = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
        
        if not self.check_hmac(buffer, hmac):
            raise SecurityError("HMAC check failure")
        
        return buffer
    
    
    def accept(self):
        conn, addr = super().accept()

        if not super().getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
            raise Exception("Socket not in listening mode")

        ########### Crypto handshake ##########
        
        # Import RSA public key
        
        try:
            pk_len = conn.recv(4)
            pk_len = int.from_bytes(pk_len)
            pk = conn.recv(pk_len)
        except Exception as ex:
            conn.close()
            raise ConnectionError(f"Error reciving RSA public key: {ex}") from ex
        
        try:
            self._pk = serialization.load_pem_public_key(pk)
        except Exception as ex:
            conn.close()
            raise SecurityError(f"Error creating RSA public key: {ex}") from ex
        
        # Generate and send ChaCha20 key
        
        key = os.urandom(32)
        
        try:
            encrypted_key = self._pk.encrypt(
                plaintext=key,
                padding=padding.OAEP(
                    mgf=padding.MGF1(SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )
        except Exception as ex:
            conn.close()
            raise SecurityError(f"Error encrypting ChaCha20 key with RSA: {ex}") from ex
        
        try:
            conn.send(len(encrypted_key).to_bytes(4))
            conn.send(encrypted_key)
        except Exception as ex:
            conn.close()
            raise ConnectionError(f"Error sending ChaCha20 key: {ex}") from ex

        # Generate and send HMAC-SHA256 key 

        hmac_key = os.urandom(32)
        
        try:
            encrypted_hmac_key = self._pk.encrypt(
                plaintext=hmac_key,
                padding=padding.OAEP(
                    mgf=padding.MGF1(SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )
        except Exception as ex:
            conn.close()
            raise SecurityError(f"Error encrypting HMAC key with RSA: {ex}") from ex
    
        try:
            conn.send(len(encrypted_hmac_key).to_bytes(4))
            conn.send(encrypted_hmac_key)
        except Exception as ex:
            conn.close()
            raise ConnectionError(f"Error sending HMAC key: {ex}") from ex

        

        new_conn = CryptoSocket(False)
        new_conn._import_object(
            conn=conn,
            addr=addr,
            key=key,
            hmac_key=hmac_key,
            rsa_key=self._pk
        )
        
        return new_conn
    
    
    def fileno(self) -> int:
        if self._socket == self:
            return super().fileno()
        else:        
            return self._socket.fileno()
    
    
    def close(self) -> None:
        if self._socket == self:
            super().close()
        else:        
            self._socket.close()
            
            
    def auth(self, username: bytes, password: bytes) -> bool:
        """ Authentication """
        
        payload = b'\x00' + username + password
        self.send_data(payload)