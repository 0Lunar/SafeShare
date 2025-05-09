import sys

sys.path.append("../")

from utils.crypto_socket import CryptoSocket
import time
from threading import Thread


def server() -> None:
    s = CryptoSocket()
    s.bind(("127.0.0.1", 9080))
    s.listen()
    conn = s.accept()
    
    msg = conn.recv_data()
        
    conn.close()
        
    print(msg.decode())
    

def client() -> None:
    s = CryptoSocket()
    s.connect("127.0.0.1", 9080)
    
    s.send_data(b'Ciao Marco')
    
    s.close()
        
    
if __name__ == "__main__":
    Thread(target=server).start()
    time.sleep(2)
    Thread(target=client).start()