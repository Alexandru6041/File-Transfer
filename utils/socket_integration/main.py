import socket
import os
import shutil
from ..network_utils.main import NetworkUtils
from django.http import HttpResponse
from django.conf import settings


class Sockets(object):
    def __init__(self):
        self._BUFFER_SIZE = 1024 * 4
        self._SEPARATOR = "<SEPARATOR>"
        self.RECEIVER_HOST = NetworkUtils.getServerIP()
        self._TRANSFER_PORT = settings.TRANSFER_PORT
        self.s = socket.socket()
            
    def receive(self):
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('', self._TRANSFER_PORT))
        self.s.listen()
        print(f"[*] Listening as {self.RECEIVER_HOST}:{self._TRANSFER_PORT}")
        client_socket, address = self.s.accept()
        print(f"[+] {address} is connected.")
        received = client_socket.recv(self._BUFFER_SIZE).decode()
        filename, filesize = received.split(self._SEPARATOR)
        filename = os.path.basename(filename)
        filesize = int(filesize)
        with open(filename, "wb") as f:
            while True:
                bytes_read = client_socket.recv(self._BUFFER_SIZE)
                if not bytes_read:
                    break
                f.write(bytes_read)
        self.s.close()
        print(f"[+] File received: {filename} from {address} via port {self._TRANSFER_PORT}")
        file_path = os.path.join(settings.BASE_DIR, filename)
        shutil.move(file_path, settings.MEDIA_URL)
        
        Sockets().receive()

    def send(self, file):
        host = self.RECEIVER_HOST
        filesize = file.size
        self.s.connect((host, int(self._TRANSFER_PORT)))
        print(f"[*] Connected to {host} via port {self._TRANSFER_PORT}")
        self.s.send(f"{file}{self._SEPARATOR}{filesize}".encode())
        print(f"[*] Sending {file} to {host} via port {self._TRANSFER_PORT}")
        
        while True:
            bytes_read = file.read()
            if not bytes_read:
                break
            self.s.sendall(bytes_read)
            
        self.s.close()
        
        print(f"[+] File sent: {file} to {host} via port {self._TRANSFER_PORT}")
        
        # Sockets().send(file, host)