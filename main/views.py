from django.shortcuts import render, redirect
from django.conf import settings
from .models import FileUnit

#Utilities
from utils.network_utils.main import NetworkUtils
from utils.socket_integration.main import Sockets
from utils.security.main import AESCipher, MyHasher
import threading
import sqlite3
import logging

# Create your views here.
def index(request):
    global ip_to_send
    error = None
    
    logger = logging.getLogger(__name__)
    logging.basicConfig(filename=f"{settings.LOG_URL}/main.log", encoding = 'utf-8', level =logging.DEBUG)
    utils = NetworkUtils()
    
    client_ip = utils.getLocalIP(request)
    server_ip = NetworkUtils.getServerIP()
    port = settings.TRANSFER_PORT
    
    sock = Sockets()
    thread = threading.Thread(target=sock.receive)
    thread.start()
    
    if(utils.checkClient() == False):
        logging.info(f"Client IP is not on the same network as server. Denying access. IP: {client_ip}")
        return render(request, "http500.html", {"ip": client_ip}, status = 500)
    else:
            
        if request.method == 'POST':
            file = request.FILES.get('fileupload')
            ip_to_send = request.POST['ReceiverIP']
            if utils.checkClient(ip_to_send) == False:
                return render(request, "index.html", {"client_ip": client_ip, "server_ip": server_ip, "port": port, "error": error})
            else:
                token = file.name + '_' + ip_to_send
                Chiper = AESCipher
                Hasher = MyHasher()
                token = Hasher.encode(token)
                token = Chiper.encrypt(str(token))
                FileUnit(IP = ip_to_send, File = file.name, token = token, server_ip = server_ip).save()
                try:
                    sock.send(file)
                except OSError:
                    return redirect(index)
                finally:
                    logging.info(f"POST req. received from IP: {client_ip} \n        POST data: \n            IP_to_send: {ip_to_send}\n            File:{file.name}\n")
        
            
    return render(request, "index.html", {"client_ip": client_ip, "server_ip" : server_ip, "port" : port, "error": error})
