from django.shortcuts import render, redirect
from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse
from django.urls import path
from .models import FileUnit

#Utilities
from utils.network_utils.main import NetworkUtils
from utils.socket_integration.main import Sockets
from utils.security.main import AESCipher, MyHasher
import threading
from os.path import join

# Create your views here.
def index(request):
    global ip_to_send
    utils = NetworkUtils()

    client_ip = utils.getLocalIP(request)
    server_ip = NetworkUtils.getServerIP()
    port = settings.TRANSFER_PORT
    
    sock = Sockets()
    thread = threading.Thread(target=sock.receive)
    thread.start()
    
    if(utils.checkClient() == False):
        return render(request, "http500.html", {"ip": client_ip}, status = 500)
    else:
        if request.method == 'POST':
            file = request.FILES.get('fileupload')
            ip_to_send = request.POST['ReceiverIP']
            token = file.name + '_' + ip_to_send
            print(token)
            Chiper = AESCipher
            Hasher = MyHasher()
            token = Hasher.encode(token)
            token = Chiper.encrypt(str(token))
            FileUnit(IP = ip_to_send, File = file.name, token = token).save()
            sock.send(file)
            
            
    return render(request, "index.html", {"client_ip": client_ip, "server_ip" : server_ip, "port" : port})
