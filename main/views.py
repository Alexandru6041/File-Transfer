from django.shortcuts import render, redirect
from django.conf import settings
from .models import FileUnit
from django.http import HttpResponse

#Utilities
from utils.network_utils.main import NetworkUtils
from utils.socket_integration.main import Sockets
from utils.security.main import AESCipher, MyHasher
import threading
import sqlite3
import logging
import math
import os

# Create your views here.
def index(request):
    global ip_to_send
    error = None
    
    logger = logging.getLogger(__name__)
    logging.basicConfig(filename=f"{settings.LOG_URL}/main.log", encoding = 'utf-8', level = logging.DEBUG)
    utils = NetworkUtils()
    
    client_ip = utils.getLocalIP(request)
    server_ip = NetworkUtils.getServerIP()
    port = settings.TRANSFER_PORT
    
    sock = Sockets()
    thread = threading.Thread(target=sock.receive)
    thread.start()

    if(utils.checkClient() == False and client_ip == server_ip):
        return redirect("admin/")
    
    if(utils.checkClient() == False):
        return render(request, "http500.html", {"ip": client_ip}, status = 500)
    else:
        Chiper = AESCipher
        Hasher = MyHasher()
        
        connection = sqlite3.connect(settings.DATABASES['default']['NAME'])
        cursor = connection.cursor()
        
        dataReceive = cursor.execute("SELECT * FROM main_fileunit WHERE IP = ?", (client_ip,)).fetchall()
        
        download_files = []
        
        for row in dataReceive:
            encrypted_token = row[3]
            file_name = row[2]
            
            #Checking if the token is valid
            decrypted_token = eval(Chiper.decrypt(encrypted_token))
            
            predicted_token = file_name + '_' + client_ip
            if(MyHasher.verify(predicted_token, decrypted_token) == False):
                logging.warning(f"Token verification failed for IP: {client_ip}. Denying access to the file. Deleting record from database.")
                file_path = settings.MEDIA_URL + file_name
                try:
                    os.remove(file_path)
                except FileNotFoundError:   
                    pass
                
                cursor.execute("DELETE FROM main_fileunit WHERE File = ?", (file_name, ))
                connection.commit()
            else:
                logging.info(f"Token verification succeeded for IP: {client_ip}. Sending file: {file_name}")
                download_files.append(file_name)
            
        if request.method == 'POST':
            file = request.FILES.get('fileupload')
            ip_to_send = request.POST['ReceiverIP']
            if utils.checkClient(ip_to_send) == False:
                error = f"Could not esablish a connection with the requested IP: {ip_to_send}"
                return render(request, "index.html", {"client_ip": client_ip, "server_ip": server_ip, "port": port, "error": error, "download_files": download_files})
            else:
                error = None
                cursor.execute("SELECT * FROM main_fileunit WHERE File = ?", (file.name, ))
                connection.commit()
                data = cursor.fetchall()
                cntFile = 0
                ok_multiple_Files = True
                while(ok_multiple_Files == True):
                    for row in data:                        
                        if(ok_multiple_Files == True):
                            if(cntFile == 0 and row[2] == file.name):
                                cntFile += 1
                                file.name = os.path.splitext(file.name)[0] + f'{cntFile}' + os.path.splitext(file.name)[1]
                            elif(cntFile > 0 and row[2] == file.name):
                                print("second file")
                                cntFile += 1
                                file.name = os.path.splitext(file.name)[0][:-(math.floor(math.log10(cntFile)) + 1)] + f'{cntFile}' + os.path.splitext(file.name)[1]
                                print(file.name)
                            cursor.execute("SELECT * FROM main_fileunit WHERE File = ?", (file.name, ))
                            connection.commit()
                            data = cursor.fetchall()
                            print(data)
                            if(data == []):
                                ok_multiple_Files = False
                            break
                        else:
                            break
                token = file.name + '_' + ip_to_send
                token = Hasher.encode(token)
                token = Chiper.encrypt(str(token))
                try:
                    sock.send(file)
                    FileUnit(IP = ip_to_send, File = file.name, token = token, server_ip = server_ip).save()
                except OSError:
                    return redirect(index)
                finally:
                    logging.info(f"POST req. received from IP: {client_ip} \n        POST data: \n            IP_to_send: {ip_to_send}\n            File:{file.name}\n")
        
            
    return render(request, "index.html", {"client_ip": client_ip, "server_ip" : server_ip, "port" : port, "error": error, "download_files": download_files})


def download_file(request, filename):
    file_path = os.path.join(settings.MEDIA_URL, filename)

    if not os.path.exists(file_path):
        connection  = sqlite3.connect(settings.DATABASES['default']['NAME'])
        cursor = connection.cursor()
        logging.warning(f"File {filename} not found in media folder. Deleting record from database.")
        cursor.execute("DELETE FROM main_fileunit WHERE File = ?", (filename, ))
        connection.commit()
        connection.close()
        
        return redirect(index)

    with open(file_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    
def refresh(request):
    Chiper = AESCipher
    Hasher = MyHasher()
    
    client_ip = NetworkUtils().getLocalIP(request)
    
    connection = sqlite3.connect(settings.DATABASES['default']['NAME'])
    cursor = connection.cursor()
    
    dataReceive = cursor.execute("SELECT * FROM main_fileunit WHERE IP = ?", (client_ip,)).fetchall()
    
    download_files = []
    
    for row in dataReceive:
        encrypted_token = row[3]
        file_name = row[2]
        
        decrypted_token = eval(Chiper.decrypt(encrypted_token))
        
        predicted_token = file_name + '_' + client_ip
        if(MyHasher.verify(predicted_token, decrypted_token) == False):
            logging.warning(f"Token verification failed for IP: {client_ip}. Denying access to the file. Deleting record from database.")
            file_path = settings.MEDIA_URL + file_name
            try:
                os.remove(file_path)
            except FileNotFoundError:   
                pass
            
            cursor.execute("DELETE FROM main_fileunit WHERE File = ?", (file_name, ))
            connection.commit()
        else:
            logging.info(f"Token verification succeeded for IP: {client_ip}. Sending file: {file_name}")
            download_files.append(file_name)
        
    return render(request, "index.html", {"download_files": download_files})
        