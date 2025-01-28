import socket, fcntl, struct, sys, netifaces
from django.conf import settings
from scapy.all import Ether, srp1


class _Operations(object):
    
    '''Converting IP to Binary'''
    def ToBinary(self, ip):
        octets = ip.split('.')
        
        binar = [format(int(octet), '08b') for octet in octets]
        ip_to_binar = '.'.join(binar)
        
        return ip_to_binar 
    
    '''Converting Binary to IP'''
    def ToIP(self, BinaryIP):
        BinaryIP = BinaryIP.replace('.', '')
        IP = [str(int(BinaryIP[i:i+8], 2)) for i in range(0, 32, 8)]
        binar_to_ip = '.'.join(IP)
        
        return binar_to_ip
    
    def AND(self, ip1, ip2):
        ip1 = int(ip1.replace('.', ''), 2)
        ip2 = int(ip2.replace('.', ''), 2)
        sol = ip1 & ip2
        
        return '.'.join([(format(sol, '032b'))[i:i + 8] for i in range(0, 32, 8)])
    
class _ServerData(object):
    @staticmethod
    def getOS():
        return sys.platform

    def _confirmCIDR(subnet_mask):
        cidr_mapping = {
        '255.0.0.0': '/8',
        '255.255.0.0': '/16',
        '255.255.255.0': '/24',
        '255.255.255.128': '/25',
        '255.255.255.192': '/26',
        '255.255.255.224': '/27',
        '255.255.255.240': '/28',
        '255.255.255.248': '/29',
        '255.255.255.252': '/30',
        }
        if(cidr_mapping.get(subnet_mask)):
            return True
    
    def getSubnet():
        subnet_mask = None
        for interface in netifaces.interfaces():
            addr = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addr:
                subnet_mask = addr[netifaces.AF_INET][0]['mask']
        
        return subnet_mask

    @staticmethod
    def getLocalIP():
        ip = None
        match _ServerData.getOS():
            case 'win32' | 'cygwin' | 'win64':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.connect(settings.DEFAULTDNS, settings.HTTP_PORT)                    
                    ip = sock.getsockname()[0]
                finally:
                    sock.close()
                
                return ip
            
            case 'linux' | 'darwin':
                for interface in netifaces.interfaces():
                    addr = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addr:
                        for addresses in addr[netifaces.AF_INET]:
                            if 'addr' in addresses and addresses['addr'] != '127.0.0.1':
                                ip = addresses['addr']
                                
                return ip
            
            case default:
                return None

class NetworkUtils(object):
    def __init__(self):
        self._ServerOS = _ServerData.getOS()
        self._ServerLocalIP = _ServerData.getLocalIP()
        self._Subnet = _ServerData.getSubnet()
        self._ADDR_REQEST_TYPE = {'remote': "REMOTE_ADDR", 'proxy_fwd': "HTTP_X_FORWARDED_FOR"}
        self.clientIP = None

    def getLocalIP(self, request):
        _separator = ','
        x_forwarded_for = request.META.get(self._ADDR_REQEST_TYPE['proxy_fwd'])
        if x_forwarded_for:
            ip = x_forwarded_for.split(_separator)[0]
        else:
            ip = request.META.get(self._ADDR_REQEST_TYPE['remote'])
            
        self.clientIP = ip
        return ip
    
    def getServerIP():
        return _ServerData.getLocalIP()

    def checkClient(self):
        state = None
        _Op_Utils = _Operations()    
        if(_ServerData._confirmCIDR(self._Subnet) == True):
            Server_Binary = _Op_Utils.ToBinary(self._ServerLocalIP)
            Subnet_Binary = _Op_Utils.ToBinary(self._Subnet)
            Client_Binary = _Op_Utils.ToBinary(self.clientIP)
            ServerAND = _Op_Utils.AND(Server_Binary, Subnet_Binary)
            Network_Address = _Op_Utils.ToIP(ServerAND)
            ClientAND = _Op_Utils.AND(Client_Binary, Subnet_Binary)
            print(Network_Address, self._Subnet)
            if(_Op_Utils.ToIP(ClientAND) == Network_Address):
                #TODO : Check if the client IP is on the same network as the server
                pass
                # print("[*] ", '{}'.format(self.clientIP), " Subnet Matches")
                # command = ['nmap', '-p', '{}'.format(settings.HTTP_PORT), '{}'.format(self.clientIP)]
                # result = subprocess.run(command, capture_output = True, text = True)
                # print(result)
                # output = result.stdout
                # print(output)
                # match = re.search(r'8000/tcp\s+(\w+)', output)
                # if match:
                #     state = match.group(1)
                # print(state)    
        pass #(TODO: Check if the client IP is on the same network as the server)
    @staticmethod
    def getPublicIP():
        pass

    @staticmethod
    def getMACAddr():
        pass

if __name__ == "__main__":
    pass