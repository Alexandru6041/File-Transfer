from django.apps import AppConfig
from django.conf import settings

#Third-Party
from utils.network_utils.main import NetworkUtils
import logging
import os

class MainConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'main'
    
    def ready(self):
        if not logging.getLogger().hasHandlers():
            
            logging.basicConfig(filename="{}/main.log".format(settings.LOG_URL), 
                                encoding = 'utf-8', 
                                level = logging.DEBUG,
                                format='%(asctime)s - %(levelname)s - %(message)s')
            debug_handler = logging.FileHandler(os.path.join(settings.LOG_URL, 'main.log'), encoding='utf-8')
            debug_handler.setLevel(logging.DEBUG)
        
        NetworkUtils().checkDatabase()
        
