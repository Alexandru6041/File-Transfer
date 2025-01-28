from django.db import models

# Create your models here.
class FileUnit(models.Model):
    IP = models.CharField(max_length=15)
    File = models.CharField(max_length=128)
    token = models.CharField(max_length=512)
    
    def __str__(self):
        return self.token
    
       
    