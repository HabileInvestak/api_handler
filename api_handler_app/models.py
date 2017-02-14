from django.db import models
from pyasn1_modules.rfc1155 import IpAddress

# Create your models here.

'''This Class is used to Store all Api request,response to data base'''
class Audit(models.Model):
    user_id = models.TextField()
    apiName=models.TextField()
    request_id = models.AutoField(primary_key=True,unique=True,null=False)
    investak_request_time_stamp = models.DateTimeField(null=True)
    api_request_time_stamp = models.DateTimeField(null=True)
    tso_response_time_stamp = models.DateTimeField(null=True)
    api_response_time_stamp = models.DateTimeField (null=True)
    investak_request = models.TextField()
    api_request = models.TextField()
    tso_response = models.TextField()
    api_response = models.TextField()
    api_status = models.TextField()
    tso_status = models.TextField()
    ipAddress=models.TextField()
    
    
    class Meta:
        ordering = ('request_id',)