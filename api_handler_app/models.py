from django.db import models

# Create your models here.

'''This Class is used to Store all api request,response to data base with status and time stamp'''
class Audit(models.Model):
    user_id = models.TextField()
    api_name=models.TextField()
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
    ip_address=models.TextField()
    
    
    class Meta:
        ordering = ('request_id',)