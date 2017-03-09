from django.db import models

# Create your models here.

'''This Class is used to Store all api request,response to data base with status and time stamp'''
class Audit(models.Model):
    user_id = models.TextField()
    api_name=models.TextField()
    request_id = models.AutoField(primary_key=True,unique=True,null=False)
    source_request_time_stamp = models.DateTimeField(null=True)
    request_validate_time_stamp = models.DateTimeField(null=True)
    target_transmit_time_stamp = models.DateTimeField(null=True)
    target_response_time_stamp = models.DateTimeField(null=True)
    response_validate_time_stamp = models.DateTimeField(null=True)
    source_transmit_time_stamp = models.DateTimeField (null=True)
    source_request = models.TextField()
    target_transmit = models.TextField()
    target_response = models.TextField()
    source_transmit = models.TextField()
    source_request_status = models.TextField()
    target_transmit_status = models.TextField()
    target_response_status = models.TextField()
    source_transmit_status = models.TextField()
    ip_address=models.TextField()
    source_system_name=models.TextField()
    target_system_name=models.TextField()
    
    class Meta:
        ordering = ('request_id',)