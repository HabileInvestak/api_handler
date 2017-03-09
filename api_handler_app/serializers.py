from rest_framework import serializers
from api_handler_app.models import Audit

class AuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Audit
        fields = ('user_id', 'api_name', 'request_id','source_request_time_stamp','request_validate_time_stamp'
                  ,'target_transmit_time_stamp'
                  ,'target_response_time_stamp','response_validate_time_stamp'
                  ,'source_transmit_time_stamp','source_request','target_transmit','target_response','source_transmit'
                  ,'source_request_status','target_transmit_status'
                  ,'target_response_status','source_transmit_status','ip_address'
                  ,'source_system_name','target_system_name')