from rest_framework import serializers
from api_handler_app.models import Audit

class AuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Audit
        fields = ('user_id', 'api_name', 'request_id','investak_request_time_stamp','api_request_time_stamp','tso_response_time_stamp'
                  ,'api_response_time_stamp','investak_request','api_request','tso_response','api_response','api_status','tso_status','ip_address')