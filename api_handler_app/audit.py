from datetime import datetime
import logging
from api_handler_app.models import Audit
from utils import UtilClass


logger = logging.getLogger('api_handler_app.audit.py')

'''This class will store All the request and response to database for audit purpose.
we will store investak request,api request,tso response and api response and its status with timestamp'''
class AuditTrial():
    
    '''This method will store the request of Investak to database
    and it create request id which has unique id for the apiName when investak_api audit enable is Yes'''
    def investak_request_audit(self,userId,bodyContent,apiName,apiHomeDict,ipAddress,requestId):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            dateNow = datetime.now ()
            logging = apiHomeDict.get(apiName)[0].logging
            logger.debug("Before Investak API audit enable")
            logger.debug("Logging="+logging)
            if (logging == utilClass.read_property ("YES") and utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                logger.debug("Investak API audit enable")
                auditobj=Audit(user_id=userId, investak_request=bodyContent,investak_request_time_stamp=dateNow,api_name=apiName,ip_address=ipAddress,request_id=requestId)
                auditobj.save()
                logger.debug("requestId="+str(requestId))
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
    

    '''This method will store the request of api to database
    and it create request id which has unique id for the apiName when investak_api audit enable is Yes and api_tso audit enable yes'''
    def api_request_audit(self,requestId,request,apiName,userId,apiHomeDict,ipAddress):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            dateNow = datetime.now ()
            logging=apiHomeDict.get(apiName)[0].logging
            if(logging==utilClass.read_property("YES") and utilClass.read_property('API_TSO_AUDIT_ENABLE')==utilClass.read_property("YES") and utilClass.read_property('INVESTAK_API_AUDIT_ENABLE')==utilClass.read_property("YES")):
                Audit.objects.update_or_create (
                    request_id=requestId,
                    defaults={utilClass.read_property('API_REQUEST'): request,utilClass.read_property('API_REQUEST_TIME_STAMP'):dateNow,utilClass.read_property('USER_ID'):userId},
                )
            else:
                auditobj = Audit (user_id=userId, api_request=request, api_request_time_stamp=dateNow,api_name=apiName,ip_address=ipAddress,request_id=requestId)
                auditobj.save ()
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
    
    
    '''This method will store the response of api to database
    and check whether the response is list or dictionary and corresponding status is noted'''
    def api_response_audit(self,requestId,request,apiName,apiHomeDict,userId):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            dateNow = datetime.now ()
            logging = apiHomeDict.get(apiName)[0].logging
            if type(request) is list:
                for dict_var in request:
                    print dict_var
                    stat=dict_var.get(utilClass.read_property('STATUS'))
                    if stat == utilClass.read_property ('OK'):
                        apiStatus = utilClass.read_property('SUCCESS')
                        pass
                    else:
                        apiStatus = utilClass.read_property('FAILURE')
                        break
                if (logging == utilClass.read_property ("YES") and utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.read_property('API_RESPONSE'): request,utilClass.read_property('API_RESPONSE_TIME_STAMP'):dateNow,utilClass.read_property('API_STATUS'):apiStatus,utilClass.read_property('USER_ID'):userId},
                ) 
            else:          
                stat= request.get (utilClass.read_property('STATUS'))
                if stat== utilClass.read_property ('OK'):
                    apiStatus=utilClass.read_property ('SUCCESS')
                elif stat == utilClass.read_property ('NOT_OK'):
                    apiStatus = utilClass.read_property ('FAILURE')
                else:
                    apiStatus = utilClass.read_property ('SUCCESS')
                if (logging == utilClass.read_property ("YES") and utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.read_property('API_RESPONSE'): request,utilClass.read_property('API_RESPONSE_TIME_STAMP'):dateNow,utilClass.read_property('API_STATUS'):apiStatus,utilClass.read_property('USER_ID'):userId},
                    )
            logger.info(utilClass.read_property("EXITING_METHOD"))
        except Exception as exception:
            raise exception
    
    
    '''This method will store the response of tso to store database
    and check whether the response is list or dictionary and corresponding status is noted'''
    def tso_response_audit(self,requestId,request,apiName,apiHomeDict,successDict,failureDict):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        tsoStatus=''
        try:
            dateNow = datetime.now ()
            #find json array
            logging = apiHomeDict.get(apiName)[0].logging
            if type(request) is list:
                for dict_var in request:
                    stat=dict_var.get(utilClass.read_property('STATUS'))
                    if stat == utilClass.read_property ('OK'):
                        tsoStatus = utilClass.read_property('SUCCESS')
                        pass
                    else:
                        tsoStatus = utilClass.read_property('FAILURE')
                        break
                if (logging == utilClass.read_property ("YES") and utilClass.read_property ('API_TSO_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.read_property('TSO_RESPONSE'): request,utilClass.read_property('TSO_RESPONSE_TIME_STAMP'):dateNow,utilClass.read_property('TSO_STATUS'):tsoStatus},
                )    
            else:
                stat = request.get(utilClass.read_property('STATUS'))
                if stat == utilClass.read_property ('OK'):
                    tsoStatus = utilClass.read_property('SUCCESS')
                elif stat == utilClass.read_property ('NOT_OK'):
                    tsoStatus = utilClass.read_property('FAILURE')
                else:
                    tsoStatus=utilClass.read_property('SUCCESS')
                logger.debug(apiName)
                logging = apiHomeDict.get(apiName)[0].logging
                if (logging == utilClass.read_property ("YES") and utilClass.read_property ('API_TSO_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.read_property('TSO_RESPONSE'): request,utilClass.read_property('TSO_RESPONSE_TIME_STAMP'):dateNow,utilClass.read_property('TSO_STATUS'):tsoStatus},
                    )
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
